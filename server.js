/**
 * =====================================================================
 *  Ağ Tarayıcı & Wake-on-LAN Dashboard (Debian 12 - Zero Dependency)
 *  Gömülü SVG Favicon Destekli & Port 80
 *
 *  v2: Sunucuda kalıcı cihaz kaydı (data.json), PIN ile giriş,
 *      canlı durum + uyanma takibi, zamanlanmış uyandırma,
 *      uzaktan kapatma (Windows ajanı / SSH), notlar, sıralama,
 *      uyandırma geçmişi, JSON dışa/içe aktarma.
 *
 *  PIN sıfırlama:
 *    docker compose stop && docker compose run --rm wol-dashboard node server.js --reset-pin && docker compose start
 * =====================================================================
 */

const http = require('http');
const dgram = require('dgram');
const net = require('net');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { exec, execFile } = require('child_process');
const os = require('os');
const dns = require('dns');

const PORT = Number(process.env.PORT) || 80;
const WOL_PORT = 9;
const DATA_DIR = process.env.WOL_DATA_DIR || __dirname;
const DATA_FILE = path.join(DATA_DIR, 'data.json');
const KEY_DIR = path.join(DATA_DIR, 'keys');
const SSH_KEY = path.join(KEY_DIR, 'id_ed25519');
const KNOWN_HOSTS = path.join(KEY_DIR, 'known_hosts');
const DEFAULT_TZ = 'Europe/Istanbul';
const DEFAULT_AGENT_PORT = 9777;
const SESSION_COOKIE = 'wol_session';
const SESSION_MAX_AGE = 365 * 24 * 3600;
const HISTORY_LIMIT = 300;
const POLL_INTERVAL = 15000;
const WATCH_POLL_INTERVAL = 3000;
const WATCH_LIMITS = { wake: 5 * 60e3, shutdown: 3 * 60e3, sleep: 3 * 60e3, restart: 6 * 60e3 };
const APP_VERSION = '4.1';
// Windows için yalnızca ajan: kısıtlanamayan SSH (ssh-windows) güvenlik nedeniyle kaldırıldı
const POWER_METHODS = ['none', 'agent', 'ssh-linux'];
const DEVICE_ICONS = ['desktop', 'laptop', 'server', 'router', 'tv', 'console', 'nas', 'other'];
const POWER_ACTIONS = { shutdown: 'Kapatma', restart: 'Yeniden başlatma', sleep: 'Uyku' };

// --- GÖMÜLÜ SVG FAVICON (Neon Mavi Güç/Power İkonu) ---
const SVG_FAVICON = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32">
  <rect width="32" height="32" rx="8" fill="#0b0f19"/>
  <path d="M16 6v10" stroke="#38bdf8" stroke-width="2.5" stroke-linecap="round"/>
  <path d="M10.5 10.5a8 8 0 1 0 11 0" stroke="#38bdf8" stroke-width="2.5" stroke-linecap="round"/>
</svg>`;

class HttpError extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
  }
}

// --- 0. KALICI VERİ (data.json) ---
function randomToken(bytes = 24) {
  return crypto.randomBytes(bytes).toString('hex');
}

function sha256(value) {
  return crypto.createHash('sha256').update(value).digest('hex');
}

function defaultData() {
  return {
    version: 1,
    devices: [],
    history: [],
    auth: { pinHash: null, pinSalt: null, sessions: {} },
    agent: { token: randomToken(16), port: DEFAULT_AGENT_PORT }
  };
}

function loadData() {
  try {
    const raw = JSON.parse(fs.readFileSync(DATA_FILE, 'utf8'));
    const base = defaultData();
    return {
      ...base,
      ...raw,
      devices: Array.isArray(raw.devices) ? raw.devices : [],
      history: Array.isArray(raw.history) ? raw.history : [],
      auth: { ...base.auth, ...(raw.auth || {}), sessions: (raw.auth && raw.auth.sessions) || {} },
      agent: { ...base.agent, ...(raw.agent || {}) }
    };
  } catch (err) {
    if (err.code !== 'ENOENT') {
      console.error('[Veri] data.json okunamadı, bozuk dosya yedeklenip sıfırdan başlanıyor:', err.message);
      try { fs.copyFileSync(DATA_FILE, `${DATA_FILE}.bozuk-${Date.now()}`); } catch { /* yok say */ }
    }
    return defaultData();
  }
}

let db = loadData();

function saveData() {
  fs.mkdirSync(DATA_DIR, { recursive: true });
  const tmp = `${DATA_FILE}.tmp`;
  fs.writeFileSync(tmp, JSON.stringify(db, null, 2), { mode: 0o600 });
  fs.renameSync(tmp, DATA_FILE);
}

if (!fs.existsSync(DATA_FILE)) saveData();

if (process.argv.includes('--reset-pin')) {
  db.auth = { pinHash: null, pinSalt: null, sessions: {} };
  saveData();
  console.log('PIN sıfırlandı. Paneli açtığınızda yeni PIN belirleyebilirsiniz.');
  process.exit(0);
}

function addHistory(entry) {
  db.history.unshift({ ts: Date.now(), ...entry });
  if (db.history.length > HISTORY_LIMIT) db.history.length = HISTORY_LIMIT;
  saveData();
}

// Arayüze anlık bildirim (toast) olarak iletilen olaylar
let eventSeq = 0;
const events = [];
function pushEvent(type, text) {
  events.push({ seq: ++eventSeq, type, text, ts: Date.now() });
  if (events.length > 50) events.shift();
}

// --- 1. DOĞRULAMA YARDIMCILARI ---
function normalizeMac(value) {
  const clean = String(value || '').replace(/[^0-9A-Fa-f]/g, '');
  if (clean.length !== 12) return null;
  return clean.toUpperCase().match(/.{2}/g).join(':');
}

function isIPv4(value) {
  return typeof value === 'string' &&
    /^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}$/.test(value);
}

function isValidTz(tz) {
  if (typeof tz !== 'string' || !tz || tz.length > 64) return false;
  try {
    new Intl.DateTimeFormat('en-US', { timeZone: tz });
    return true;
  } catch {
    return false;
  }
}

function cleanStr(value, max) {
  return String(value ?? '').replace(/[\u0000-\u001f\u007f]/g, ' ').trim().slice(0, max);
}

function cleanNote(value) {
  return String(value ?? '').replace(/[\u0000-\u0009\u000b-\u001f\u007f]/g, '').trim().slice(0, 500);
}

function sanitizeSchedules(list, existingList = []) {
  if (!Array.isArray(list)) return [];
  return list.slice(0, 20).map(s => {
    if (!s || typeof s !== 'object') return null;
    const time = /^([01]\d|2[0-3]):[0-5]\d$/.test(s.time) ? s.time : null;
    const days = [...new Set((Array.isArray(s.days) ? s.days : [])
      .map(Number)
      .filter(n => Number.isInteger(n) && n >= 0 && n <= 6))].sort();
    if (!time || !days.length) return null;
    const id = typeof s.id === 'string' && /^[a-f0-9]{8,32}$/.test(s.id) ? s.id : randomToken(6);
    const prev = existingList.find(e => e.id === id);
    return {
      id,
      days,
      time,
      tz: isValidTz(s.tz) ? s.tz : DEFAULT_TZ,
      enabled: s.enabled !== false,
      last: prev ? prev.last || '' : ''
    };
  }).filter(Boolean);
}

function sanitizeDevice(input, existing) {
  if (!input || typeof input !== 'object') throw new HttpError(400, 'Geçersiz cihaz verisi.');
  const mac = normalizeMac(input.mac);
  if (!mac) throw new HttpError(400, 'Geçersiz MAC adresi (örn: AA:BB:CC:DD:EE:FF).');
  const ip = cleanStr(input.ip, 15);
  if (ip && !isIPv4(ip)) throw new HttpError(400, 'Geçersiz IP adresi.');

  const p = input.power && typeof input.power === 'object' ? input.power : {};
  const method = POWER_METHODS.includes(p.method) ? p.method : 'none';
  const isSsh = method.startsWith('ssh');
  const user = cleanStr(p.user, 32);
  if (isSsh && !/^[A-Za-z0-9._-]{1,32}$/.test(user)) {
    throw new HttpError(400, 'SSH kullanıcı adı geçersiz (harf, rakam, . _ - kullanılabilir).');
  }
  const port = parseInt(p.port, 10);

  return {
    id: existing ? existing.id : randomToken(6),
    name: cleanStr(input.name, 60) || 'Cihaz',
    icon: DEVICE_ICONS.includes(input.icon) ? input.icon : (existing && existing.icon) || 'desktop',
    mac,
    ip,
    note: cleanNote(input.note),
    power: {
      method,
      user: isSsh ? user : '',
      port: isSsh && Number.isInteger(port) && port > 0 && port < 65536 ? port : 22
    },
    schedules: sanitizeSchedules(input.schedules, existing ? existing.schedules || [] : []),
    createdAt: existing ? existing.createdAt : Date.now(),
    updatedAt: Date.now()
  };
}

function findDevice(id) {
  return db.devices.find(d => d.id === id) || null;
}

function mustDevice(id) {
  const dev = typeof id === 'string' ? findDevice(id) : null;
  if (!dev) throw new HttpError(404, 'Cihaz bulunamadı.');
  return dev;
}

function assertUniqueMac(mac, exceptId) {
  const other = db.devices.find(d => d.mac === mac && d.id !== exceptId);
  if (other) throw new HttpError(409, `Bu MAC adresi zaten "${other.name}" olarak kayıtlı.`);
}

function fmtDuration(secs) {
  if (secs < 60) return `${secs} sn`;
  return `${Math.floor(secs / 60)} dk ${secs % 60} sn`;
}

function lastLine(text) {
  const lines = String(text || '').trim().split('\n').filter(Boolean);
  return lines.length ? lines[lines.length - 1].trim() : 'bilinmeyen hata';
}

// --- 2. OTURUM & PIN ---
function hashPin(pin, salt) {
  return crypto.scryptSync(String(pin), salt, 32).toString('hex');
}

function setPin(pin) {
  const salt = randomToken(16);
  db.auth.pinSalt = salt;
  db.auth.pinHash = hashPin(pin, salt);
  saveData();
}

function verifyPin(pin) {
  if (!db.auth.pinHash || typeof pin !== 'string') return false;
  const a = Buffer.from(hashPin(pin, db.auth.pinSalt), 'hex');
  const b = Buffer.from(db.auth.pinHash, 'hex');
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

function validatePinFormat(pin) {
  if (typeof pin !== 'string' || pin.length < 4 || pin.length > 64) {
    throw new HttpError(400, 'PIN en az 4, en fazla 64 karakter olmalı.');
  }
}

function clientIp(req) {
  return String(req.socket.remoteAddress || '').replace(/^::ffff:/, '');
}

function parseCookies(req) {
  const out = {};
  String(req.headers.cookie || '').split(';').forEach(part => {
    const i = part.indexOf('=');
    if (i > 0) out[part.slice(0, i).trim()] = decodeURIComponent(part.slice(i + 1).trim());
  });
  return out;
}

function createSession(req, res) {
  const token = randomToken(32);
  db.auth.sessions[sha256(token)] = {
    created: Date.now(),
    lastSeen: Date.now(),
    ua: cleanStr(req.headers['user-agent'], 160),
    ip: clientIp(req)
  };
  saveData();
  res.setHeader('Set-Cookie', `${SESSION_COOKIE}=${token}; Path=/; HttpOnly; SameSite=Strict; Max-Age=${SESSION_MAX_AGE}`);
}

function getSession(req) {
  const token = parseCookies(req)[SESSION_COOKIE];
  if (!token) return null;
  const key = sha256(token);
  const session = db.auth.sessions[key];
  if (!session) return null;
  if (Date.now() - session.lastSeen > 3600e3) {
    session.lastSeen = Date.now();
    saveData();
  }
  return { key, ...session };
}

// Kaba kuvvete karşı: 5 hatalı denemeden sonra artan süreli kilit
const loginFails = new Map();
function checkLock(ip) {
  const f = loginFails.get(ip);
  if (f && f.until > Date.now()) {
    throw new HttpError(429, `Çok fazla hatalı deneme. ${Math.ceil((f.until - Date.now()) / 1000)} sn sonra tekrar deneyin.`);
  }
}
function registerFail(ip) {
  const f = loginFails.get(ip) || { count: 0, until: 0 };
  f.count++;
  if (f.count >= 5) f.until = Date.now() + Math.min(15, 2 ** (f.count - 5)) * 60e3;
  loginFails.set(ip, f);
}

// --- 3. AĞ VE SİSTEM YARDIMCILARI ---
function run(cmd, args, timeout = 5000) {
  return new Promise(resolve => {
    execFile(cmd, args, { timeout }, (err, stdout, stderr) => {
      resolve({
        code: err ? (typeof err.code === 'number' ? err.code : -1) : 0,
        stdout: stdout || '',
        stderr: stderr || (err && typeof err.code !== 'number' ? err.message : '')
      });
    });
  });
}

function getPrimaryLanInterface() {
  const ifaces = os.networkInterfaces();
  for (const [name, addrs] of Object.entries(ifaces)) {
    if (name === 'lo' || name.startsWith('tailscale') || name.startsWith('docker') || name.startsWith('br-')) {
      continue;
    }
    for (const addr of addrs) {
      if (addr.family === 'IPv4' && !addr.internal) {
        const parts = addr.address.split('.');
        const subnetPrefix = parts.slice(0, 3).join('.');
        return {
          name,
          ip: addr.address,
          netmask: addr.netmask,
          broadcast: `${subnetPrefix}.255`,
          subnetPrefix
        };
      }
    }
  }
  return { name: 'eth0', ip: '127.0.0.1', broadcast: '255.255.255.255', subnetPrefix: '192.168.1' };
}

async function readNeighbors(ip) {
  const args = ['-j', 'neigh', 'show'];
  if (ip) args.push('to', ip);
  const r = await run('ip', args, 4000);
  try {
    return JSON.parse(r.stdout || '[]')
      .filter(n => n.dst && n.lladdr && isIPv4(n.dst) && !n.lladdr.startsWith('00:00:00'))
      .map(n => ({
        ip: n.dst,
        mac: n.lladdr.toUpperCase(),
        dev: n.dev,
        state: Array.isArray(n.state) ? n.state.join(', ') : String(n.state || 'UNKNOWN')
      }));
  } catch {
    return [];
  }
}

// Kayıtlı cihazların IP'lerini ARP tablosundan güncelle (DHCP ile IP değişirse)
function updateIpsFromNeighbors(neighbors) {
  let changed = false;
  for (const dev of db.devices) {
    const matches = neighbors.filter(n => n.mac === dev.mac);
    const best = matches.find(n => n.state.includes('REACHABLE')) || matches[0];
    if (!best || best.ip === dev.ip) continue;
    if (!dev.ip || best.state.includes('REACHABLE')) {
      dev.ip = best.ip;
      statusMap.delete(dev.id);
      changed = true;
    }
  }
  if (changed) saveData();
}

function scanNetwork() {
  return new Promise((resolve) => {
    const lan = getPrimaryLanInterface();
    const startTime = Date.now();

    // 1-254 arası tüm IP'lere hızlı ping dalgası fırlatarak ARP tablosunu tazele
    const pingCmd = `/bin/bash -c "for i in \\$(seq 1 254); do ping -c 1 -W 1 ${lan.subnetPrefix}.\\$i >/dev/null 2>&1 & done; wait"`;

    exec(pingCmd, { timeout: 8000 }, async () => {
      const neighbors = await readNeighbors();
      updateIpsFromNeighbors(neighbors);

      const byMac = new Map();
      for (const n of neighbors) {
        const prev = byMac.get(n.mac);
        if (!prev || (!prev.state.includes('REACHABLE') && n.state.includes('REACHABLE'))) byMac.set(n.mac, n);
      }
      const rawDevices = [...byMac.values()].sort((a, b) => {
        const numA = Number(a.ip.split('.')[3]) || 0;
        const numB = Number(b.ip.split('.')[3]) || 0;
        return numA - numB;
      });

      const enrichedDevices = await Promise.all(
        rawDevices.map(device => {
          return new Promise(res => {
            const timer = setTimeout(() => res({ ...device, hostname: '' }), 300);
            dns.reverse(device.ip, (dErr, hosts) => {
              clearTimeout(timer);
              res({ ...device, hostname: (!dErr && hosts && hosts[0]) ? hosts[0] : '' });
            });
          });
        })
      );

      resolve({
        success: true,
        durationMs: Date.now() - startTime,
        lan,
        devices: enrichedDevices
      });
    });
  });
}

function sendMagicPacket(macAddress, broadcastIp = '255.255.255.255', repeat = 3) {
  return new Promise((resolve, reject) => {
    const cleanMac = macAddress.replace(/[^0-9A-Fa-f]/g, '');
    if (cleanMac.length !== 12) {
      return reject(new HttpError(400, 'Geçersiz MAC adresi formatı.'));
    }

    const macBuffer = Buffer.from(cleanMac, 'hex');
    const packet = Buffer.alloc(102);
    packet.fill(0xff, 0, 6);
    for (let i = 0; i < 16; i++) {
      macBuffer.copy(packet, 6 + i * 6);
    }

    // Kayıp ihtimaline karşı paket 100ms arayla birkaç kez gönderilir
    const socket = dgram.createSocket({ type: 'udp4', reuseAddr: true });
    socket.on('error', err => { socket.close(); reject(err); });
    socket.bind(() => {
      socket.setBroadcast(true);
      let sent = 0;
      const sendOne = () => socket.send(packet, 0, packet.length, WOL_PORT, broadcastIp, (err) => {
        if (err) { socket.close(); return reject(err); }
        if (++sent >= repeat) { socket.close(); return resolve(); }
        setTimeout(sendOne, 100);
      });
      sendOne();
    });
  });
}

// --- 4. CANLI DURUM (ping + TCP + ARP) ---
const statusMap = new Map(); // deviceId -> { state, via, checkedAt, ip, conflict }
const watches = new Map();   // deviceId -> { kind, startedAt, phase }

// Açık port VEYA "bağlantı reddedildi" yanıtı, cihazın ayakta olduğunu gösterir
function tcpProbe(ip, port, timeout = 800) {
  return new Promise(resolve => {
    const socket = new net.Socket();
    let done = false;
    const finish = (alive) => {
      if (done) return;
      done = true;
      socket.destroy();
      resolve(alive);
    };
    socket.setTimeout(timeout);
    socket.once('connect', () => finish(true));
    socket.once('timeout', () => finish(false));
    socket.once('error', err => finish(err.code === 'ECONNREFUSED'));
    socket.connect(port, ip);
  });
}

async function probeDevice(dev) {
  if (!dev.ip) return { state: 'unknown' };
  // Eski ARP kaydını silip taze çözümleme yaptırıyoruz: ping'i engelleyen Windows'lar da ARP'ye yanıt verir
  await run('ip', ['neigh', 'flush', 'to', dev.ip], 2000);
  const ports = new Set([445, 3389, 22]);
  if (dev.power.method === 'agent') ports.add(db.agent.port);
  if (dev.power.method.startsWith('ssh')) ports.add(dev.power.port);
  const [ping, ...tcp] = await Promise.all([
    run('ping', ['-c', '1', '-W', '1', dev.ip], 3000),
    ...[...ports].map(port => tcpProbe(dev.ip, port))
  ]);
  const neighbor = (await readNeighbors(dev.ip))[0];
  if (neighbor && neighbor.mac !== dev.mac) return { state: 'offline', conflict: neighbor.mac };
  if (ping.code === 0) return { state: 'online', via: 'ping' };
  if (tcp.some(Boolean)) return { state: 'online', via: 'tcp' };
  if (neighbor && neighbor.state.includes('REACHABLE')) return { state: 'arp' };
  return { state: 'offline' };
}

let polling = false;
async function pollStatuses(onlyIds) {
  if (polling) return;
  polling = true;
  try {
    updateIpsFromNeighbors(await readNeighbors());
    const targets = db.devices.filter(d => !onlyIds || onlyIds.includes(d.id));
    const results = await Promise.all(targets.map(d => probeDevice(d).catch(() => ({ state: 'unknown' }))));
    targets.forEach((d, i) => statusMap.set(d.id, { ...results[i], ip: d.ip, checkedAt: Date.now() }));
    processWatches();
  } catch (err) {
    console.error('[Durum] Yoklama hatası:', err.message);
  } finally {
    polling = false;
  }
}

function pollSoon(id) {
  setTimeout(() => pollStatuses(id ? [id] : undefined), 300);
}

function finishWatch(dev, type, text, eventType) {
  watches.delete(dev.id);
  addHistory({ type, deviceId: dev.id, name: dev.name, mac: dev.mac, text });
  pushEvent(eventType, text);
}

function processWatches() {
  const now = Date.now();
  for (const [id, w] of watches) {
    const dev = findDevice(id);
    if (!dev) { watches.delete(id); continue; }
    const st = (statusMap.get(id) || {}).state;
    const elapsed = fmtDuration(Math.round((now - w.startedAt) / 1000));

    // Ping'i engelleyen Windows'lar yalnızca ARP'ye yanıt verir; kapalıyken (S5) ARP yanıtı gelmez
    if (w.kind === 'wake' && (st === 'online' || (st === 'arp' && w.wasOff))) {
      finishWatch(dev, 'online', `${dev.name} açıldı (${elapsed})`, 'success');
    } else if ((w.kind === 'shutdown' && st === 'offline') || (w.kind === 'sleep' && (st === 'offline' || st === 'arp'))) {
      finishWatch(dev, 'offline', `${dev.name} ${w.kind === 'sleep' ? 'uyku moduna geçti' : 'kapandı'} (${elapsed})`, 'success');
    } else if (w.kind === 'restart') {
      if (w.phase === 'down' && st && st !== 'online') w.phase = 'up';
      else if (w.phase === 'up' && st === 'online') finishWatch(dev, 'restarted', `${dev.name} yeniden başladı (${elapsed})`, 'success');
    }

    if (watches.has(id) && now - w.startedAt > WATCH_LIMITS[w.kind]) {
      const text = w.kind === 'wake'
        ? `${dev.name} ${elapsed} içinde açılmadı. BIOS/ağ kartı WoL ayarlarını kontrol edin.`
        : `${dev.name} beklenen sürede ${w.kind === 'restart' ? 'yeniden başlamadı' : 'kapanmadı'}.`;
      finishWatch(dev, 'timeout', text, 'error');
    }
  }
}

// --- 5. UYANDIRMA & UZAKTAN KAPATMA ---
async function wakeDevice(dev, source) {
  const lan = getPrimaryLanInterface();
  await sendMagicPacket(dev.mac, lan.broadcast);
  console.log(`[WoL] Paket iletildi -> MAC: ${dev.mac} | Hedef: ${lan.broadcast}${source === 'schedule' ? ' | Zamanlanmış' : ''}`);
  addHistory({
    type: 'wake', deviceId: dev.id, name: dev.name, mac: dev.mac, source,
    text: `${dev.name} için uyandırma paketi gönderildi${source === 'schedule' ? ' (zamanlanmış)' : ''}`
  });

  const st = statusMap.get(dev.id);
  if (st && st.state === 'online' && Date.now() - st.checkedAt < 30000) return { alreadyOn: true, watching: false };
  if (!dev.ip) return { watching: false };
  watches.set(dev.id, { kind: 'wake', startedAt: Date.now(), phase: 'up', wasOff: !!st && st.state === 'offline' });
  return { watching: true };
}

// SSH: hedefte yalnızca wol-ssh-guard'ın izin verdiği sabit komutlar çalışır (Ayarlar → SSH kurulumu).
// HostKeyAlias, sunucu kimliğini IP'ye değil cihaza bağlar: DHCP ile IP değişse de kimlik doğrulanır,
// IP başka bir makineye geçerse bağlantı reddedilir.
const SSH_VERBS = { ping: 'wol-ping', shutdown: 'wol-shutdown', restart: 'wol-restart' };

function sshArgs(dev, ip, verb) {
  return [
    '-i', SSH_KEY,
    '-o', 'BatchMode=yes',
    '-o', 'IdentitiesOnly=yes',
    '-o', 'StrictHostKeyChecking=accept-new',
    '-o', `UserKnownHostsFile=${KNOWN_HOSTS}`,
    '-o', `HostKeyAlias=wol-${dev.id}`,
    '-o', 'ConnectTimeout=6',
    '-p', String(dev.power.port || 22),
    `${dev.power.user}@${ip}`,
    verb
  ];
}

function sshError(r) {
  const out = `${r.stderr}\n${r.stdout}`;
  if (r.code === 127 || /command not found|izin verilmeyen/i.test(out)) {
    return 'Hedefte wol-ssh-guard kurulu değil; Ayarlar → SSH bölümündeki kurulum komutunu çalıştırın.';
  }
  if (/IDENTIFICATION HAS CHANGED|Host key verification failed/i.test(out)) {
    return 'Hedefin SSH kimliği değişmiş; güvenlik için bağlantı reddedildi.';
  }
  if (/Permission denied/i.test(out)) return 'SSH anahtarı reddedildi; hedefteki authorized_keys satırını kontrol edin.';
  return `SSH başarısız: ${lastLine(r.stderr)}`;
}

function readPubKey() {
  try { return fs.readFileSync(`${SSH_KEY}.pub`, 'utf8').trim(); } catch { return null; }
}

async function ensureSshKey() {
  if (!fs.existsSync(SSH_KEY)) {
    fs.mkdirSync(KEY_DIR, { recursive: true, mode: 0o700 });
    const r = await run('ssh-keygen', ['-t', 'ed25519', '-N', '', '-C', `wol-dashboard@${os.hostname()}`, '-f', SSH_KEY], 15000);
    if (r.code !== 0) throw new HttpError(500, `SSH anahtarı oluşturulamadı: ${lastLine(r.stderr)}`);
  }
  return readPubKey();
}

// Hedefte çalıştırılacak kurulum: anahtar yalnızca yerel alt ağdan ve yalnızca wol-ssh-guard ile kullanılabilir
function buildSshSetup(pubKey) {
  const from = `${getPrimaryLanInterface().subnetPrefix}.*`;
  return `sudo sh -c 'cat > /usr/local/bin/wol-ssh-guard <<"EOF"
#!/bin/sh
# WoL paneli: bu anahtarla yalnizca asagidaki komutlar calisabilir
run() { if [ "$(id -u)" -eq 0 ]; then exec "$@"; else exec sudo -n "$@"; fi; }
case "$SSH_ORIGINAL_COMMAND" in
  wol-ping) echo wol-ok ;;
  wol-shutdown) run /usr/bin/systemctl poweroff ;;
  wol-restart) run /usr/bin/systemctl reboot ;;
  *) echo "wol-ssh-guard: izin verilmeyen komut" >&2; exit 1 ;;
esac
EOF
chmod 755 /usr/local/bin/wol-ssh-guard'
mkdir -p ~/.ssh && chmod 700 ~/.ssh
echo 'restrict,from="${from}",command="/usr/local/bin/wol-ssh-guard" ${pubKey}' >> ~/.ssh/authorized_keys
chmod 600 ~/.ssh/authorized_keys`;
}

// Ajan protokolü v2: anahtar ağda hiç dolaşmaz; her istek HMAC-SHA256 ile imzalanır.
// İmza yöntem, yol, zaman damgası, tek kullanımlık nonce ve hedef MAC'i kapsar. Ajan imzayı,
// ±2 dk saat farkını, nonce tekrarını ve MAC'in kendi ağ kartlarından birine ait olduğunu doğrular.
const AGENT_ERRORS = {
  sig: 'Ajan imzayı reddetti (anahtar eşleşmiyor). Ajanı Ayarlar\'daki güncel komutla yeniden kurun.',
  token: 'Ajan eski sürüm. Ayarlar\'daki güncel komutla yeniden kurun.',
  auth: 'Ajan imzasız isteği reddetti.',
  replay: 'Ajan isteği tekrar olarak algıladı; yeniden deneyin.',
  mac: 'Bu IP\'deki bilgisayar kayıtlı cihaz değil (MAC eşleşmedi); komut uygulanmadı. Ağı tarayın.',
  source: 'Ajan isteği reddetti: kaynak adres yerel ağda değil.'
};

function signAgentRequest(method, pathName, mac) {
  const ts = String(Date.now());
  const nonce = randomToken(16);
  const macHex = mac.replace(/:/g, '');
  const sig = crypto.createHmac('sha256', db.agent.token)
    .update([method, pathName, ts, nonce, macHex].join('\n'))
    .digest('hex');
  return { 'X-Wol-Ts': ts, 'X-Wol-Nonce': nonce, 'X-Wol-Mac': macHex, 'X-Wol-Sig': sig };
}

function agentRequest(dev, ip, method, pathName) {
  return new Promise(resolve => {
    const req = http.request({
      host: ip,
      port: db.agent.port,
      path: pathName,
      method,
      headers: { ...signAgentRequest(method, pathName, dev.mac), 'Content-Length': 0 },
      timeout: 5000
    }, res => {
      let body = '';
      res.on('data', c => { body += c; });
      res.on('end', () => {
        let data = {};
        try { data = JSON.parse(body); } catch { /* yok say */ }
        if (res.statusCode === 200 && data.ok) return resolve({ ok: true, data });
        let error = AGENT_ERRORS[data.error];
        if (data.error === 'time') {
          error = `Saat farkı çok büyük (${Math.round(Math.abs(Date.now() - Number(data.now)) / 1000)} sn). Bilgisayarın saatini eşitleyin.`;
        }
        resolve({ ok: false, error: error || `Ajan HTTP ${res.statusCode} döndürdü.` });
      });
    });
    req.on('timeout', () => req.destroy(new Error('timeout')));
    req.on('error', err => resolve({
      ok: false,
      error: err.message === 'timeout'
        ? 'Ajana ulaşılamadı (zaman aşımı). Cihaz açık ve ajan kurulu mu?'
        : err.code === 'ECONNREFUSED'
          ? 'Bağlantı reddedildi: ajan çalışmıyor.'
          : `Ajana ulaşılamadı: ${err.message}`
    }));
    req.end();
  });
}

// Komut göndermeden önce IP'nin hâlâ bu cihaza ait olduğunu ARP ile doğrula; DHCP ile değiştiyse
// cihazı MAC'inden bulup yeni IP'yi kullan. persist: bulunan yeni IP kayda yazılsın mı.
async function resolveTarget(dev, persist) {
  if (!dev.ip) throw new HttpError(400, 'Cihazın IP adresi bilinmiyor. Önce ağı tarayın veya IP girin.');
  await run('ip', ['neigh', 'flush', 'to', dev.ip], 2000);
  await run('ping', ['-c', '1', '-W', '1', dev.ip], 3000);
  const here = (await readNeighbors(dev.ip))[0];
  if (here && here.mac === dev.mac) return dev.ip;

  const moved = (await readNeighbors()).find(n => n.mac === dev.mac && n.ip !== dev.ip);
  if (moved) {
    await run('ip', ['neigh', 'flush', 'to', moved.ip], 2000);
    await run('ping', ['-c', '1', '-W', '1', moved.ip], 3000);
    const check = (await readNeighbors(moved.ip))[0];
    if (check && check.mac === dev.mac) {
      if (persist) {
        dev.ip = moved.ip;
        statusMap.delete(dev.id);
        saveData();
      }
      return moved.ip;
    }
  }
  if (here) throw new HttpError(409, `${dev.ip} adresinde artık başka bir cihaz var (${here.mac}); komut gönderilmedi. Ağı tarayın.`);
  throw new HttpError(409, `${dev.name} ağda yanıt vermiyor (kapalı olabilir).`);
}

async function powerAction(dev, action) {
  const method = dev.power.method;
  if (method === 'none') throw new HttpError(400, 'Bu cihaz için kapatma yöntemi ayarlanmamış (Düzenle → Uzaktan kapatma).');
  if (action === 'sleep' && method !== 'agent') throw new HttpError(400, 'Uyku yalnızca Windows ajanı ile destekleniyor.');

  let error = null;
  let ip = null;
  try {
    ip = await resolveTarget(dev, true);
  } catch (err) {
    error = err.message;
  }
  if (!error && method === 'agent') {
    const r = await agentRequest(dev, ip, 'POST', `/${action}`);
    if (!r.ok) error = r.error;
  } else if (!error) {
    await ensureSshKey();
    const r = await run('ssh', sshArgs(dev, ip, SSH_VERBS[action]), 20000);
    // Kapanış sırasında bağlantının kopması (255) başarı sayılır
    const droppedOk = r.code === 255 && /closed|reset|broken pipe/i.test(r.stderr);
    if (r.code !== 0 && !droppedOk) error = sshError(r);
  }

  if (error) {
    addHistory({ type: 'fail', deviceId: dev.id, name: dev.name, mac: dev.mac, text: `${dev.name}: ${POWER_ACTIONS[action]} başarısız. ${error}` });
    throw new HttpError(502, error);
  }
  addHistory({ type: action, deviceId: dev.id, name: dev.name, mac: dev.mac, text: `${dev.name}: ${POWER_ACTIONS[action]} komutu gönderildi` });
  watches.set(dev.id, { kind: action, startedAt: Date.now(), phase: 'down' });
}

// --- 6. ZAMANLANMIŞ UYANDIRMA ---
const WEEKDAYS = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'];
function zonedNow(tz) {
  const fmt = new Intl.DateTimeFormat('en-US', {
    timeZone: tz, hourCycle: 'h23', weekday: 'short',
    year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit'
  });
  const p = Object.fromEntries(fmt.formatToParts(new Date()).map(x => [x.type, x.value]));
  return { date: `${p.year}-${p.month}-${p.day}`, time: `${p.hour}:${p.minute}`, weekday: WEEKDAYS.indexOf(p.weekday) };
}

function runScheduler() {
  for (const dev of db.devices) {
    for (const s of dev.schedules || []) {
      if (!s.enabled) continue;
      const now = zonedNow(isValidTz(s.tz) ? s.tz : DEFAULT_TZ);
      const key = `${now.date} ${now.time}`;
      if (s.time !== now.time || !s.days.includes(now.weekday) || s.last === key) continue;
      s.last = key;
      saveData();
      wakeDevice(dev, 'schedule')
        .then(() => pushEvent('info', `⏰ Zamanlanmış uyandırma: ${dev.name}`))
        .catch(err => {
          addHistory({ type: 'fail', deviceId: dev.id, name: dev.name, mac: dev.mac, text: `${dev.name}: zamanlanmış uyandırma başarısız. ${err.message}` });
          pushEvent('error', `${dev.name} zamanlanmış uyandırma başarısız: ${err.message}`);
        });
    }
  }
}

// --- 7. WINDOWS AJANI (uzaktan kapatma dinleyicisi, protokol v2) ---
// Not: Betikler yalnızca ASCII içerir (PowerShell 5.1 kodlama sorunları) ve ters eğik çizgi
// kullanmaz (JS şablon metni içinde kaçış gerektirmesin diye).
function buildAgentScript() {
  return `# WoL Ajani v2 - WoL & Ag Rolesi paneli icin uzaktan kapatma dinleyicisi
# Yalnizca HMAC-SHA256 ile imzalanmis istekleri kabul eder; anahtar agda hic dolasmaz.
# Imza: yontem, yol, zaman damgasi, tek kullanimlik nonce ve hedef MAC adresini kapsar.
$Secret = '${db.agent.token}'
$Port = ${db.agent.port}
$MaxSkewMs = 120000
$CR = [string][char]13
$LF = [string][char]10
$CRLF = $CR + $LF
$Utf8 = New-Object System.Text.UTF8Encoding($false)
$Hmac = [System.Security.Cryptography.HMACSHA256]::new($Utf8.GetBytes($Secret))
$Seen = @{}
$LogFile = Join-Path $PSScriptRoot 'agent.log'

function Write-Log($msg) {
  try {
    if ((Test-Path $LogFile) -and (Get-Item $LogFile).Length -gt 1MB) { Move-Item $LogFile ($LogFile + '.1') -Force }
    Add-Content -Path $LogFile -Value ((Get-Date).ToString('s') + ' ' + $msg)
  } catch {}
}

function Get-NowMs { [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds() }

# Bu bilgisayarin tum ag kartlarinin MAC adresleri (AABBCCDDEEFF)
function Get-MyMacs {
  [System.Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces() |
    ForEach-Object { $_.GetPhysicalAddress().ToString().ToUpperInvariant() } |
    Where-Object { $_.Length -eq 12 }
}

# Yalnizca ozel (yerel) IPv4 adreslerinden gelen baglantilar
function Test-LocalSource($addr) {
  if ($addr.IsIPv4MappedToIPv6) { $addr = $addr.MapToIPv4() }
  $b = $addr.GetAddressBytes()
  if ($b.Length -ne 4) { return $false }
  return ($b[0] -eq 10) -or ($b[0] -eq 127) -or ($b[0] -eq 172 -and $b[1] -ge 16 -and $b[1] -le 31) -or ($b[0] -eq 192 -and $b[1] -eq 168)
}

# Sabit zamanli karsilastirma
function Test-SameText([string]$a, [string]$b) {
  if ($a.Length -ne $b.Length) { return $false }
  $diff = 0
  for ($i = 0; $i -lt $a.Length; $i++) { $diff = $diff -bor ([int]$a[$i] -bxor [int]$b[$i]) }
  return ($diff -eq 0)
}

# Istek basligini en fazla 8 KB okur
function Read-RequestHead($stream) {
  $buf = New-Object byte[] 1
  $sb = New-Object System.Text.StringBuilder
  $tail = ''
  while ($sb.Length -lt 8192) {
    if ($stream.Read($buf, 0, 1) -le 0) { return $null }
    $ch = [string][char]$buf[0]
    [void]$sb.Append($ch)
    $tail = $tail + $ch
    if ($tail.Length -gt 4) { $tail = $tail.Substring($tail.Length - 4) }
    if ($tail -eq ($CRLF + $CRLF)) { return $sb.ToString() }
  }
  return $null
}

$listener = $null
while ($null -eq $listener) {
  try {
    $l = New-Object System.Net.Sockets.TcpListener([System.Net.IPAddress]::Any, $Port)
    $l.Start()
    $listener = $l
  } catch {
    Write-Log ('Port acilamadi: ' + $_.Exception.Message)
    Start-Sleep -Seconds 10
  }
}
Write-Log ('Dinleniyor: TCP ' + $Port + ' (protokol v2)')

while ($true) {
  $client = $listener.AcceptTcpClient()
  $action = $null
  $remote = $null
  try {
    $client.ReceiveTimeout = 3000
    $client.SendTimeout = 3000
    $remote = $client.Client.RemoteEndPoint.Address
    $stream = $client.GetStream()
    $status = '200 OK'
    $body = '{"ok":false}'
    $err = $null
    $now = Get-NowMs

    if (-not (Test-LocalSource $remote)) {
      $status = '403 Forbidden'
      $err = 'source'
    } else {
      $head = Read-RequestHead $stream
      if ($null -eq $head) { throw 'Gecersiz ya da cok uzun istek basligi' }
      $lines = $head.Split($LF) | ForEach-Object { $_.Trim() }
      $parts = ([string]$lines[0]).Split(' ')
      $method = $parts[0]
      $path = '/'
      if ($parts.Length -gt 1) { $path = $parts[1] }
      $h = @{}
      foreach ($line in ($lines | Select-Object -Skip 1)) {
        $i = $line.IndexOf(':')
        if ($i -gt 0) { $h[$line.Substring(0, $i).Trim().ToLowerInvariant()] = $line.Substring($i + 1).Trim() }
      }
      $ts = [string]$h['x-wol-ts']
      $nonce = ([string]$h['x-wol-nonce']).ToLowerInvariant()
      $mac = ([string]$h['x-wol-mac']).ToUpperInvariant()
      $sig = ([string]$h['x-wol-sig']).ToLowerInvariant()

      if (-not ($ts -match '^[0-9]{10,16}$' -and $nonce -match '^[a-f0-9]{16,64}$' -and $mac -match '^[0-9A-F]{12}$' -and $sig -match '^[a-f0-9]{64}$')) {
        $status = '401 Unauthorized'
        $err = 'auth'
      } else {
        $msg = $method + $LF + $path + $LF + $ts + $LF + $nonce + $LF + $mac
        $expected = -join ($Hmac.ComputeHash($Utf8.GetBytes($msg)) | ForEach-Object { $_.ToString('x2') })
        if (-not (Test-SameText $expected $sig)) {
          $status = '401 Unauthorized'
          $err = 'sig'
        } elseif ([Math]::Abs($now - [int64]$ts) -gt $MaxSkewMs) {
          $status = '401 Unauthorized'
          $err = 'time'
        } elseif ($Seen.ContainsKey($nonce)) {
          $status = '401 Unauthorized'
          $err = 'replay'
        } elseif (@(Get-MyMacs) -notcontains $mac) {
          $status = '409 Conflict'
          $err = 'mac'
        } else {
          $Seen[$nonce] = $now
          foreach ($k in @($Seen.Keys)) { if ($now - $Seen[$k] -gt (2 * $MaxSkewMs)) { $Seen.Remove($k) } }
          if ($method -eq 'GET' -and $path -eq '/ping') {
            $body = '{"ok":true,"v":2,"host":"' + $env:COMPUTERNAME + '"}'
          } elseif ($method -eq 'POST' -and (@('/shutdown', '/restart', '/sleep') -contains $path)) {
            $action = $path.TrimStart('/')
            $body = '{"ok":true,"action":"' + $action + '"}'
          } else {
            $status = '404 Not Found'
          }
        }
      }
    }

    if ($err -eq 'time') {
      $body = '{"ok":false,"error":"time","now":' + $now + '}'
    } elseif ($err) {
      $body = '{"ok":false,"error":"' + $err + '"}'
    }
    if ($err) { Write-Log ('Reddedildi (' + $err + '): ' + $remote) }

    $bytes = $Utf8.GetBytes($body)
    $resp = 'HTTP/1.1 ' + $status + $CRLF + 'Content-Type: application/json' + $CRLF + 'Content-Length: ' + $bytes.Length + $CRLF + 'Connection: close' + $CRLF + $CRLF
    $respBytes = [System.Text.Encoding]::ASCII.GetBytes($resp)
    $stream.Write($respBytes, 0, $respBytes.Length)
    $stream.Write($bytes, 0, $bytes.Length)
    $stream.Flush()
  } catch {
    Write-Log ('Istek hatasi (' + $remote + '): ' + $_.Exception.Message)
  } finally {
    $client.Close()
  }

  if ($action) {
    Write-Log ('Komut: ' + $action + ' (' + $remote + ')')
    switch ($action) {
      'shutdown' { & shutdown.exe /s /t 5 /c 'WoL paneli tarafindan kapatiliyor' }
      'restart'  { & shutdown.exe /r /t 5 /c 'WoL paneli tarafindan yeniden baslatiliyor' }
      'sleep'    {
        Add-Type -AssemblyName System.Windows.Forms
        [void][System.Windows.Forms.Application]::SetSuspendState([System.Windows.Forms.PowerState]::Suspend, $false, $false)
      }
    }
  }
}
`;
}

function buildAgentInstaller() {
  const agentB64 = Buffer.from(buildAgentScript(), 'utf8').toString('base64');
  return `# WoL Ajani v2 kurulum betigi (Yonetici PowerShell'de calistirin)
$ErrorActionPreference = 'Stop'
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
if (-not (New-Object Security.Principal.WindowsPrincipal($identity)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  Write-Host 'HATA: Bu komutu "Yonetici olarak calistir" ile acilmis PowerShell penceresinde calistirin.' -ForegroundColor Red
  return
}
$Port = ${db.agent.port}
$Dir = Join-Path $env:ProgramData 'WolAgent'
$AgentPath = Join-Path $Dir 'agent.ps1'
$TaskName = 'WoL Ajani'

Write-Host 'WoL Ajani kuruluyor...' -ForegroundColor Cyan
if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) {
  Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
  Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
}
New-Item -ItemType Directory -Force -Path $Dir | Out-Null
# Anahtar iceren klasoru yalnizca SYSTEM ve Yoneticiler okuyabilsin
& icacls.exe $Dir /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' | Out-Null
[IO.File]::WriteAllBytes($AgentPath, [Convert]::FromBase64String('${agentB64}'))

# Sunucunun IP'si DHCP ile degisebilir: belirli bir IP yerine yerel alt aga izin verilir.
# Asil koruma imza dogrulamasidir; ajan ayrica ozel olmayan adresleri kendisi reddeder.
Get-NetFirewallRule -DisplayName $TaskName -ErrorAction SilentlyContinue | Remove-NetFirewallRule
New-NetFirewallRule -DisplayName $TaskName -Direction Inbound -Protocol TCP -LocalPort $Port -RemoteAddress LocalSubnet -Action Allow -Profile Any | Out-Null

$act = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument ('-NoProfile -NonInteractive -ExecutionPolicy Bypass -WindowStyle Hidden -File "' + $AgentPath + '"')
$trg = New-ScheduledTaskTrigger -AtStartup
$prn = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
$set = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -ExecutionTimeLimit ([TimeSpan]::Zero) -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1)
Register-ScheduledTask -TaskName $TaskName -Action $act -Trigger $trg -Principal $prn -Settings $set | Out-Null
Start-ScheduledTask -TaskName $TaskName

# Kurulum komutu anahtari URL'de tasidi: PowerShell gecmisinden sil
try {
  $hist = (Get-PSReadLineOption).HistorySavePath
  if ($hist -and (Test-Path $hist)) {
    $keep = @(Get-Content $hist | Where-Object { $_ -notmatch 'agent/install' })
    Set-Content -Path $hist -Value $keep -Encoding UTF8
  }
} catch {}

Start-Sleep -Seconds 2
Write-Host ''
Write-Host ('Kurulum tamam. Ajan TCP ' + $Port + ' portunda yalnizca imzali istekleri kabul ediyor.') -ForegroundColor Green
Write-Host 'Bu bilgisayarin ag kartlari (panelde MAC/IP olarak kullanin):'
Get-NetAdapter -Physical | Where-Object Status -eq 'Up' | ForEach-Object {
  $ip = (Get-NetIPAddress -InterfaceIndex $_.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue | Select-Object -First 1).IPAddress
  Write-Host ('  ' + $_.Name + '  MAC: ' + ($_.MacAddress -replace '-', ':') + '  IP: ' + $ip)
}
`;
}

// Panelde gösterilen tek satırlık kurulum: betik indirilir, SHA-256 özeti doğrulanmadan çalıştırılmaz.
// Özet panelde (tercihen Tailscale üzerinden açılmış, şifreli sayfada) gösterildiği için betiğin
// yerel ağda şifresiz indirilmesi sırasında araya kod eklenmesi engellenir.
function buildAgentCommands() {
  const lan = getPrimaryLanInterface();
  const base = `http://${lan.ip}${Number(PORT) !== 80 ? `:${PORT}` : ''}`;
  const url = `${base}/agent/install.ps1?key=${db.agent.token}`;
  const sha256 = crypto.createHash('sha256').update(buildAgentInstaller(), 'utf8').digest('hex');
  const install = "$u='" + url + "'; $b=(Invoke-WebRequest -UseBasicParsing $u).RawContentStream.ToArray(); " +
    "$h=-join([Security.Cryptography.SHA256]::Create().ComputeHash($b)|ForEach-Object{$_.ToString('x2')}); " +
    "if($h -eq '" + sha256 + "'){Invoke-Expression ([Text.Encoding]::UTF8.GetString($b))}" +
    "else{Write-Host 'Dogrulama basarisiz: betik yolda degistirilmis olabilir, kurulum yapilmadi.' -ForegroundColor Red}";
  const uninstall = "Stop-ScheduledTask 'WoL Ajani'; Unregister-ScheduledTask 'WoL Ajani' -Confirm:$false; " +
    "Remove-NetFirewallRule -DisplayName 'WoL Ajani'; Remove-Item -Recurse -Force (Join-Path $env:ProgramData 'WolAgent')";
  return { install, uninstall, sha256 };
}

// --- 8. GÖMÜLÜ DASHBOARD FRONTEND (DESIGN.md: "starlit violet cosmos") ---
// İkonlar: 1.5px çizgi, dolgusuz, geometrik
const ICON_SPRITE = `<svg xmlns="http://www.w3.org/2000/svg" style="position:absolute;width:0;height:0;overflow:hidden" aria-hidden="true">
  <defs>
    <symbol id="i-power" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"><path d="M12 3v8M6.4 6.4a8 8 0 1 0 11.2 0"/></symbol>
    <symbol id="i-bolt" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linejoin="round"><path d="M13 2.5 4.5 13.5H12l-1 8 8.5-11H12l1-8z"/></symbol>
    <symbol id="i-plus" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"><path d="M12 5v14M5 12h14"/></symbol>
    <symbol id="i-scan" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M20 11.5a8 8 0 1 1-2.4-5.9M20 4v5h-5"/></symbol>
    <symbol id="i-more" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><circle cx="5.5" cy="12" r="1.2"/><circle cx="12" cy="12" r="1.2"/><circle cx="18.5" cy="12" r="1.2"/></symbol>
    <symbol id="i-search" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"><circle cx="11" cy="11" r="7"/><path d="m20 20-3.5-3.5"/></symbol>
    <symbol id="i-chev" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="m9 6 6 6-6 6"/></symbol>
    <symbol id="i-x" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"><path d="M7 7l10 10M17 7 7 17"/></symbol>
    <symbol id="i-copy" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linejoin="round"><rect x="8.5" y="8.5" width="12" height="12" rx="2"/><path d="M15.5 8.5V5.5a2 2 0 0 0-2-2h-8a2 2 0 0 0-2 2v8a2 2 0 0 0 2 2h3"/></symbol>
  </defs>
</svg>`;

// Tarayıcıda çalışan kod; kaynağı olduğu gibi sayfaya gömülür (Node bu fonksiyonu çalıştırmaz).
function clientMain() {
  'use strict';
  const $ = (sel, root) => (root || document).querySelector(sel);
  const $$ = (sel, root) => Array.from((root || document).querySelectorAll(sel));
  const DAY_NAMES = ['Pz', 'Pt', 'Sa', 'Ça', 'Pe', 'Cu', 'Ct'];
  const DAY_ORDER = [1, 2, 3, 4, 5, 6, 0];
  const BROWSER_TZ = (() => {
    try { return Intl.DateTimeFormat().resolvedOptions().timeZone || 'Europe/Istanbul'; } catch (e) { return 'Europe/Istanbul'; }
  })();
  const VIEWS = {
    devices: { title: 'Cihazlar', lead: 'Kayıtlı bilgisayarlarını tek dokunuşla uyandır.' },
    network: { title: 'Ağ', lead: 'Yerel ağda görünen cihazlar.' },
    history: { title: 'Geçmiş', lead: 'Uyandırma ve kapatma kayıtları.' },
    settings: { title: 'Ayarlar', lead: 'Güvenlik, uzaktan kapatma ve yedekleme.' }
  };
  const WATCH_TEXT = { wake: 'Uyanıyor…', shutdown: 'Kapanıyor…', restart: 'Yeniden başlıyor…', sleep: 'Uykuya geçiyor…' };
  const POWER_LABEL = { none: 'Kapalı', agent: 'Windows ajanı', 'ssh-linux': 'SSH (Linux)' };
  const METHOD_HINT = {
    none: 'Bu cihaz yalnızca uyandırılır.',
    agent: 'Hedef bilgisayara Windows ajanı kurulmalı (Ayarlar → Windows ajanı).',
    'ssh-linux': 'Hedefte Ayarlar → SSH bölümündeki kurulum komutu çalıştırılmalı; anahtar yalnızca kapatıp yeniden başlatabilir.'
  };

  const S = {
    view: 'devices', devices: [], status: {}, watches: {}, discovered: [], lan: null,
    seq: 0, seqReady: false, pollTimer: null, started: false, scanning: false, scannedOnce: false,
    history: null, settings: null
  };

  const ic = name => '<svg class="ic" aria-hidden="true"><use href="#i-' + name + '"/></svg>';
  const esc = v => String(v == null ? '' : v).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

  // ---------- Bildirim (rozet biçiminde, altta ortada) ----------
  function toast(msg, type) {
    const box = $('#toasts');
    const t = document.createElement('div');
    t.className = 'toast' + (type === 'error' ? ' error' : '');
    t.setAttribute('role', type === 'error' ? 'alert' : 'status');
    t.innerHTML = '<i></i><span></span>';
    $('span', t).textContent = msg;
    box.appendChild(t);
    while (box.children.length > 3) box.firstChild.remove();
    setTimeout(() => {
      t.classList.add('out');
      setTimeout(() => t.remove(), 300);
    }, type === 'error' ? 5500 : 3200);
  }

  async function api(path, body) {
    const opts = { method: body === undefined ? 'GET' : 'POST', headers: {}, credentials: 'same-origin' };
    if (body !== undefined) {
      opts.headers['Content-Type'] = 'application/json';
      opts.body = JSON.stringify(body);
    }
    let res;
    let text;
    try {
      res = await fetch(path, opts);
      text = await res.text();
    } catch (e) {
      throw new Error('Sunucuya ulaşılamıyor.');
    }
    let data;
    try {
      data = JSON.parse(text);
    } catch (e) {
      throw new Error(text.trim().startsWith('<')
        ? 'Sunucu JSON yerine HTML döndürdü (GoodbyeDPI veya bir proxy araya giriyor olabilir).'
        : 'Geçersiz sunucu yanıtı (HTTP ' + res.status + ').');
    }
    if (res.status === 401 && data.auth) {
      showAuth(true);
      throw new Error('Oturum süresi doldu, tekrar giriş yapın.');
    }
    if (!data.success) throw new Error(data.message || 'İşlem başarısız.');
    return data;
  }

  async function copyText(text) {
    try {
      if (navigator.clipboard && window.isSecureContext) {
        await navigator.clipboard.writeText(text);
        return true;
      }
    } catch (e) { /* aşağıdaki yönteme düş */ }
    const ta = document.createElement('textarea');
    ta.value = text;
    ta.style.position = 'fixed';
    ta.style.opacity = '0';
    document.body.appendChild(ta);
    ta.select();
    let ok = false;
    try { ok = document.execCommand('copy'); } catch (e) { ok = false; }
    ta.remove();
    return ok;
  }

  function timeOf(ts) {
    return new Date(ts).toLocaleTimeString('tr-TR', { hour: '2-digit', minute: '2-digit' });
  }

  function dayLabel(ts) {
    const d = new Date(ts);
    const start = x => new Date(x.getFullYear(), x.getMonth(), x.getDate()).getTime();
    const diff = Math.round((start(new Date()) - start(d)) / 864e5);
    if (diff === 0) return 'Bugün';
    if (diff === 1) return 'Dün';
    return d.toLocaleDateString('tr-TR', { weekday: 'long', day: 'numeric', month: 'long' });
  }

  // ---------- Pencere, onay, menü ----------
  let sheetToken = 0;
  function openSheet(opts) {
    sheetToken++;
    const root = $('#sheetRoot');
    root.classList.remove('hidden', 'closing');
    root.innerHTML = '<div class="sheet" role="dialog" aria-modal="true" aria-label="' + esc(opts.title) + '">' +
      '<header class="sheet-head"><h2>' + esc(opts.title) + '</h2>' +
      '<button type="button" class="icon-btn" data-sheet-close aria-label="Kapat">' + ic('x') + '</button></header>' +
      '<div class="sheet-body">' + opts.body + '</div>' +
      '<footer class="sheet-foot">' + (opts.footLeft || '') + '<span class="spacer"></span>' +
      '<button type="button" class="btn btn-ghost" data-sheet-close>Vazgeç</button>' +
      (opts.okText ? '<button type="button" class="btn btn-primary" data-sheet-ok>' + esc(opts.okText) + '</button>' : '') +
      '</footer></div>';
    document.body.classList.add('modal-open');
    const sheet = $('.sheet', root);
    $$('[data-sheet-close]', sheet).forEach(b => b.addEventListener('click', closeSheet));
    const ok = $('[data-sheet-ok]', sheet);
    if (ok && opts.onOk) {
      ok.addEventListener('click', async () => {
        ok.disabled = true;
        try { await opts.onOk(sheet); } finally { if (ok.isConnected) ok.disabled = false; }
      });
    }
    if (opts.autofocus) setTimeout(() => { const f = $('input', sheet); if (f) f.focus(); }, 80);
    return sheet;
  }

  function closeSheet() {
    const root = $('#sheetRoot');
    if (root.classList.contains('hidden')) return;
    const token = sheetToken;
    root.classList.add('closing');
    document.body.classList.remove('modal-open');
    setTimeout(() => {
      if (token !== sheetToken) return;
      root.classList.add('hidden');
      root.classList.remove('closing');
      root.innerHTML = '';
    }, 200);
  }

  function ask(o) {
    return new Promise(resolve => {
      const root = $('#alertRoot');
      root.innerHTML = '<div class="alert" role="alertdialog" aria-modal="true" aria-label="' + esc(o.title) + '">' +
        '<h2>' + esc(o.title) + '</h2>' + (o.message ? '<p>' + esc(o.message) + '</p>' : '') +
        '<div class="alert-actions">' + o.buttons.map((b, i) =>
          '<button type="button" class="btn ' + (b.role === 'cancel' ? 'btn-ghost' : 'btn-primary') + '" data-i="' + i + '">' + esc(b.label) + '</button>'
        ).join('') + '</div></div>';
      root.classList.remove('hidden');
      const onKey = e => {
        if (e.key === 'Escape') { e.stopPropagation(); done(null); }
      };
      function done(value) {
        root.classList.add('hidden');
        root.innerHTML = '';
        root.onclick = null;
        document.removeEventListener('keydown', onKey, true);
        resolve(value);
      }
      document.addEventListener('keydown', onKey, true);
      root.onclick = e => {
        const b = e.target.closest('[data-i]');
        if (b) done(o.buttons[Number(b.dataset.i)].value);
        else if (e.target === root) done(null);
      };
      const def = $('.btn-primary', root);
      if (def) def.focus();
    });
  }

  function confirmAction(title, message, label) {
    return ask({
      title,
      message,
      buttons: [{ label: 'Vazgeç', role: 'cancel', value: false }, { label, value: true }]
    });
  }

  function openMenu(anchor, groups) {
    const m = $('#menu');
    const items = [];
    m.innerHTML = groups.map(g => '<div class="menu-group">' + g.map(it => {
      items.push(it);
      return '<button type="button" class="menu-item" role="menuitem" data-i="' + (items.length - 1) + '"' + (it.disabled ? ' disabled' : '') + '>' + esc(it.label) + '</button>';
    }).join('') + '</div>').join('');
    m.classList.remove('hidden');
    const r = anchor.getBoundingClientRect();
    const w = m.offsetWidth;
    const h = m.offsetHeight;
    const left = Math.max(8, Math.min(r.right - w, innerWidth - w - 8));
    let top = r.bottom + 8;
    if (top + h > innerHeight - 8) top = Math.max(8, r.top - h - 8);
    m.style.left = left + 'px';
    m.style.top = top + 'px';
    m.onclick = e => {
      const b = e.target.closest('[data-i]');
      if (!b) return;
      closeMenu();
      items[Number(b.dataset.i)].run();
    };
  }

  function closeMenu() {
    $('#menu').classList.add('hidden');
  }

  document.addEventListener('pointerdown', e => {
    if (!e.target.closest('#menu') && !e.target.closest('[data-action="menu"]')) closeMenu();
  });
  window.addEventListener('resize', closeMenu);
  window.addEventListener('scroll', closeMenu, true);

  // ---------- Giriş / PIN ----------
  let authMode = 'login';
  function showAuth(pinSet) {
    S.started = false;
    clearTimeout(S.pollTimer);
    closeSheet();
    closeMenu();
    document.body.classList.add('locked');
    authMode = pinSet === false ? 'setup' : 'login';
    const setup = authMode === 'setup';
    $('#lockDesc').textContent = setup ? 'Panel için bir PIN belirle. Her cihazda bir kez girmen yeterli.' : 'Devam etmek için PIN\'ini gir.';
    $('#authPin2').classList.toggle('hidden', !setup);
    $('#authPin').placeholder = setup ? 'Yeni PIN' : 'PIN';
    $('#authPin').setAttribute('autocomplete', setup ? 'new-password' : 'current-password');
    $('#authGo').textContent = setup ? 'PIN\'i kaydet' : 'Giriş yap';
    $('#authErr').textContent = '';
    $('#lock').classList.remove('hidden');
    setTimeout(() => $('#authPin').focus(), 60);
  }

  $('#authForm').addEventListener('submit', async e => {
    e.preventDefault();
    const pin = $('#authPin').value;
    if (!pin) return;
    if (authMode === 'setup') {
      if (!$('#authPin2').value) { $('#authPin2').focus(); return; }
      if (pin !== $('#authPin2').value) { $('#authErr').textContent = 'PIN\'ler eşleşmiyor.'; return; }
    }
    const btn = $('#authGo');
    btn.disabled = true;
    try {
      await api(authMode === 'setup' ? '/api/auth/setup' : '/api/auth/login', { pin });
      $('#authPin').value = '';
      $('#authPin2').value = '';
      $('#lock').classList.add('hidden');
      start();
    } catch (err) {
      $('#authErr').textContent = err.message;
      $('#authPin').select();
    } finally {
      btn.disabled = false;
    }
  });

  async function boot() {
    setView(location.hash.slice(1), true);
    try {
      const st = await api('/api/auth/status');
      if (!st.authed) return showAuth(st.pinSet);
      start();
    } catch (err) {
      document.body.classList.remove('locked');
      toast(err.message, 'error');
    }
  }

  async function start() {
    if (S.started) return;
    S.started = true;
    S.seqReady = false;
    document.body.classList.remove('locked');
    await migrateLegacy();
    await refreshState().catch(err => toast(err.message, 'error'));
    schedulePoll();
    if (S.view === 'history') loadHistory();
    if (S.view === 'settings') loadSettings();
    triggerScan(true);
  }

  // Eski sürümde tarayıcıya (localStorage) kaydedilen cihazları sunucuya taşı
  async function migrateLegacy() {
    let legacy = [];
    try {
      if (localStorage.getItem('wol_migrated_v2')) return;
      legacy = JSON.parse(localStorage.getItem('wol_pinned_devices') || '[]');
    } catch (e) {
      return;
    }
    try {
      if (Array.isArray(legacy) && legacy.length) {
        const devices = legacy.map(d => ({
          mac: d.mac,
          name: d.name,
          ip: /^\d+\.\d+\.\d+\.\d+$/.test(d.ip || '') ? d.ip : ''
        }));
        const r = await api('/api/devices/import', { mode: 'merge', devices });
        if (r.added) toast(r.added + ' kayıtlı cihaz sunucuya aktarıldı.');
      }
      try { localStorage.setItem('wol_migrated_v2', '1'); } catch (e) { /* yok say */ }
    } catch (err) {
      console.warn('Eski kayıtlar aktarılamadı:', err);
    }
  }

  // ---------- Görünümler ----------
  function setView(v, initial) {
    if (!VIEWS[v]) v = 'devices';
    S.view = v;
    closeMenu();
    $$('[data-nav]').forEach(b => {
      const on = b.dataset.nav === v;
      b.classList.toggle('active', on);
      if (on) b.setAttribute('aria-current', 'page');
      else b.removeAttribute('aria-current');
    });
    $$('.view').forEach(sec => sec.classList.toggle('hidden', sec.id !== 'view-' + v));
    $('#viewTitle').textContent = VIEWS[v].title;
    document.title = VIEWS[v].title + ' · WoL & Ağ Rölesi';
    if (location.hash !== '#' + v) history.replaceState(null, '', '#' + v);
    renderToolbar();
    if (initial) return;
    if (v === 'history') loadHistory();
    if (v === 'settings') loadSettings();
    renderAll();
  }

  window.addEventListener('hashchange', () => {
    const v = location.hash.slice(1);
    if (v !== S.view) setView(v);
  });

  function renderToolbar() {
    const v = S.view;
    $('#searchBox').classList.toggle('hidden', v !== 'devices' && v !== 'network');
    const scan = '<button type="button" class="btn btn-ghost' + (S.scanning ? ' spinning' : '') + '" data-action="scan"' + (S.scanning ? ' disabled' : '') + '>' + ic('scan') + (S.scanning ? 'Taranıyor' : 'Ağı tara') + '</button>';
    const html = {
      devices: scan + '<button type="button" class="btn btn-primary" data-action="add">' + ic('plus') + 'Cihaz ekle</button>',
      network: scan,
      history: '<button type="button" class="btn btn-ghost" data-action="clear-history">Geçmişi temizle</button>',
      settings: ''
    };
    $('#actions').innerHTML = html[v];
    $('#toolbar').classList.toggle('hidden', v === 'settings');
  }

  // ---------- Durum yenileme ----------
  async function refreshState() {
    const d = await api('/api/state?since=' + S.seq);
    S.devices = d.devices;
    S.status = d.status;
    S.watches = d.watches;
    S.lan = d.lan;
    if (S.seqReady && d.events.length) {
      d.events.forEach(ev => toast(ev.text, ev.type));
      if (S.view === 'history') loadHistory();
    }
    S.seq = d.seq;
    S.seqReady = true;
    renderAll();
  }

  function schedulePoll() {
    clearTimeout(S.pollTimer);
    if (!S.started) return;
    const fast = Object.keys(S.watches).length > 0;
    S.pollTimer = setTimeout(async () => {
      if (!document.hidden) await refreshState().catch(() => {});
      schedulePoll();
    }, fast ? 3000 : 10000);
  }

  document.addEventListener('visibilitychange', () => {
    if (!document.hidden && S.started) refreshState().then(schedulePoll).catch(() => {});
  });

  async function triggerScan(quiet) {
    if (S.scanning) return;
    S.scanning = true;
    renderToolbar();
    renderAll();
    try {
      const data = await api('/api/scan', {});
      S.discovered = data.devices;
      S.lan = data.lan;
      S.scannedOnce = true;
      if (!quiet) toast(data.devices.length + ' cihaz bulundu.');
      await refreshState();
    } catch (err) {
      toast('Tarama hatası: ' + err.message, 'error');
    } finally {
      S.scanning = false;
      renderToolbar();
      renderAll();
    }
  }

  // ---------- Çizim ----------
  function filterQuery() {
    return $('#filterInput').value.trim().toLowerCase();
  }

  function matches(q, vals) {
    return !q || vals.some(v => String(v || '').toLowerCase().includes(q));
  }

  // Renkli durum yok: lavanta vurgu + opaklık
  function statusInfo(dev) {
    const w = S.watches[dev.id];
    if (w) return { cls: 'busy', text: WATCH_TEXT[w.kind] || 'Bekleniyor…' };
    const st = S.status[dev.id];
    if (!st) return { cls: 'idle', text: dev.ip ? 'Kontrol ediliyor' : 'IP bilinmiyor' };
    switch (st.state) {
      case 'online': return { cls: 'on', text: 'Açık' };
      case 'arp': return { cls: 'dim', text: 'Ağda', title: 'Ping yanıtı yok ama ağda görünüyor (güvenlik duvarı ping\'i engelliyor olabilir ya da uyku modunda).' };
      case 'offline': return { cls: 'off', text: st.conflict ? 'IP başka cihazda' : 'Kapalı' };
      default: return { cls: 'idle', text: 'IP bilinmiyor' };
    }
  }

  function isUp(id) {
    const st = S.status[id];
    return !!st && (st.state === 'online' || st.state === 'arp');
  }

  function renderAll() {
    renderLead();
    if (S.view === 'devices') renderDevices();
    else if (S.view === 'network') renderNetwork();
  }

  function renderLead() {
    const on = S.devices.filter(d => isUp(d.id)).length;
    const lead = {
      devices: S.devices.length ? S.devices.length + ' kayıtlı cihaz, ' + on + ' tanesi açık.' : VIEWS.devices.lead,
      network: S.scanning && !S.scannedOnce ? 'Ağ taranıyor…' : (S.lan ? S.lan.subnetPrefix + '.0/24 ağında ' : '') + S.discovered.length + ' cihaz görünüyor.',
      history: VIEWS.history.lead,
      settings: VIEWS.settings.lead
    };
    $('#viewLead').textContent = lead[S.view];
  }

  function badge(st) {
    return '<span class="badge s-' + st.cls + '" title="' + esc(st.title || '') + '"><i></i>' + esc(st.text) + '</span>';
  }

  function renderDevices() {
    const box = $('#deviceGrid');
    if (!S.devices.length) {
      box.innerHTML = `
        <div class="empty">
          <h3>Henüz kayıtlı cihaz yok</h3>
          <p>Ağda bulunan bir cihazı kaydet ya da MAC adresiyle elle ekle.</p>
          <div class="empty-actions">
            <button type="button" class="btn btn-ghost" data-nav="network">Ağı görüntüle</button>
            <button type="button" class="btn btn-primary" data-action="add">${ic('plus')}Cihaz ekle</button>
          </div>
        </div>`;
      return;
    }
    const q = filterQuery();
    const list = S.devices.filter(d => matches(q, [d.name, d.ip, d.mac, d.note]));
    if (!list.length) {
      box.innerHTML = '<div class="empty"><p>“' + esc(q) + '” ile eşleşen cihaz yok.</p></div>';
      return;
    }
    box.innerHTML = list.map(d => {
      const st = statusInfo(d);
      return `
        <article class="card device" data-id="${esc(d.id)}">
          <div class="device-top">
            ${badge(st)}
            <button type="button" class="icon-btn" data-action="menu" aria-label="Diğer işlemler" aria-haspopup="menu">${ic('more')}</button>
          </div>
          <button type="button" class="device-name" data-action="edit" title="Düzenle">${esc(d.name)}</button>
          <p class="device-meta"><span class="mono">${esc(d.ip || 'IP yok')}</span><span class="sep">·</span><span class="mono">${esc(d.mac)}</span></p>
          ${d.note ? `<p class="device-note">${esc(d.note)}</p>` : ''}
          <div class="device-actions">
            <button type="button" class="btn btn-primary" data-action="wake">${ic('bolt')}Uyandır</button>
          </div>
        </article>`;
    }).join('');
  }

  function renderNetwork() {
    const box = $('#discList');
    const q = filterQuery();
    const savedByMac = new Map(S.devices.map(d => [d.mac, d]));
    const list = S.discovered.filter(d => {
      const saved = savedByMac.get(d.mac);
      return matches(q, [saved ? saved.name : '', d.hostname, d.ip, d.mac]);
    });
    if (!list.length) {
      const msg = S.scanning ? 'Ağ taranıyor…' : !S.scannedOnce ? 'Cihazları görmek için ağı tara.' : S.discovered.length ? 'Sonuç yok.' : 'Cihaz bulunamadı.';
      box.innerHTML = '<p class="list-empty">' + esc(msg) + '</p>';
      return;
    }
    box.innerHTML = list.map(d => {
      const saved = savedByMac.get(d.mac);
      const name = saved ? saved.name : (d.hostname || d.ip);
      const on = d.state.includes('REACHABLE');
      return `
        <div class="row">
          <span class="dot ${on ? 's-on' : 's-off'}" title="${on ? 'Yanıt veriyor' : esc(d.state)}"></span>
          <div class="row-main">
            <span class="row-title">${esc(name)}</span>
            <span class="row-sub mono">${esc(d.ip)} · ${esc(d.mac)}</span>
          </div>
          <div class="row-actions">
            ${saved
              ? '<span class="tag">Kayıtlı</span>'
              : `<button type="button" class="link" data-action="save-discovered" data-mac="${esc(d.mac)}" data-ip="${esc(d.ip)}" data-name="${esc(d.hostname || '')}">Kaydet</button>`}
            <button type="button" class="btn btn-secondary" data-action="wake-mac" data-mac="${esc(d.mac)}" data-name="${esc(name)}">Uyandır</button>
          </div>
        </div>`;
    }).join('');
  }

  // ---------- Geçmiş ----------
  async function loadHistory() {
    try {
      const r = await api('/api/history');
      S.history = r.history;
    } catch (err) {
      if (!S.history) {
        $('#historyBox').innerHTML = '<div class="card"><p class="list-empty">' + esc(err.message) + '</p></div>';
        return;
      }
    }
    renderHistory();
  }

  function renderHistory() {
    const list = S.history || [];
    if (!list.length) {
      $('#historyBox').innerHTML = '<div class="empty"><h3>Henüz kayıt yok</h3><p>Uyandırdığın ve kapattığın cihazlar burada listelenir.</p></div>';
      return;
    }
    const groups = [];
    list.forEach(h => {
      const label = dayLabel(h.ts);
      let g = groups[groups.length - 1];
      if (!g || g.label !== label) {
        g = { label, items: [] };
        groups.push(g);
      }
      g.items.push(h);
    });
    $('#historyBox').innerHTML = groups.map(g =>
      '<section class="card list-card"><h3 class="card-title">' + esc(g.label) + '</h3>' + g.items.map(h =>
        '<div class="row"><span class="dot ' + (h.type === 'fail' || h.type === 'timeout' ? 's-off' : 's-on') + '"></span>' +
        '<div class="row-main"><span class="row-text">' + esc(h.text) + '</span></div>' +
        '<span class="row-time mono">' + esc(timeOf(h.ts)) + '</span></div>'
      ).join('') + '</section>'
    ).join('');
  }

  // ---------- Ayarlar ----------
  let importMode = 'merge';

  async function loadSettings() {
    try {
      S.settings = await api('/api/settings');
      renderSettings();
    } catch (err) {
      $('#settingsBox').innerHTML = '<div class="card"><p class="list-empty">' + esc(err.message) + '</p></div>';
    }
  }

  function renderSettings() {
    const st = S.settings;
    if (!st) return;
    const code = text => '<div class="code"><code>' + esc(text) + '</code><button type="button" class="icon-btn" data-copy="' + esc(text) + '" aria-label="Kopyala" title="Kopyala">' + ic('copy') + '</button></div>';
    const linkRow = (attr, title, sub) => '<button type="button" class="row row-link" ' + attr + '><div class="row-main"><span class="row-title">' + title + '</span>' + (sub ? '<span class="row-sub">' + sub + '</span>' : '') + '</div><span class="chev">' + ic('chev') + '</span></button>';

    $('#settingsBox').innerHTML = `
      <section class="card list-card">
        <h3 class="card-title">Güvenlik</h3>
        ${linkRow('data-set="change-pin"', 'PIN\'i değiştir')}
        ${linkRow('data-set="logout-others"' + (st.sessions < 2 ? ' disabled' : ''), 'Diğer cihazlardan çıkış yap', esc(st.sessions) + ' açık oturum')}
        ${linkRow('data-set="logout"', 'Çıkış yap')}
      </section>

      <section class="card">
        <h3 class="card-title">Windows ajanı</h3>
        <p class="card-text">Uzaktan kapatmak istediğin her Windows bilgisayarda PowerShell'i yönetici olarak aç ve bu komutu çalıştır. Komut, betiğin özetini doğrulamadan hiçbir şey çalıştırmaz. Ajan yalnızca bu panelin imzaladığı ve kendi MAC adresine yönelik komutları uygular.</p>
        ${code(st.agent.install)}
        <p class="hint">Betik özeti (SHA-256): <span class="mono">${esc(st.agent.sha256)}</span><br>En güvenlisi bu sayfayı Tailscale adresinden açıp komutu oradan kopyalamak.</p>
        <div class="card-links">
          <button type="button" class="link" data-copy="${esc(st.agent.uninstall)}">Kaldırma komutunu kopyala ${ic('chev')}</button>
          <button type="button" class="link" data-set="agent-token">Ajan anahtarını yenile ${ic('chev')}</button>
        </div>
      </section>

      <section class="card">
        <h3 class="card-title">SSH (Linux)</h3>
        ${st.sshSetup
          ? `<p class="card-text">Kapatmak istediğin Linux makinede, panelde SSH kullanıcısı olarak gireceğin hesapla bu komutu çalıştır. Anahtar yalnızca yerel ağdan ve yalnızca kapatma / yeniden başlatma için kullanılabilir; kabuk erişimi vermez.</p>
             ${code(st.sshSetup)}
             <p class="hint">Hesap root değilse ayrıca: <span class="mono">echo "KULLANICI ALL=(root) NOPASSWD: /usr/bin/systemctl poweroff, /usr/bin/systemctl reboot" | sudo tee /etc/sudoers.d/wol</span></p>`
          : '<p class="card-text">Linux makineleri kapatmak için önce bir SSH anahtarı oluştur.</p><div class="card-links"><button type="button" class="link" data-set="ssh-key">SSH anahtarı oluştur ' + ic('chev') + '</button></div>'}
      </section>

      <section class="card list-card">
        <h3 class="card-title">Yedekleme</h3>
        <a class="row row-link" href="/api/export" download><div class="row-main"><span class="row-title">Dışa aktar</span><span class="row-sub">Cihazlar, notlar ve zamanlamalar (JSON)</span></div><span class="chev">${ic('chev')}</span></a>
        ${linkRow('data-set="import-merge"', 'İçe aktar', 'Mevcut listeye ekler')}
        ${linkRow('data-set="import-replace"', 'İçe aktar ve değiştir', 'Mevcut listenin yerine geçer')}
      </section>

      <p class="about mono">${esc(st.lan.name)} · ${esc(st.lan.ip)} · sürüm ${esc(st.version || '')}</p>`;
  }

  $('#settingsBox').addEventListener('click', async e => {
    const copy = e.target.closest('[data-copy]');
    if (copy) {
      toast(await copyText(copy.dataset.copy) ? 'Kopyalandı.' : 'Kopyalanamadı; metni elle seç.');
      return;
    }
    const btn = e.target.closest('[data-set]');
    if (!btn) return;
    try {
      switch (btn.dataset.set) {
        case 'change-pin':
          openPinSheet();
          break;
        case 'logout-others': {
          if (!await confirmAction('Diğer cihazlardan çıkış yapılsın mı?', 'Bu cihaz dışındaki oturumlar kapanır.', 'Çıkış yap')) return;
          const r = await api('/api/auth/logout-others', {});
          toast(r.closed + ' oturum kapatıldı.');
          loadSettings();
          break;
        }
        case 'logout':
          await api('/api/auth/logout', {});
          showAuth(true);
          break;
        case 'agent-token':
          if (!await confirmAction('Ajan anahtarı yenilensin mi?', 'Kurulu ajanlar yeni komutla yeniden kurulana kadar çalışmaz.', 'Yenile')) return;
          await api('/api/settings/agent-token', {});
          toast('Ajan anahtarı yenilendi.');
          loadSettings();
          break;
        case 'ssh-key':
          btn.disabled = true;
          await api('/api/settings/ssh-key', {});
          loadSettings();
          break;
        case 'import-merge':
        case 'import-replace':
          importMode = btn.dataset.set === 'import-replace' ? 'replace' : 'merge';
          $('#importFile').click();
          break;
      }
    } catch (err) {
      toast(err.message, 'error');
      btn.disabled = false;
    }
  });

  $('#importFile').addEventListener('change', async e => {
    const file = e.target.files[0];
    if (!file) return;
    try {
      const json = JSON.parse(await file.text());
      const devices = Array.isArray(json) ? json : json.devices;
      if (!Array.isArray(devices)) throw new Error('Dosyada cihaz listesi bulunamadı.');
      if (importMode === 'replace' && !await confirmAction('Liste değiştirilsin mi?', 'Mevcut ' + S.devices.length + ' kayıt silinip dosyadaki ' + devices.length + ' cihaz yüklenecek.', 'Değiştir')) return;
      const r = await api('/api/devices/import', { mode: importMode, devices });
      toast(r.added + ' eklendi, ' + r.skipped + ' atlandı.');
      await refreshState();
    } catch (err) {
      toast(err.message, 'error');
    } finally {
      e.target.value = '';
    }
  });

  function openPinSheet() {
    openSheet({
      title: 'PIN\'i değiştir',
      okText: 'Değiştir',
      autofocus: true,
      body: `
        <div class="form-grid">
          <label class="field full"><span>Mevcut PIN</span><input class="input" type="password" name="current" autocomplete="current-password"></label>
          <label class="field"><span>Yeni PIN</span><input class="input" type="password" name="pin" autocomplete="new-password"></label>
          <label class="field"><span>Yeni PIN (tekrar)</span><input class="input" type="password" name="pin2" autocomplete="new-password"></label>
        </div>
        <p class="hint">En az 4 karakter.</p>`,
      onOk: async sheet => {
        const v = n => $('[name="' + n + '"]', sheet).value;
        if (v('pin') !== v('pin2')) return toast('Yeni PIN\'ler eşleşmiyor.', 'error');
        try {
          await api('/api/auth/change-pin', { current: v('current'), pin: v('pin') });
          closeSheet();
          toast('PIN değiştirildi.');
        } catch (err) {
          toast(err.message, 'error');
        }
      }
    });
  }

  // ---------- Cihaz işlemleri ----------
  document.addEventListener('click', e => {
    const nav = e.target.closest('[data-nav]');
    if (nav) {
      e.preventDefault();
      setView(nav.dataset.nav);
      return;
    }
    const btn = e.target.closest('[data-action]');
    if (!btn) return;
    const card = btn.closest('[data-id]');
    const dev = card ? S.devices.find(d => d.id === card.dataset.id) : null;
    switch (btn.dataset.action) {
      case 'wake': if (dev) wakeSaved(dev, btn); break;
      case 'edit': if (dev) openEditor(dev); break;
      case 'menu':
        if (!dev) break;
        if (!$('#menu').classList.contains('hidden')) closeMenu();
        else deviceMenu(dev, btn);
        break;
      case 'add': openEditor(null); break;
      case 'scan': triggerScan(); break;
      case 'clear-history': clearHistory(); break;
      case 'wake-mac': wakeMac(btn.dataset.mac, btn.dataset.name, btn); break;
      case 'save-discovered': openEditor(null, { mac: btn.dataset.mac, ip: btn.dataset.ip, name: btn.dataset.name }); break;
    }
  });

  function deviceMenu(dev, anchor) {
    const idx = S.devices.indexOf(dev);
    const groups = [];
    if (dev.power.method !== 'none') {
      const power = [
        { label: 'Kapat', run: () => powerAction(dev, 'shutdown') },
        { label: 'Yeniden başlat', run: () => powerAction(dev, 'restart') }
      ];
      if (dev.power.method === 'agent') power.push({ label: 'Uyut', run: () => powerAction(dev, 'sleep') });
      groups.push(power);
    }
    groups.push([
      { label: 'Düzenle', run: () => openEditor(dev) },
      { label: 'Yukarı taşı', disabled: idx <= 0, run: () => moveDevice(dev, -1) },
      { label: 'Aşağı taşı', disabled: idx >= S.devices.length - 1, run: () => moveDevice(dev, 1) }
    ]);
    groups.push([{ label: 'Sil', run: () => deleteDevice(dev) }]);
    openMenu(anchor, groups);
  }

  async function wakeSaved(dev, btn) {
    if (btn) btn.disabled = true;
    try {
      const r = await api('/api/wake', { id: dev.id });
      toast(r.alreadyOn ? dev.name + ' zaten açık.' : dev.name + ' uyandırılıyor…');
      await refreshState();
      schedulePoll();
    } catch (err) {
      toast(err.message, 'error');
    } finally {
      if (btn) btn.disabled = false;
    }
  }

  async function wakeMac(mac, name, btn) {
    if (btn) btn.disabled = true;
    try {
      await api('/api/wake', { mac, name });
      toast((name || mac) + ' için paket gönderildi.');
      await refreshState();
      schedulePoll();
    } catch (err) {
      toast(err.message, 'error');
    } finally {
      if (btn) btn.disabled = false;
    }
  }

  async function powerAction(dev, action) {
    const meta = {
      shutdown: ['kapatılsın mı?', 'Kapat'],
      restart: ['yeniden başlatılsın mı?', 'Yeniden başlat'],
      sleep: ['uyutulsun mu?', 'Uyut']
    }[action];
    if (!await confirmAction(dev.name + ' ' + meta[0], 'Kaydedilmemiş işler kaybolabilir.', meta[1])) return;
    try {
      await api('/api/power', { id: dev.id, action });
      toast(dev.name + ': komut gönderildi.');
      await refreshState();
      schedulePoll();
    } catch (err) {
      toast(err.message, 'error');
    }
  }

  async function deleteDevice(dev) {
    if (!await confirmAction(dev.name + ' silinsin mi?', 'Zamanlamaları da silinir.', 'Sil')) return false;
    try {
      await api('/api/devices/delete', { id: dev.id });
      toast(dev.name + ' silindi.');
      await refreshState();
      return true;
    } catch (err) {
      toast(err.message, 'error');
      return false;
    }
  }

  async function moveDevice(dev, delta) {
    const list = S.devices.slice();
    const i = list.indexOf(dev);
    const j = i + delta;
    if (i < 0 || j < 0 || j >= list.length) return;
    [list[i], list[j]] = [list[j], list[i]];
    S.devices = list;
    renderAll();
    try {
      await api('/api/devices/reorder', { ids: list.map(d => d.id) });
    } catch (err) {
      toast(err.message, 'error');
      await refreshState().catch(() => {});
    }
  }

  async function clearHistory() {
    if (!await confirmAction('Geçmiş temizlensin mi?', 'Tüm kayıtlar silinir.', 'Temizle')) return;
    try {
      await api('/api/history/clear', {});
      S.history = [];
      renderHistory();
    } catch (err) {
      toast(err.message, 'error');
    }
  }

  $('#filterInput').addEventListener('input', renderAll);

  $('#quickForm').addEventListener('submit', e => {
    e.preventDefault();
    const mac = $('#manualMac').value.trim();
    if (!mac) return toast('MAC adresi gir.', 'error');
    wakeMac(mac, mac);
  });

  // ---------- Cihaz düzenleme ----------
  function schedRowHtml(s) {
    const tz = s.tz || BROWSER_TZ;
    return `
      <div class="srow" data-sid="${esc(s.id || '')}" data-tz="${esc(tz)}">
        <div class="days">${DAY_ORDER.map(i => `<button type="button" class="day${s.days.includes(i) ? ' on' : ''}" data-day="${i}" aria-pressed="${s.days.includes(i)}">${DAY_NAMES[i]}</button>`).join('')}</div>
        <input class="input time" type="time" value="${esc(s.time)}" aria-label="Saat">
        <label class="switch" title="Etkin"><input type="checkbox"${s.enabled !== false ? ' checked' : ''} aria-label="Etkin"><span></span></label>
        <button type="button" class="icon-btn" data-act="del-sched" aria-label="Zamanlamayı sil">${ic('x')}</button>
      </div>`;
  }

  function openEditor(dev, preset) {
    const d = dev || Object.assign({ name: '', mac: '', ip: '', note: '', power: { method: 'none', user: '', port: 22 }, schedules: [] }, preset || {});
    const power = d.power || { method: 'none', user: '', port: 22 };
    const body = `
      <form id="devForm" autocomplete="off" novalidate>
        <div class="form-grid">
          <label class="field full"><span>İsim</span><input class="input" name="name" maxlength="60" value="${esc(d.name)}" placeholder="Salon PC"></label>
          <label class="field"><span>MAC adresi</span><input class="input mono upper" name="mac" maxlength="17" value="${esc(d.mac)}" placeholder="AA:BB:CC:DD:EE:FF"></label>
          <label class="field"><span>IP adresi</span><input class="input mono" name="ip" maxlength="15" value="${esc(d.ip)}" placeholder="Otomatik"></label>
          <label class="field full"><span>Not</span><input class="input" name="note" maxlength="500" value="${esc(d.note)}" placeholder="İsteğe bağlı"></label>
        </div>

        <div class="aurora"></div>
        <h3 class="form-title">Uzaktan kapatma</h3>
        <div class="form-grid">
          <label class="field full"><span>Yöntem</span><select class="input" name="method">${Object.keys(POWER_LABEL).map(m => `<option value="${m}"${power.method === m ? ' selected' : ''}>${esc(POWER_LABEL[m])}</option>`).join('')}</select></label>
          <label class="field ssh-only"><span>SSH kullanıcı</span><input class="input mono" name="user" maxlength="32" value="${esc(power.user || '')}" placeholder="kullanici"></label>
          <label class="field ssh-only"><span>SSH port</span><input class="input mono" name="sshport" type="number" min="1" max="65535" value="${esc(power.port || 22)}"></label>
        </div>
        <p class="hint" id="methodHint"></p>
        <div class="test-row">
          <button type="button" class="link" data-act="test">Bağlantıyı test et ${ic('chev')}</button>
          <span class="hint" id="testResult"></span>
        </div>

        <div class="aurora"></div>
        <h3 class="form-title">Zamanlanmış uyandırma</h3>
        <div id="schedList">${(d.schedules || []).map(schedRowHtml).join('')}</div>
        <button type="button" class="link" data-act="add-sched">${ic('plus')} Zamanlama ekle</button>
        <p class="hint">Saatler ${esc(BROWSER_TZ)} saat dilimine göredir. Paketi sunucu gönderir; panelin açık olması gerekmez.</p>
      </form>`;

    const sheet = openSheet({
      title: dev ? 'Cihazı düzenle' : 'Yeni cihaz',
      okText: 'Kaydet',
      autofocus: !dev,
      body,
      footLeft: dev ? '<button type="button" class="btn btn-ghost" data-act="delete">Sil</button>' : '',
      onOk: save
    });
    const form = $('#devForm', sheet);
    const field = n => form.elements.namedItem(n);

    const syncMethod = () => {
      const m = field('method').value;
      $$('.ssh-only', form).forEach(el => el.classList.toggle('hidden', !m.startsWith('ssh')));
      $('.test-row', form).classList.toggle('hidden', m === 'none');
      $('#methodHint', form).textContent = METHOD_HINT[m];
      $('#testResult', form).textContent = '';
    };
    field('method').addEventListener('change', syncMethod);
    syncMethod();

    const collect = () => ({
      name: field('name').value.trim(),
      mac: field('mac').value.trim(),
      ip: field('ip').value.trim(),
      note: field('note').value,
      power: { method: field('method').value, user: field('user').value.trim(), port: Number(field('sshport').value) || 22 },
      schedules: $$('.srow', form).map(r => ({
        id: r.dataset.sid || undefined,
        tz: r.dataset.tz,
        time: $('input[type=time]', r).value,
        enabled: $('input[type=checkbox]', r).checked,
        days: $$('.day.on', r).map(b => Number(b.dataset.day))
      }))
    });

    async function save() {
      const data = collect();
      if (!data.mac) return toast('MAC adresi gerekli.', 'error');
      if (data.schedules.some(s => !s.days.length || !s.time)) return toast('Her zamanlama için gün ve saat seç.', 'error');
      try {
        if (dev) await api('/api/devices/update', Object.assign({ id: dev.id }, data));
        else await api('/api/devices/create', data);
        closeSheet();
        toast((data.name || 'Cihaz') + ' kaydedildi.');
        await refreshState();
      } catch (err) {
        toast(err.message, 'error');
      }
    }

    async function testPower(btn) {
      const out = $('#testResult', form);
      out.className = 'hint';
      out.textContent = 'Test ediliyor…';
      btn.disabled = true;
      try {
        const r = await api('/api/power/test', { id: dev ? dev.id : undefined, device: collect() });
        out.className = 'hint ok';
        out.textContent = r.message;
      } catch (err) {
        out.className = 'hint';
        out.textContent = err.message;
      } finally {
        btn.disabled = false;
      }
    }

    sheet.addEventListener('click', async e => {
      const day = e.target.closest('.day');
      if (day) {
        day.classList.toggle('on');
        day.setAttribute('aria-pressed', String(day.classList.contains('on')));
        return;
      }
      const act = e.target.closest('[data-act]');
      if (!act) return;
      switch (act.dataset.act) {
        case 'add-sched':
          $('#schedList', form).insertAdjacentHTML('beforeend', schedRowHtml({ days: [1, 2, 3, 4, 5], time: '08:00', enabled: true, tz: BROWSER_TZ }));
          break;
        case 'del-sched':
          act.closest('.srow').remove();
          break;
        case 'test':
          testPower(act);
          break;
        case 'delete':
          if (await deleteDevice(dev)) closeSheet();
          break;
      }
    });
  }

  document.addEventListener('keydown', e => {
    if (e.key !== 'Escape') return;
    if (!$('#menu').classList.contains('hidden')) closeMenu();
    else if (!$('#sheetRoot').classList.contains('hidden')) closeSheet();
  });

  boot();
}

const DASHBOARD_HTML = `<!DOCTYPE html>
<html lang="tr">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0, viewport-fit=cover">
  <meta name="color-scheme" content="dark">
  <meta name="theme-color" content="#030014">
  <meta name="apple-mobile-web-app-capable" content="yes">
  <meta name="apple-mobile-web-app-title" content="WoL Rölesi">
  <title>WoL & Ağ Rölesi</title>
  <!-- Gömülü SVG Favicon -->
  <link rel="icon" type="image/svg+xml" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 32 32'><rect width='32' height='32' rx='5' fill='%2310093a'/><path d='M16 8v8' stroke='%239382ff' stroke-width='2' stroke-linecap='round'/><path d='M10.7 10.7a7.5 7.5 0 1 0 10.6 0' fill='none' stroke='%23f4f0ff' stroke-width='2' stroke-linecap='round'/></svg>">
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=DM+Sans:opsz,wght@9..40,500&family=Inter:wght@400;500&display=swap">
  <style>
    :root {
      color-scheme: dark;
      /* Renkler */
      --void: #030014;
      --midnight: #060317;
      --indigo: #10093a;
      --lilac: #f4f0ff;
      --pearl: #ffffff;
      --ash: #a8a6b7;
      --fog: #918ea0;
      --steel: #54525f;
      --dusk: #72707b;
      --accent: #9382ff;
      --iris: #5046e4;
      --cosmic: linear-gradient(90.01deg, #e59cff 0.01%, #ba9cff 50.01%, #9cb2ff 100%);
      --aurora: linear-gradient(90deg, rgba(183, 164, 251, 0) 0%, #b7a4fb 50%, #8562ff 80%, rgba(133, 98, 255, 0) 100%);
      --line: rgba(244, 240, 255, 0.06);
      /* Yazı */
      --font-display: "AeonikPro", "Aeonik", "DM Sans", "Inter", system-ui, sans-serif;
      --font-body: "Inter V", "Inter", "Geist", system-ui, sans-serif;
      --mono: ui-monospace, "SF Mono", SFMono-Regular, Menlo, Consolas, monospace;
      /* Köşe */
      --r-control: 5px;
      --r-card: 16px;
      --r-badge: 32px;
      --r-nav: 999px;
      /* Yükselti: dış gölge yok, yalnızca iç parıltı */
      --glow: inset 0 0 24px rgba(255, 255, 255, 0.04);
      --glow-2: inset 0 0 24px rgba(255, 255, 255, 0.06);
      --glow-violet: inset 0 -7px 11px rgba(164, 143, 255, 0.12);
    }

    * { box-sizing: border-box; margin: 0; padding: 0; }
    html { -webkit-text-size-adjust: 100%; }
    body {
      font-family: var(--font-body);
      font-feature-settings: "calt" 0, "cv10", "liga" 0, "ss01";
      font-size: 16px;
      line-height: 1.5;
      font-weight: 400;
      color: var(--lilac);
      background: var(--void);
      min-height: 100vh;
      -webkit-font-smoothing: antialiased;
    }
    h1, h2, h3, b, strong, th { font-weight: 500; }
    button, input, select { font: inherit; color: inherit; }
    button { -webkit-tap-highlight-color: transparent; }
    a { color: inherit; text-decoration: none; }
    .hidden { display: none !important; }
    .mono { font-family: var(--mono); font-size: 0.875em; }
    .upper { text-transform: uppercase; }
    .ic { width: 18px; height: 18px; flex-shrink: 0; }
    body.locked .page { visibility: hidden; }
    body.modal-open { overflow: hidden; }
    :focus-visible { outline: 1px solid var(--accent); outline-offset: 2px; }

    /* Yıldız alanı */
    .stars {
      position: fixed;
      inset: 0;
      z-index: -1;
      pointer-events: none;
      opacity: 0.55;
      background-image:
        radial-gradient(1px 1px at 12% 18%, rgba(244, 240, 255, 0.7), transparent 60%),
        radial-gradient(1px 1px at 78% 12%, rgba(244, 240, 255, 0.55), transparent 60%),
        radial-gradient(1.5px 1.5px at 34% 64%, rgba(244, 240, 255, 0.5), transparent 60%),
        radial-gradient(1px 1px at 88% 72%, rgba(244, 240, 255, 0.6), transparent 60%),
        radial-gradient(1px 1px at 56% 38%, rgba(244, 240, 255, 0.35), transparent 60%),
        radial-gradient(1.5px 1.5px at 22% 86%, rgba(244, 240, 255, 0.45), transparent 60%),
        radial-gradient(1px 1px at 66% 90%, rgba(244, 240, 255, 0.4), transparent 60%),
        radial-gradient(1px 1px at 92% 42%, rgba(244, 240, 255, 0.5), transparent 60%);
      background-size: 420px 420px, 380px 380px, 520px 520px, 460px 460px, 300px 300px, 560px 560px, 340px 340px, 480px 480px;
    }

    .page { max-width: 1200px; margin: 0 auto; padding: 24px 24px 96px; }

    /* Yüzen gezinme hapı */
    .nav-pill {
      display: flex;
      align-items: center;
      gap: 8px;
      width: fit-content;
      max-width: 100%;
      margin: 0 auto;
      padding: 4px 4px 4px 16px;
      min-height: 40px;
      border-radius: var(--r-nav);
      background: var(--midnight);
      box-shadow: var(--glow);
    }
    .brand { display: flex; align-items: center; gap: 8px; font-size: 15px; font-weight: 500; white-space: nowrap; margin-right: 8px; }
    .brand .ic { color: var(--accent); width: 18px; height: 18px; }
    .grad { background: var(--cosmic); -webkit-background-clip: text; background-clip: text; -webkit-text-fill-color: transparent; }
    .nav-links { display: flex; align-items: center; gap: 4px; }
    .nav-links button {
      height: 32px;
      padding: 0 12px;
      border: 0;
      border-radius: var(--r-control);
      background: transparent;
      font-size: 15px;
      color: var(--fog);
      cursor: pointer;
      transition: color 0.2s;
    }
    .nav-links button:hover { color: var(--lilac); }
    .nav-links button.active { color: var(--lilac); }
    .nav-links button.active::after { content: ''; display: block; height: 1px; margin-top: 2px; background: var(--cosmic); }

    /* Bölüm başlığı */
    .hero { text-align: center; padding: 72px 0 32px; }
    .display { font-family: var(--font-display); font-weight: 500; font-size: 56px; line-height: 1.14; letter-spacing: -0.4px; }
    .lead { font-size: 18px; line-height: 1.56; color: var(--fog); margin-top: 12px; min-height: 28px; }

    .toolbar { display: flex; flex-wrap: wrap; align-items: center; justify-content: space-between; gap: 12px; margin-bottom: 24px; }
    .search { display: flex; align-items: center; gap: 8px; height: 40px; padding: 0 12px; border-radius: var(--r-control); background: var(--midnight); box-shadow: var(--glow); width: 320px; max-width: 100%; color: var(--fog); }
    .search input { flex: 1; min-width: 0; border: 0; outline: 0; background: transparent; font-size: 15px; color: var(--lilac); }
    .search input::placeholder { color: var(--steel); }
    .search input::-webkit-search-cancel-button { filter: grayscale(1) brightness(0.8); }
    .actions { display: flex; flex-wrap: wrap; gap: 8px; margin-left: auto; }
    .aurora { height: 1px; background: var(--aurora); opacity: 0.6; margin: 24px 0; }

    /* Düğmeler: 5px köşe, orta ağırlık */
    .btn {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      gap: 8px;
      height: 40px;
      padding: 10px 16px;
      border: 0;
      border-radius: var(--r-control);
      font-size: 15px;
      font-weight: 500;
      line-height: 1;
      cursor: pointer;
      white-space: nowrap;
      transition: color 0.2s, background-color 0.2s, opacity 0.2s;
    }
    .btn:disabled { opacity: 0.5; cursor: default; }
    .btn .ic { width: 16px; height: 16px; }
    .btn-primary { background: var(--indigo); color: var(--lilac); box-shadow: var(--glow-violet), var(--glow); }
    .btn-primary:hover:not(:disabled) { background: #160d4c; }
    .btn-secondary { background: var(--midnight); color: var(--lilac); box-shadow: var(--glow-2); }
    .btn-secondary:hover:not(:disabled) { background: var(--indigo); }
    .btn-ghost { background: transparent; color: var(--fog); }
    .btn-ghost:hover:not(:disabled) { color: var(--lilac); }
    .spinning .ic { animation: spin 1s linear infinite; }
    .icon-btn {
      width: 32px;
      height: 32px;
      border: 0;
      border-radius: var(--r-control);
      background: transparent;
      color: var(--fog);
      display: grid;
      place-items: center;
      cursor: pointer;
      flex-shrink: 0;
      transition: color 0.2s;
    }
    .icon-btn:hover { color: var(--lilac); }
    .link {
      display: inline-flex;
      align-items: center;
      gap: 4px;
      border: 0;
      background: none;
      color: var(--accent);
      font-size: 15px;
      font-weight: 500;
      cursor: pointer;
      border-radius: var(--r-control);
      padding: 4px 0;
      transition: color 0.2s;
    }
    .link:hover { color: var(--lilac); }
    .link:disabled { opacity: 0.5; }
    .link .ic { width: 14px; height: 14px; }

    /* Kartlar: 16px köşe, iç parıltı, dış gölge yok */
    .card { background: var(--midnight); border-radius: var(--r-card); box-shadow: var(--glow); padding: 24px; }
    .card + .card { margin-top: 16px; }
    .grid > .card + .card { margin-top: 0; }
    .card-title { font-family: var(--font-display); font-size: 24px; line-height: 1.33; font-weight: 500; margin-bottom: 8px; }
    .card-text { font-size: 15px; color: var(--ash); }
    .card-links { display: flex; flex-wrap: wrap; gap: 8px 24px; margin-top: 16px; }

    .grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(min(100%, 300px), 1fr)); gap: 16px; }
    .device { display: flex; flex-direction: column; gap: 8px; min-width: 0; }
    .device-top { display: flex; align-items: center; justify-content: space-between; margin-bottom: 8px; }
    .device-top .icon-btn { margin-right: -8px; }
    .device-name {
      border: 0;
      background: none;
      text-align: left;
      cursor: pointer;
      font-family: var(--font-display);
      font-size: 24px;
      line-height: 1.33;
      font-weight: 500;
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
      border-radius: var(--r-control);
    }
    .device-name:hover { color: var(--pearl); }
    .device-meta { font-size: 14px; color: var(--fog); display: flex; flex-wrap: wrap; gap: 4px 8px; }
    .device-meta .sep { color: var(--steel); }
    .device-note { font-size: 14px; color: var(--ash); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
    .device-actions { margin-top: 16px; display: flex; gap: 8px; }
    .device-actions .btn { flex: 1; }

    /* Durum rozeti: renk yerine lavanta + opaklık */
    .badge {
      display: inline-flex;
      align-items: center;
      gap: 8px;
      height: 28px;
      padding: 0 12px;
      border-radius: var(--r-badge);
      background: var(--indigo);
      box-shadow: var(--glow-violet);
      font-size: 13px;
      font-weight: 500;
      color: var(--lilac);
      white-space: nowrap;
    }
    .badge i, .dot { width: 6px; height: 6px; border-radius: 50%; flex-shrink: 0; background: var(--accent); }
    .s-on i, .dot.s-on { background: var(--accent); }
    .s-dim i { background: transparent; box-shadow: inset 0 0 0 1px var(--accent); }
    .s-dim { color: var(--ash); }
    .s-off, .s-idle { background: transparent; box-shadow: inset 0 0 0 1px rgba(244, 240, 255, 0.08); color: var(--fog); }
    .s-off i, .s-idle i, .dot.s-off { background: var(--steel); box-shadow: none; }
    .s-busy i { animation: pulse 1s ease-in-out infinite; }
    .tag { font-size: 13px; color: var(--fog); padding: 0 4px; }

    /* Liste satırları */
    .list-card { padding: 16px 24px; }
    .list-card .card-title { margin: 8px 0 8px; }
    .row {
      display: flex;
      align-items: center;
      gap: 16px;
      min-height: 56px;
      padding: 8px 0;
      width: 100%;
      border: 0;
      background: none;
      text-align: left;
      position: relative;
    }
    .row + .row { border-top: 1px solid var(--line); }
    .row-link { cursor: pointer; }
    .row-link:hover .row-title { color: var(--pearl); }
    .row-link:hover .chev { color: var(--lilac); }
    .row-link:disabled { opacity: 0.5; cursor: default; }
    .row-main { flex: 1; min-width: 0; display: flex; flex-direction: column; }
    .row-title { font-size: 15px; font-weight: 500; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
    .row-sub { font-size: 13px; color: var(--fog); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
    .row-text { font-size: 15px; color: var(--ash); }
    .row-time { font-size: 13px; color: var(--fog); }
    .row-actions { display: flex; align-items: center; gap: 16px; flex-shrink: 0; }
    .row-actions .btn { height: 36px; }
    .chev { color: var(--steel); display: grid; transition: color 0.2s; }
    .chev .ic { width: 16px; height: 16px; }
    .list-empty { color: var(--fog); font-size: 15px; padding: 24px 0; text-align: center; }

    .quick { display: flex; flex-wrap: wrap; gap: 12px; align-items: center; }
    .quick .input { flex: 1 1 240px; }

    .empty { text-align: center; padding: 64px 16px; grid-column: 1 / -1; }
    .empty h3 { font-family: var(--font-display); font-size: 24px; line-height: 1.33; }
    .empty p { color: var(--fog); margin-top: 8px; }
    .empty-actions { display: flex; justify-content: center; flex-wrap: wrap; gap: 8px; margin-top: 24px; }

    .code {
      display: flex;
      align-items: flex-start;
      gap: 8px;
      margin-top: 16px;
      padding: 12px 8px 12px 16px;
      border-radius: var(--r-control);
      background: var(--void);
      box-shadow: var(--glow);
    }
    .code code { flex: 1; font-family: var(--mono); font-size: 12px; line-height: 1.6; color: var(--ash); overflow-wrap: anywhere; user-select: all; }
    .about { text-align: center; color: var(--steel); font-size: 12px; margin-top: 32px; }

    /* Form */
    .input {
      width: 100%;
      height: 40px;
      padding: 0 12px;
      border: 0;
      border-radius: var(--r-control);
      background: var(--void);
      box-shadow: var(--glow-2);
      color: var(--lilac);
      font-size: 15px;
      outline: 0;
    }
    .input:focus { box-shadow: var(--glow-2), inset 0 0 0 1px var(--accent); }
    .input::placeholder { color: var(--steel); text-transform: none; }
    select.input { cursor: pointer; }
    select.input option { background: var(--midnight); color: var(--lilac); }
    .input.mono { font-size: 14px; }
    .form-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; }
    .field { display: flex; flex-direction: column; gap: 8px; font-size: 13px; color: var(--fog); min-width: 0; }
    .field.full { grid-column: 1 / -1; }
    .form-title { font-family: var(--font-display); font-size: 24px; line-height: 1.33; margin-bottom: 16px; }
    .hint { font-size: 13px; color: var(--fog); margin-top: 8px; }
    .hint:empty { display: none; }
    .hint.ok { color: var(--accent); }
    .hint .mono { overflow-wrap: anywhere; }
    .test-row { display: flex; flex-wrap: wrap; align-items: baseline; gap: 4px 16px; margin-top: 8px; }
    .test-row .hint { margin-top: 0; }

    .srow { display: flex; flex-wrap: wrap; align-items: center; gap: 12px; padding: 12px 0; }
    .srow + .srow { border-top: 1px solid var(--line); }
    .days { display: flex; flex-wrap: wrap; gap: 4px; flex: 1 1 260px; }
    .day {
      width: 36px;
      height: 32px;
      border: 0;
      border-radius: var(--r-control);
      background: var(--void);
      box-shadow: var(--glow);
      color: var(--fog);
      font-size: 13px;
      font-weight: 500;
      cursor: pointer;
      transition: color 0.2s, background-color 0.2s;
    }
    .day.on { background: var(--indigo); color: var(--lilac); box-shadow: var(--glow-violet), inset 0 0 0 1px rgba(147, 130, 255, 0.5); }
    .input.time { width: 112px; height: 32px; font-family: var(--mono); font-size: 14px; }
    .switch { position: relative; width: 40px; height: 24px; flex-shrink: 0; }
    .switch input { position: absolute; inset: 0; opacity: 0; margin: 0; cursor: pointer; z-index: 1; }
    .switch span { position: absolute; inset: 0; border-radius: var(--r-control); background: var(--void); box-shadow: var(--glow-2); transition: background-color 0.2s; }
    .switch span::after { content: ''; position: absolute; top: 4px; left: 4px; width: 16px; height: 16px; border-radius: var(--r-control); background: var(--steel); transition: transform 0.2s, background-color 0.2s; }
    .switch input:checked + span { background: var(--indigo); box-shadow: var(--glow-violet); }
    .switch input:checked + span::after { transform: translateX(16px); background: var(--accent); }
    .switch input:focus-visible + span { outline: 1px solid var(--accent); outline-offset: 2px; }

    /* Pencere */
    .overlay {
      position: fixed;
      inset: 0;
      z-index: 100;
      display: flex;
      align-items: flex-start;
      justify-content: center;
      padding: 8vh 16px 24px;
      overflow-y: auto;
      background: rgba(3, 0, 20, 0.78);
      -webkit-backdrop-filter: blur(6px);
      backdrop-filter: blur(6px);
      animation: fadeIn 0.2s;
    }
    .overlay.closing { animation: fadeOut 0.2s forwards; }
    .sheet { width: 100%; max-width: 600px; background: var(--midnight); border-radius: var(--r-card); box-shadow: var(--glow-2); animation: rise 0.25s ease-out; }
    .sheet-head { display: flex; align-items: center; justify-content: space-between; gap: 16px; padding: 24px 24px 0; }
    .sheet-head h2 { font-family: var(--font-display); font-size: 32px; line-height: 1.25; letter-spacing: -0.2px; }
    .sheet-body { padding: 24px; }
    .sheet-foot { display: flex; align-items: center; gap: 8px; padding: 16px 24px 24px; border-top: 1px solid var(--line); }
    .spacer { flex: 1; }

    .alert-root {
      position: fixed;
      inset: 0;
      z-index: 150;
      display: grid;
      place-items: center;
      padding: 16px;
      background: rgba(3, 0, 20, 0.78);
      -webkit-backdrop-filter: blur(6px);
      backdrop-filter: blur(6px);
      animation: fadeIn 0.15s;
    }
    .alert { width: 100%; max-width: 400px; background: var(--midnight); border-radius: var(--r-card); box-shadow: var(--glow-2); padding: 24px; animation: rise 0.2s ease-out; }
    .alert h2 { font-family: var(--font-display); font-size: 24px; line-height: 1.33; overflow-wrap: anywhere; }
    .alert p { font-size: 15px; color: var(--ash); margin-top: 8px; }
    .alert-actions { display: flex; justify-content: flex-end; gap: 8px; margin-top: 24px; }

    .menu { position: fixed; z-index: 120; min-width: 200px; padding: 4px; background: var(--indigo); border-radius: var(--r-card); box-shadow: var(--glow-2); animation: rise 0.15s ease-out; }
    .menu-group + .menu-group { border-top: 1px solid var(--line); margin-top: 4px; padding-top: 4px; }
    .menu-item {
      display: block;
      width: 100%;
      height: 36px;
      padding: 0 12px;
      border: 0;
      border-radius: var(--r-control);
      background: transparent;
      color: var(--lilac);
      font-size: 15px;
      text-align: left;
      cursor: pointer;
    }
    .menu-item:hover:not(:disabled) { background: rgba(244, 240, 255, 0.06); }
    .menu-item:disabled { color: var(--steel); cursor: default; }

    /* Bildirim rozeti */
    #toasts { position: fixed; left: 50%; bottom: max(24px, env(safe-area-inset-bottom)); transform: translateX(-50%); z-index: 300; display: flex; flex-direction: column; align-items: center; gap: 8px; width: calc(100% - 32px); max-width: 480px; pointer-events: none; }
    .toast {
      display: inline-flex;
      align-items: center;
      gap: 8px;
      padding: 8px 16px;
      border-radius: var(--r-badge);
      background: var(--indigo);
      box-shadow: var(--glow-violet), var(--glow);
      font-size: 14px;
      font-weight: 500;
      color: var(--lilac);
      animation: rise 0.25s ease-out;
      transition: opacity 0.3s;
    }
    .toast i { width: 6px; height: 6px; border-radius: 50%; background: var(--accent); flex-shrink: 0; }
    .toast.error i { background: transparent; box-shadow: inset 0 0 0 1px var(--accent); }
    .toast.out { opacity: 0; }

    /* Giriş */
    .lock { position: fixed; inset: 0; z-index: 200; display: flex; align-items: center; justify-content: center; padding: 24px; background: transparent; overflow-y: auto; }
    .lock-box { width: 100%; max-width: 400px; display: flex; flex-direction: column; align-items: center; text-align: center; }
    .lock .badge { margin-bottom: 24px; }
    .lock .badge .ic { width: 14px; height: 14px; color: var(--accent); }
    .lock .display { font-size: 48px; line-height: 1.17; letter-spacing: -0.3px; }
    .lock .lead { margin: 12px 0 32px; }
    .lock .input { height: 44px; margin-bottom: 12px; text-align: center; }
    .lock .btn { width: 100%; height: 44px; }
    .lock-err { min-height: 24px; margin-top: 12px; font-size: 14px; color: var(--accent); }

    @keyframes spin { to { transform: rotate(360deg); } }
    @keyframes pulse { 50% { opacity: 0.3; } }
    @keyframes fadeIn { from { opacity: 0; } }
    @keyframes fadeOut { to { opacity: 0; } }
    @keyframes rise { from { opacity: 0; transform: translateY(8px); } }

    @media (max-width: 720px) {
      .page { padding: 16px 16px 96px; }
      .nav-pill { padding: 4px; }
      .brand { margin: 0 0 0 8px; }
      .brand-text { display: none; }
      .nav-links button { padding: 0 8px; font-size: 14px; }
      .hero { padding: 48px 0 24px; }
      .display { font-size: 32px; line-height: 1.25; letter-spacing: -0.2px; }
      .lead { font-size: 16px; }
      .search { width: 100%; }
      .actions { width: 100%; margin-left: 0; }
      .actions .btn { flex: 1; }
      .card { padding: 20px; }
      .list-card { padding: 12px 20px; }
      .form-grid { grid-template-columns: 1fr; }
      .overlay { align-items: flex-end; padding: 0; }
      .sheet { border-radius: var(--r-card) var(--r-card) 0 0; max-height: 92vh; overflow-y: auto; padding-bottom: env(safe-area-inset-bottom); }
      .sheet-head h2 { font-size: 24px; line-height: 1.33; }
      .row { flex-wrap: wrap; }
      .row-actions { margin-left: 22px; }
      .lock .display { font-size: 32px; }
    }
    @media (prefers-reduced-motion: reduce) {
      *, *::before, *::after { animation-duration: 0.01ms !important; transition-duration: 0.01ms !important; }
    }
  </style>
</head>
<body class="locked">
  <div class="stars" aria-hidden="true"></div>
  ${ICON_SPRITE}

  <div id="lock" class="lock hidden">
    <form id="authForm" class="lock-box">
      <span class="badge"><svg class="ic" aria-hidden="true"><use href="#i-power"/></svg>WoL & Ağ Rölesi</span>
      <h1 class="display">Ağına <span class="grad">hoş geldin</span></h1>
      <p class="lead" id="lockDesc"></p>
      <input type="text" name="username" value="wol-panel" autocomplete="username" hidden>
      <input type="password" class="input" id="authPin" placeholder="PIN" autocomplete="current-password" aria-label="PIN">
      <input type="password" class="input hidden" id="authPin2" placeholder="PIN (tekrar)" autocomplete="new-password" aria-label="PIN tekrar">
      <button type="submit" class="btn btn-primary" id="authGo">Giriş yap</button>
      <div class="lock-err" id="authErr" role="alert"></div>
    </form>
  </div>

  <div class="page">
    <nav class="nav-pill" aria-label="Bölümler">
      <a class="brand" href="#devices" data-nav="devices"><svg class="ic" aria-hidden="true"><use href="#i-power"/></svg><span class="brand-text grad">WoL Rölesi</span></a>
      <div class="nav-links">
        <button type="button" data-nav="devices">Cihazlar</button>
        <button type="button" data-nav="network">Ağ</button>
        <button type="button" data-nav="history">Geçmiş</button>
        <button type="button" data-nav="settings">Ayarlar</button>
      </div>
    </nav>

    <header class="hero">
      <h1 class="display" id="viewTitle">Cihazlar</h1>
      <p class="lead" id="viewLead"></p>
    </header>

    <div class="toolbar" id="toolbar">
      <label class="search" id="searchBox">
        <svg class="ic" aria-hidden="true"><use href="#i-search"/></svg>
        <input id="filterInput" type="search" placeholder="Ara" aria-label="Ara" autocomplete="off">
      </label>
      <div class="actions" id="actions"></div>
    </div>

    <section class="view" id="view-devices">
      <div class="grid" id="deviceGrid"></div>
    </section>

    <section class="view hidden" id="view-network">
      <div class="card">
        <h3 class="card-title">Hızlı uyandırma</h3>
        <p class="card-text">Kayıtlı olmayan bir cihaza MAC adresiyle sihirli paket gönder.</p>
        <form class="quick" id="quickForm" style="margin-top:16px">
          <input class="input mono upper" id="manualMac" placeholder="AA:BB:CC:DD:EE:FF" maxlength="17" aria-label="MAC adresi" autocomplete="off">
          <button type="submit" class="btn btn-primary">Uyandır</button>
        </form>
      </div>
      <section class="card list-card">
        <h3 class="card-title">Ağdaki cihazlar</h3>
        <div id="discList"></div>
      </section>
    </section>

    <section class="view hidden" id="view-history"><div id="historyBox"></div></section>
    <section class="view hidden" id="view-settings"><div id="settingsBox"></div></section>
  </div>

  <div id="sheetRoot" class="overlay hidden"></div>
  <div id="alertRoot" class="alert-root hidden"></div>
  <div id="menu" class="menu hidden" role="menu"></div>
  <div id="toasts" aria-live="polite"></div>
  <input type="file" id="importFile" accept=".json,application/json" hidden>

  <script>(${clientMain.toString()})();</script>
</body>
</html>`;

// --- 9. HTTP API ---
function sendJson(res, status, obj) {
  res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store' });
  res.end(JSON.stringify(obj));
}

function readBody(req, limit = 2e6) {
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks = [];
    req.on('data', chunk => {
      size += chunk.length;
      if (size > limit) {
        reject(new HttpError(413, 'İstek çok büyük.'));
        req.destroy();
      } else {
        chunks.push(chunk);
      }
    });
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    req.on('error', reject);
  });
}

function importDevices(list, mode) {
  if (!Array.isArray(list)) throw new HttpError(400, 'Cihaz listesi bekleniyordu.');
  const next = mode === 'replace' ? [] : db.devices.slice();
  let added = 0;
  let skipped = 0;
  for (const item of list.slice(0, 500)) {
    try {
      // Eski sürümdeki "Manuel/Sabit" gibi IP olmayan değerler boş sayılır
      const input = item && typeof item === 'object' && !isIPv4(item.ip) ? { ...item, ip: '' } : item;
      const dev = sanitizeDevice(input);
      if (next.some(d => d.mac === dev.mac)) { skipped++; continue; }
      next.push(dev);
      added++;
    } catch {
      skipped++;
    }
  }
  db.devices = next;
  saveData();
  if (added) addHistory({ type: 'import', text: `${added} cihaz içe aktarıldı${mode === 'replace' ? ' (liste değiştirildi)' : ''}` });
  pollSoon();
  return { added, skipped };
}

const API = {
  'GET /api/auth/status': {
    public: true,
    fn: ({ session }) => ({ pinSet: !!db.auth.pinHash, authed: !!session })
  },
  'POST /api/auth/setup': {
    public: true,
    fn: ({ req, res, body }) => {
      if (db.auth.pinHash) throw new HttpError(409, 'PIN zaten belirlenmiş. Sayfayı yenileyip giriş yapın.');
      validatePinFormat(body.pin);
      setPin(body.pin);
      createSession(req, res);
      return {};
    }
  },
  'POST /api/auth/login': {
    public: true,
    fn: ({ req, res, body }) => {
      const ip = clientIp(req);
      checkLock(ip);
      if (!db.auth.pinHash) throw new HttpError(409, 'Önce PIN belirlenmeli. Sayfayı yenileyin.');
      if (!verifyPin(body.pin)) {
        registerFail(ip);
        throw new HttpError(403, 'PIN hatalı.');
      }
      loginFails.delete(ip);
      createSession(req, res);
      return {};
    }
  },
  'POST /api/auth/logout': {
    fn: ({ res, session }) => {
      delete db.auth.sessions[session.key];
      saveData();
      res.setHeader('Set-Cookie', `${SESSION_COOKIE}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0`);
      return {};
    }
  },
  'POST /api/auth/logout-others': {
    fn: ({ session }) => {
      const closed = Object.keys(db.auth.sessions).length - 1;
      db.auth.sessions = { [session.key]: db.auth.sessions[session.key] };
      saveData();
      return { closed };
    }
  },
  'POST /api/auth/change-pin': {
    fn: ({ req, body }) => {
      const ip = clientIp(req);
      checkLock(ip);
      if (!verifyPin(body.current)) {
        registerFail(ip);
        throw new HttpError(403, 'Mevcut PIN hatalı.');
      }
      validatePinFormat(body.pin);
      setPin(body.pin);
      return {};
    }
  },

  'GET /api/state': {
    fn: ({ url }) => {
      const since = Number(url.searchParams.get('since')) || 0;
      const watchList = {};
      for (const [id, w] of watches) watchList[id] = { kind: w.kind, startedAt: w.startedAt, phase: w.phase };
      return {
        devices: db.devices,
        status: Object.fromEntries(statusMap),
        watches: watchList,
        lan: getPrimaryLanInterface(),
        agentPort: db.agent.port,
        events: events.filter(e => e.seq > since),
        seq: eventSeq
      };
    }
  },

  // Ağı Tara
  'POST /api/scan': {
    fn: async () => {
      const result = await scanNetwork();
      pollSoon();
      return result;
    }
  },

  // WoL Paketi Gönder (kayıtlı cihaz id'si veya serbest MAC)
  'POST /api/wake': {
    fn: async ({ body }) => {
      if (body.id) return wakeDevice(mustDevice(body.id), 'manual');
      const mac = normalizeMac(body.mac);
      if (!mac) throw new HttpError(400, body.mac ? 'Geçersiz MAC adresi formatı.' : 'MAC adresi gereklidir.');
      const saved = db.devices.find(d => d.mac === mac);
      if (saved) return wakeDevice(saved, 'manual');

      const lan = getPrimaryLanInterface();
      await sendMagicPacket(mac, lan.broadcast);
      console.log(`[WoL] Paket iletildi -> MAC: ${mac} | Hedef: ${lan.broadcast}`);
      const name = cleanStr(body.name, 60) || mac;
      addHistory({ type: 'wake', mac, name, source: 'manual', text: `${name} için uyandırma paketi gönderildi` });
      return { watching: false };
    }
  },

  'POST /api/power': {
    fn: async ({ body }) => {
      const dev = mustDevice(body.id);
      if (!POWER_ACTIONS[body.action]) throw new HttpError(400, 'Geçersiz işlem.');
      await powerAction(dev, body.action);
      return {};
    }
  },
  'POST /api/power/test': {
    fn: async ({ body }) => {
      const existing = body.id ? findDevice(body.id) : null;
      const dev = sanitizeDevice(body.device, existing);
      if (dev.power.method === 'none') throw new HttpError(400, 'Kapatma yöntemi seçilmedi.');
      // Test kaydı değiştirmez: bulunan yeni IP yalnızca bu istekte kullanılır
      const ip = await resolveTarget(dev, false);
      if (dev.power.method === 'agent') {
        const r = await agentRequest(dev, ip, 'GET', '/ping');
        if (!r.ok) throw new HttpError(502, r.error);
        return { message: `Ajan yanıt verdi (${r.data.host || ip}); imza ve MAC doğrulandı.` };
      }
      await ensureSshKey();
      const r = await run('ssh', sshArgs(dev, ip, SSH_VERBS.ping), 15000);
      if (r.code === 0 && r.stdout.includes('wol-ok')) return { message: 'SSH bağlantısı başarılı (kısıtlı komut modu).' };
      throw new HttpError(502, sshError(r));
    }
  },

  'POST /api/devices/create': {
    fn: ({ body }) => {
      const dev = sanitizeDevice(body);
      assertUniqueMac(dev.mac);
      db.devices.push(dev);
      saveData();
      pollSoon(dev.id);
      return { device: dev };
    }
  },
  'POST /api/devices/update': {
    fn: ({ body }) => {
      const existing = mustDevice(body.id);
      const dev = sanitizeDevice(body, existing);
      assertUniqueMac(dev.mac, existing.id);
      Object.assign(existing, dev);
      statusMap.delete(existing.id);
      saveData();
      pollSoon(existing.id);
      return { device: existing };
    }
  },
  'POST /api/devices/delete': {
    fn: ({ body }) => {
      const dev = mustDevice(body.id);
      db.devices = db.devices.filter(d => d !== dev);
      statusMap.delete(dev.id);
      watches.delete(dev.id);
      saveData();
      return {};
    }
  },
  'POST /api/devices/reorder': {
    fn: ({ body }) => {
      const ids = Array.isArray(body.ids) ? body.ids : [];
      const pos = new Map(ids.map((id, i) => [id, i]));
      const rank = d => (pos.has(d.id) ? pos.get(d.id) : Number.MAX_SAFE_INTEGER);
      db.devices.sort((a, b) => rank(a) - rank(b));
      saveData();
      return {};
    }
  },
  'POST /api/devices/import': {
    fn: ({ body }) => importDevices(body.devices, body.mode === 'replace' ? 'replace' : 'merge')
  },
  'GET /api/export': {
    fn: ({ res }) => {
      const date = new Date().toISOString().slice(0, 10);
      const devices = db.devices.map(({ id, createdAt, updatedAt, ...rest }) => ({
        ...rest,
        schedules: (rest.schedules || []).map(({ last, ...s }) => s)
      }));
      res.writeHead(200, {
        'Content-Type': 'application/json; charset=utf-8',
        'Content-Disposition': `attachment; filename="wol-cihazlar-${date}.json"`,
        'Cache-Control': 'no-store'
      });
      res.end(JSON.stringify({ app: 'wol-dashboard', version: 1, exportedAt: new Date().toISOString(), devices }, null, 2));
    }
  },

  'GET /api/history': {
    fn: () => ({ history: db.history })
  },
  'POST /api/history/clear': {
    fn: () => {
      db.history = [];
      saveData();
      return {};
    }
  },

  'GET /api/settings': {
    fn: () => ({
      agent: { port: db.agent.port, ...buildAgentCommands() },
      lan: getPrimaryLanInterface(),
      httpPort: PORT,
      sshPublicKey: readPubKey(),
      sshSetup: readPubKey() ? buildSshSetup(readPubKey()) : null,
      sessions: Object.keys(db.auth.sessions).length,
      version: APP_VERSION
    })
  },
  'POST /api/settings/agent-token': {
    fn: () => {
      db.agent.token = randomToken(16);
      saveData();
      return {};
    }
  },
  'POST /api/settings/ssh-key': {
    fn: async () => ({ sshPublicKey: await ensureSshKey() })
  }
};

// --- 10. HTTP ROUTER ---
const server = http.createServer(async (req, res) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'no-referrer');

  let url;
  try {
    url = new URL(req.url, 'http://localhost');
  } catch {
    return sendJson(res, 400, { success: false, message: 'Geçersiz adres.' });
  }
  const route = `${req.method} ${url.pathname}`;

  try {
    // Favicon doğrudan çağrıldığında SVG içeriğini döndür (Tarayıcı konsolunda 404 önler)
    if (req.method === 'GET' && (url.pathname === '/favicon.ico' || url.pathname === '/favicon.svg')) {
      res.writeHead(200, { 'Content-Type': 'image/svg+xml' });
      res.end(SVG_FAVICON);
      return;
    }

    // Dashboard Arayüzü (GET /) — giriş kontrolü sayfa içinde API üzerinden yapılır
    if (req.method === 'GET' && url.pathname === '/') {
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' });
      res.end(DASHBOARD_HTML);
      return;
    }

    // Windows ajanı kurulum betiği (ajan anahtarı ile korunur)
    if (req.method === 'GET' && url.pathname === '/agent/install.ps1') {
      const key = Buffer.from(String(url.searchParams.get('key') || ''));
      const token = Buffer.from(db.agent.token);
      if (key.length !== token.length || !crypto.timingSafeEqual(key, token)) {
        res.writeHead(403, { 'Content-Type': 'text/plain; charset=utf-8' });
        res.end("Write-Host 'Gecersiz ajan anahtari. Komutu panelin Ayarlar bolumunden yeniden kopyalayin.' -ForegroundColor Red");
        return;
      }
      res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8', 'Cache-Control': 'no-store' });
      res.end(buildAgentInstaller());
      return;
    }

    const handler = API[route];
    if (!handler) return sendJson(res, 404, { success: false, message: '404 Bulunamadı' });

    if (req.method === 'POST') {
      // CSRF koruması: yalnızca aynı kaynaktan gelen JSON istekleri kabul edilir
      const origin = req.headers.origin;
      if (origin) {
        let originHost = '';
        try { originHost = new URL(origin).host; } catch { /* geçersiz */ }
        if (originHost !== req.headers.host) throw new HttpError(403, 'Farklı kaynaktan gelen istek reddedildi.');
      }
      if (!String(req.headers['content-type'] || '').includes('application/json')) {
        throw new HttpError(415, 'İstek JSON olmalı.');
      }
    }

    const session = getSession(req);
    if (!handler.public && !session) {
      return sendJson(res, 401, { success: false, auth: true, message: 'Oturum gerekli.' });
    }

    let body = {};
    if (req.method === 'POST') {
      const raw = await readBody(req);
      try {
        body = raw ? JSON.parse(raw) : {};
      } catch {
        throw new HttpError(400, 'Geçersiz JSON.');
      }
      if (!body || typeof body !== 'object') body = {};
    }

    const result = await handler.fn({ req, res, url, body, session });
    if (!res.writableEnded) sendJson(res, 200, { success: true, ...(result || {}) });
  } catch (err) {
    const status = err instanceof HttpError ? err.status : 500;
    if (status === 500) console.error('[Hata]', route, err);
    if (!res.headersSent) sendJson(res, status, { success: false, message: err.message || 'Sunucu hatası' });
  }
});

// Arka plan görevleri: canlı durum yoklaması, uyanma/kapanma takibi, zamanlayıcı
setInterval(() => pollStatuses(), POLL_INTERVAL);
setInterval(() => {
  if (watches.size) pollStatuses([...watches.keys()]);
}, WATCH_POLL_INTERVAL);
setInterval(runScheduler, 15000);
setTimeout(() => pollStatuses(), 1000);

// Sunucuyu başlat
server.listen(PORT, '0.0.0.0', () => {
  const lan = getPrimaryLanInterface();
  console.log(`====================================================`);
  console.log(` 🚀 WoL & Network Dashboard Aktif`);
  console.log(` 🌐 Arayüz: ${lan.name} (${lan.ip})`);
  console.log(` 📡 Port: ${PORT}`);
  console.log(` 💾 Veri: ${DATA_FILE} (${db.devices.length} kayıtlı cihaz)`);
  console.log(`====================================================`);
});
