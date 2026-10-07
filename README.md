# WoL Dashboard

Ev ağı için tek dosyalık, bağımlılıksız (yalnızca Node.js yerleşik modülleri) Wake-on-LAN paneli.

- Cihaz kaydı, PIN ile giriş
- Canlı durum (ping + TCP + ARP), uyanma takibi
- Zamanlanmış uyandırma, uyandırma geçmişi
- Uzaktan kapatma / yeniden başlatma (Windows ajanı veya kısıtlı SSH)
- JSON dışa/içe aktarma

## Kurulum (Docker)

Debian 12 üzerinde, root olarak:

```bash
git clone https://github.com/alpyxd/wol-dashboard.git
cd wol-dashboard
bash install.sh
```

Docker zaten kuruluysa:

```bash
docker compose up -d --build
```

Panel `http://<sunucu-ip>` adresinde açılır; ilk girişte PIN belirlenir.

## Neden `network_mode: host`?

Magic packet yerel ağa broadcast olarak gönderilir. Docker'ın varsayılan bridge ağı
broadcast'i LAN'a iletmez, bu yüzden konteyner host ağında çalışır. ARP tablosunu
tazelemek için `NET_ADMIN`, ping için `NET_RAW` yetkisi verilir.

Sunucu, uyandırılacak cihazlarla aynı yerel ağda olmalıdır.

## Veri

Tüm veri `./data` klasöründe tutulur (konteyner içinde `/data`):

- `data.json` — cihazlar, geçmiş, PIN özeti, oturumlar, ajan tokeni
- `keys/` — uzaktan kapatma için kullanılan SSH anahtarı

Bu klasör `.gitignore` ile depodan hariç tutulur. Yedek almak için `data/` klasörünü kopyalamak yeterlidir.

## Ayarlar

| Ortam değişkeni | Varsayılan | Açıklama |
|---|---|---|
| `PORT` | `80` | Web arayüzü portu |
| `WOL_DATA_DIR` | `/data` | Veri klasörü |
| `TZ` | `Europe/Istanbul` | Zamanlanmış uyandırmalar için saat dilimi |

## Yararlı komutlar

```bash
docker compose logs -f          # canlı log
docker compose restart          # yeniden başlat
docker compose up -d --build    # server.js değiştiyse yeniden derle

# PIN sıfırlama
docker compose stop && docker compose run --rm wol-dashboard node server.js --reset-pin && docker compose start
```

## Güvenlik notu

Panel yalnızca yerel ağda veya Tailscale gibi bir VPN üzerinden kullanılmak üzere tasarlanmıştır.
Port 80'i internete doğrudan açmayın.
