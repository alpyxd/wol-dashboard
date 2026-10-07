#!/bin/bash
# Debian 12 üzerinde root olarak çalıştır: bash install.sh
# Docker'ı (resmi depodan) kurar, uygulamayı /opt/wol-dashboard altına kopyalayıp başlatır.
set -euo pipefail

APP_DIR=/opt/wol-dashboard
SRC_DIR="$(cd "$(dirname "$0")" && pwd)"

echo "==> Temel paketler"
apt-get update
apt-get install -y ca-certificates curl

echo "==> Docker"
if ! command -v docker >/dev/null; then
  install -m 0755 -d /etc/apt/keyrings
  curl -fsSL https://download.docker.com/linux/debian/gpg -o /etc/apt/keyrings/docker.asc
  chmod a+r /etc/apt/keyrings/docker.asc
  echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/debian $(. /etc/os-release && echo "$VERSION_CODENAME") stable" \
    > /etc/apt/sources.list.d/docker.list
  apt-get update
  apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
fi
systemctl enable --now docker

echo "==> Uygulama dosyaları -> $APP_DIR"
mkdir -p "$APP_DIR"
if [ "$SRC_DIR" != "$APP_DIR" ]; then
  cp "$SRC_DIR"/server.js "$SRC_DIR"/Dockerfile "$SRC_DIR"/docker-compose.yml "$SRC_DIR"/.dockerignore "$APP_DIR"/
fi
mkdir -p "$APP_DIR/data"
chmod 700 "$APP_DIR/data"

echo "==> Konteyner başlatılıyor"
cd "$APP_DIR"
docker compose up -d --build
sleep 3
docker compose ps
docker compose logs --tail 20

echo
echo "Bitti. Arayüz: http://$(hostname -I | awk '{print $1}')"
