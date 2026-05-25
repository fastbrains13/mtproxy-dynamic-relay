#!/usr/bin/env bash
set -euo pipefail

echo "🚀 MTProxy Dynamic Relay Installer v1.0"
echo "📦 Установка зависимостей..."
sudo apt update && sudo apt install -y golang-go build-essential ufw fail2ban sqlite3

echo "👤 Создание пользователя..."
sudo useradd -r -m -s /bin/bash mtproxy-relay || true
sudo mkdir -p /opt/mtproxy-relay/{bin,data,logs}
sudo chown -R mtproxy-relay:mtproxy-relay /opt/mtproxy-relay

echo "🔧 Подготовка зависимостей Go..."
go mod download
go mod tidy

echo "🔨 Компиляция..."
CGO_ENABLED=1 go build -trimpath -ldflags="-s -w" -o /opt/mtproxy-relay/bin/mtproxy-relay ./cmd/server
sudo chmod +x /opt/mtproxy-relay/bin/mtproxy-relay
sudo chown mtproxy-relay:mtproxy-relay /opt/mtproxy-relay/bin/mtproxy-relay

echo "📦 Установка systemd..."
sudo cp mtproxy-relay.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now mtproxy-relay

echo "🛡️ Настройка UFW..."
sudo ufw allow 22/tcp || true
sudo ufw allow 8080/tcp || true
sudo ufw allow 1024:65535/tcp comment "MTProxy Relay Ports" || true
sudo ufw --force enable || true

SERVER_IP=$(curl -s ifconfig.me)
echo -e "\n✅ Готово! Админка: http://${SERVER_IP}:8080"
echo "👤 Логин: admin | 🔑 Пароль: admin"
echo "🔐 Смените пароль после первого входа через SQLite или админку."