#!/usr/bin/env bash
set -euo pipefail

echo "🚀 MTProxy Dynamic Relay Installer"
sudo apt update && sudo apt install -y golang-go build-essential ufw fail2ban

sudo useradd -r -m -s /bin/bash mtproxy-relay || true
sudo mkdir -p /opt/mtproxy-relay/{bin,data,logs}
sudo chown -R mtproxy-relay:mtproxy-relay /opt/mtproxy-relay

echo "🔨 Компиляция..."
go build -o /opt/mtproxy-relay/bin/mtproxy-relay ./cmd/server
sudo chmod +x /opt/mtproxy-relay/bin/mtproxy-relay
sudo chown mtproxy-relay:mtproxy-relay /opt/mtproxy-relay/bin/mtproxy-relay

echo "📦 Установка systemd..."
sudo cp mtproxy-relay.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now mtproxy-relay

echo "🛡️ Настройка UFW..."
sudo ufw allow 22/tcp
sudo ufw allow 8080/tcp
sudo ufw allow 1024:65535/tcp comment "MTProxy Relay Ports"
sudo ufw --force enable

echo -e "\n✅ Готово! Админка: http://$(curl -s ifconfig.me):8080\n👤 Логин: admin | 🔑 Пароль: admin\n📝 Не забудьте сменить пароль в базе после первого входа!"