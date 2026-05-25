# 🌐 MTProxy Dynamic Relay

Умный MTProxy-релей с веб-админкой, автоматическим выбором лучшего бэкенда по пингу (RTT) и поддержкой обфусцированных (`ee`) и сырых (`dd`) секретов.

## ✨ Возможности
- 🔄 **Динамическая маршрутизация**: клиенты подключаются к фиксированному порту/секрету, сервер автоматически перенаправляет трафик на прокси с наименьшим RTT
- 🔐 **Поддержка XOR-обфускации**: полная совместимость с `ee...` секретами Telegram
- 📊 **Веб-админка**: управление списками, прокси, просмотр статуса и RTT в реальном времени
- 📈 **Мониторинг**: автоматическая проверка доступности бэкендов каждые 15 секунд
- 🛡️ **Безопасность**: аутентификация в админке, запуск от непривилегированного пользователя, systemd-изоляция
- 🐧 **Простая установка**: скрипт `install.sh` для Ubuntu 24.04

## 🚀 Быстрый старт

### Установка
```bash
git clone https://github.com/fastbrains13/mtproxy-dynamic-relay.git
cd mtproxy-dynamic-relay
chmod +x install.sh
sudo ./install.sh
```

# Статус сервиса
sudo systemctl status mtproxy-relay

# Логи в реальном времени
sudo journalctl -u mtproxy-relay -f

# Перезапуск после обновления кода
cd ~/mtproxy-dynamic-relay
sudo systemctl stop mtproxy-relay
go build -trimpath -ldflags="-s -w" -o /opt/mtproxy-relay/bin/mtproxy-relay ./cmd/server
sudo systemctl start mtproxy-relay

# Резервное копирование БД
sudo cp /opt/mtproxy-relay/data/app.db ~/backup_$(date +%F).db