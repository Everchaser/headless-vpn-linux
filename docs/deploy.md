# Установка на чистый сервер

Выполняй из корня репозитория. Это **не обновление поверх старого Headless или Happ**. До переключения сохрани доступ через консоль, исходные `ip -br link`, `ip rule show`, `ip route` и `ip -6 route show table all`; проверь DNS, открытые inbound-порты и зависимые от хоста сервисы. Не отключай IPv6 и чужие VPN автоматически. На хосте с IPv6 default route, чужим TUN или нетипичными таблицами маршрутизации остановись и пересмотри топологию.

## 1. Подготовка (без запуска VPN)

См. [релизы и проверку бинарников](upstream.md). Укажи фактические абсолютные пути к распакованным и проверенным исполняемым файлам. Установщик ничего не скачивает.

```bash
XRAY_BIN="$HOME/downloads/xray"
SING_BOX_BIN="$HOME/downloads/sing-box"
sudo bash ./install-headless-vpn-v2.sh --stage "$XRAY_BIN" "$SING_BOX_BIN"
```

Ожидается `Staged. No units installed or started.` Код, ядра и шаблон принадлежат root в `/opt/headless-vpn`; аккаунт `headless-vpn` без интерактивного входа записывает только `/var/lib/headless-vpn/state` (0700). Повторный `--stage` откажется, если обнаружит существующую установку, state или аккаунт: ничего не удаляй вслепую. В случае неполной подготовки сначала сверяй файлы с установщиком; при повторной установке не уничтожай существующий state.

## 2. Ввод профиля и безопасная проверка

```bash
cd /opt/headless-vpn
sudo -u headless-vpn /usr/bin/python3 -m headless_vpn.cli subscription add primary
```

Ссылку HTTPS вставь в собственном терминале в `Subscription URL (hidden):`, не в чат, переменную окружения или аргументы. Если провайдер требует HWID и разрешил отдельное устройство, **вместо предыдущей команды**:

```bash
sudo -u headless-vpn /usr/bin/python3 -m headless_vpn.cli \
  subscription add primary --device-name vpn-host
```

`vpn-host` — произвольная метка. Стабильный идентификатор выводится из локальной идентичности машины; на нескольких серверах не клонируй `/etc/machine-id`. Не регистрируй устройство повторно ради диагностики. Проверь кабинет провайдера. Поддерживаются распознаваемые VLESS URI/Xray JSON; не любой формат или транспорт. При отсутствии работающих кандидатов ничего не публикуется. Альтернатива для JSON: `init` принимает **файл**, читаемый сервисным пользователем; держи его вне репозитория с режимом 0600.

```bash
sudo -u headless-vpn /usr/bin/python3 -m headless_vpn.cli check
sudo -u headless-vpn /usr/bin/python3 -m headless_vpn.cli probe
```

Нужны `Both cores validated` и хотя бы один `ok: true`. Это изолированные SOCKS-пробы, не проверка системного маршрута. Для реального резерва нужны как минимум два отвечающих узла. Не продолжай при неуспехе.

## 3. Переключение (только после явного согласия)

Закрой прежний GUI-клиент и освободи TUN по его инструкции. Не запускай одновременно два системных туннеля. Для Happ это отдельно согласованное выключение `happd.service` и его автозапуска. На новом сервере без Happ ничего отключать не нужно.

```bash
sudo bash /opt/headless-vpn/install-headless-vpn-v2.sh --activate
```

Установщик проверяет конфликты, повторно прогоняет синтаксис и пробу, сохраняет резерв определений systemd, запускает Xray и TUN и включает автозапуск и таймер после проверки egress через SOCKS. Дождись `v2 services activated`. При исходном отказе не повторяй команду поверх незавершённого состояния.

## 4. Проверка и откат

```bash
systemctl is-active headless-vpn-xray.service headless-vpn.service headless-vpn-refresh.timer
ip -brief link show tun0
curl -q --noproxy '*' --max-time 10 -fsS -o /dev/null -w 'HTTP %{http_code}\n' https://www.gstatic.com/generate_204
systemctl show headless-vpn-xray.service -p ActiveState -p NRestarts
```

Ожидай три `active`, `tun0`, HTTP `204`. Повтори HTTPS несколько раз в течение минимум трёх минут, проверь независимый HTTPS-ресурс, новый SSH-сеанс и зависимые сервисы. Проверь [чек-лист](checklist.md) до перезагрузки.

Если теряется доступ, из консоли сначала останови и отключи TUN вместе с обновлениями:

```bash
sudo systemctl disable --now headless-vpn-refresh.timer headless-vpn.service
sudo systemctl stop headless-vpn-refresh.service headless-vpn-xray.service
ip -brief link
```

После исчезновения `tun0` верни прежний VPN отдельно. Если надо восстановить **старые определения** systemd, а не просто выключить v2:

```bash
sudo bash /opt/headless-vpn/install-headless-vpn-v2.sh --rollback
```

Откат не удаляет подписки и не запускает старые службы. Перед новой активацией проверь резерв `/var/lib/headless-vpn-v2/rollback` и сохрани его в приватном архиве; не удаляй. Если определения уже v2 и нужен обычный повторный запуск, установщик не нужен: после проверки отсутствия другого TUN используй `sudo systemctl start headless-vpn.service headless-vpn-refresh.timer`.
