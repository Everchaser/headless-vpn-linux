# Ядра и документация

- [Xray-core v26.7.28](https://github.com/XTLS/Xray-core/releases/tag/v26.7.28) — проверенная по поведению версия Xray; upstream помечает релиз как pre-release. Например, для x86-64 архив `Xray-linux-64.zip`.
- [sing-box v1.12.12](https://github.com/SagerNet/sing-box/releases/tag/v1.12.12) — версия с используемым шаблоном TUN. Например, для x86-64 архив `sing-box-1.12.12-linux-amd64.tar.gz`.
- [sing-box: TUN](https://sing-box.sagernet.org/configuration/inbound/tun/), [Xray: документация](https://xtls.github.io/en/).
- [Remnawave: HWID device limit](https://docs.rw/features/hwid-device-limit/) — пример поведения панели; политика и способ регистрации зависят от провайдера.

Скачай платформенный архив на доверенной машине без `sudo`, сравни опубликованный SHA-256 (и подпись, если есть), распакуй в отдельный каталог и запусти `version`. Для другой архитектуры выбери соответствующий официальный архив, не копируй бинарники Happ. Далее передай **пути к двум исполняемым файлам** в `--stage`. Версии закреплены для воспроизводимости, а не как рекомендация держать их без проверки обновлений. При замене версии повтори проверку шаблона, тесты, попытку переключения поколений и тест холодной загрузки.

В каталоге с архивами для **Linux x86-64**:

```bash
sha256sum -c <<'SUMS'
8195d909f1109b8f3d99eefe401a3c451d7bf4af71f24d3815420f77e5dd2a40  Xray-linux-64.zip
7c103cb2f9a7dc54cb82962043596718ed27989a478d6405f0939a9b775f889f  sing-box-1.12.12-linux-amd64.tar.gz
SUMS
```
