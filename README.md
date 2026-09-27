# TP-Link Access Control CLI

Управление списком MAC-адресов (**Access Control**) на TP-Link репитере/расширителе
из командной строки: добавление и удаление MAC, просмотр списков, включение/выключение
и переключение режима (blacklist / whitelist).

Работает напрямую с веб-интерфейсом устройства по его собственному зашифрованному
протоколу — браузер не нужен. Адрес устройства задаётся переменной `TPLINK_HOST`.

Проверено на репитере в режиме **Range Extender** (прошивка с шифрованием «TDDP/MER», gdpr).

## Установка

Требуется Python 3.8+. Виртуальное окружение находится в корне проекта
(интерпретатор `./bin/python`). Установка зависимостей:

```bash
./bin/python -m pip install -r requirements.txt
```

Если окружения ещё нет, создайте его:

```bash
python3 -m venv .           # или: virtualenv -p python3.12 .
./bin/python -m pip install -r requirements.txt
```

Зависимости (`requirements.txt`): `pycryptodome`, `requests`.

## Настройка (адрес и пароль)

Адрес устройства и пароль веб-панели задаются переменными окружения (или флагами
`--host` / `--password` к каждой команде):

```bash
export TPLINK_HOST='192.168.1.1'      # адрес вашего устройства
export TPLINK_PASSWORD='ваш_пароль'
```

Без `TPLINK_HOST`/`--host` и `TPLINK_PASSWORD`/`--password` команда завершится с ошибкой.

## Использование

```bash
PY=./bin/python

# Просмотр списков
$PY src/tplink_ac.py list                       # blacklist
$PY src/tplink_ac.py list -l whitelist          # whitelist

# Добавить / удалить MAC
$PY src/tplink_ac.py add -m AA-BB-CC-DD-EE-FF -n "Мой телефон"
$PY src/tplink_ac.py add -m AA-BB-CC-DD-EE-FF -l whitelist
$PY src/tplink_ac.py del -m AA-BB-CC-DD-EE-FF

# Управление Access Control
$PY src/tplink_ac.py status                     # вкл/выкл и текущий режим
$PY src/tplink_ac.py enable                      # включить (режим сохраняется)
$PY src/tplink_ac.py disable                     # выключить
$PY src/tplink_ac.py mode blacklist              # сменить режим (вкл/выкл сохраняется)
$PY src/tplink_ac.py mode whitelist
```

MAC принимается в любом формате: `AA-BB-CC-DD-EE-FF`, `aa:bb:cc:dd:ee:ff`, `aabbccddeeff`.

### Все команды

| Команда | Действие |
|---|---|
| `list` | показать список (`-l whitelist` для белого) |
| `add -m <MAC> [-n имя] [-t тип]` | добавить MAC (`-t`: `pc\|phone\|pad\|other`) |
| `del -m <MAC>` | удалить MAC по адресу |
| `status` | показать статус и режим |
| `enable` / `disable` | включить / выключить Access Control |
| `mode blacklist` / `mode whitelist` | переключить режим |

### Опции

| Опция | По умолчанию | Назначение |
|---|---|---|
| `-l, --list` | `blacklist` | целевой список: `blacklist` \| `whitelist` |
| `-n, --name` | `device` | имя устройства (для `add`) |
| `-t, --type` | `other` | тип устройства (для `add`) |
| `--host` | `$TPLINK_HOST` | адрес устройства |
| `--password` | `$TPLINK_PASSWORD` | пароль веб-панели |
| `--debug` | — | печать расшифрованных ответов устройства |

## Использование как библиотеки

```python
import os, sys
sys.path.insert(0, "src")                  # модуль лежит в src/
from tplink_ac import TPLinkAC

c = TPLinkAC(os.environ["TPLINK_HOST"], os.environ["TPLINK_PASSWORD"])
c.login()
print(c.get_status())                      # {'enable': '1', 'rule': '1'}
print(c.get_list("whitelist"))             # [{'hMac': ..., 'hName': ..., ...}, ...]
c.add_mac("AA-BB-CC-DD-EE-FF", name="ПК", which="blacklist")
c.del_mac("AA-BB-CC-DD-EE-FF", which="blacklist")
c.set_status(enable=True, rule="1")        # rule: "0" blacklist, "1" whitelist
```

## Автодополнение по TAB

Автодополнение bash привязывается к первому слову команды, поэтому по
`$PY src/tplink_ac.py <TAB>` оно не работает (`$PY` — переменная, bash её не
разворачивает при дополнении). Решение — короткая команда-обёртка `tplink-ac`:

```bash
source /home/lis/Projects/wifi_access/completion.bash   # или строкой в ~/.bashrc
```

После этого доступна команда `tplink-ac` с автодополнением:

```bash
tplink-ac <TAB>          # list add del status enable disable mode
tplink-ac mode <TAB>     # blacklist whitelist
tplink-ac add -t <TAB>   # pc phone pad other
tplink-ac list -l <TAB>  # blacklist whitelist
```

Обёртка сама вызывает `./bin/python src/tplink_ac.py`, так что окружение
активировать не нужно. Пароль по-прежнему берётся из `TPLINK_PASSWORD` или `--password`.

## ⚠️ Осторожно с режимом

- **blacklist** — доступ разрешён всем, кроме адресов из списка.
- **whitelist** — доступ разрешён **только** адресам из списка.

Переключение `mode` или `disable` при активном Access Control немедленно меняет
логику доступа к сети. Если сейчас активен whitelist с вашими устройствами —
`mode blacklist` или `disable` изменит поведение; будьте внимательны, чтобы
не отрезать себе доступ.

## Как это устроено

Протокол разобран из JavaScript самого устройства и задокументирован в комментариях
`src/tplink_ac.py`:

- **Логин** — пароль кодируется дважды: сначала `securityEncode` с дефолтными
  ключами (`doEncrypt` поля формы), затем challenge-ключами `authInfo`; результат
  передаётся как параметр `id` (`?code=7`).
- **Канал данных** — тело запроса шифруется AES-128-CBC (PKCS7) и подписывается RSA
  (`sign`), ответы расшифровываются (режим gdpr).
- **Access Control** — списки хранятся в блоках `59` (blacklist) и `60` (whitelist)
  по 16 слотов; add/delete — текстовые команды `advanced bm host -add/-delete`;
  статус и режим — блок `31` (`bhavEnable`, `bhavRule`).

## Файлы

- `src/tplink_ac.py` — клиент и CLI
- `requirements.txt` — зависимости
- `completion.bash` — команда-обёртка `tplink-ac` и автодополнение по TAB
