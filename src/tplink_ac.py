#!/usr/bin/env python3
"""
Управление списком MAC-адресов (Access Control) на TP-Link репитере/расширителе
через его веб-интерфейс (протокол "TDDP/MER" с шифрованием, gdpr-режим).

Проверено на репитере в режиме Range Extender (страница Access Control).
Протокол разобран из JS самого устройства:
  - логин: id = securityEncode(authInfo3, password, authInfo4), ?code=7
  - канал данных: AES-128-CBC(PKCS7) тело + RSA-подпись (sign), gdpr
  - Access Control:
      список  : чтение блока 59 (blacklist) / 60 (whitelist)
      добавить: advanced bm host -add id:<59|60> name:<url> mac:<MAC> devType:<type>
      удалить : advanced bm host -delete id:<59|60> index:<N>
      статус/режим: блок 31 (bhavEnable=вкл/выкл, bhavRule=0 blacklist / 1 whitelist)

Использование:
    python tplink_ac.py list
    python tplink_ac.py add   -m AA-BB-CC-DD-EE-FF -n "Мой телефон"
    python tplink_ac.py del   -m AA-BB-CC-DD-EE-FF
    python tplink_ac.py status
    python tplink_ac.py enable | disable
    python tplink_ac.py mode blacklist | mode whitelist
Адрес устройства — из TPLINK_HOST (или флаг --host).
Пароль — из TPLINK_PASSWORD (или флаг --password).
Список: --list blacklist (по умолчанию) | whitelist.
"""
import argparse
import base64
import os
import random
import re
import sys
import time
from urllib.parse import quote, unquote

import requests
from Crypto.Cipher import AES, PKCS1_v1_5
from Crypto.Util.Padding import pad, unpad
from Crypto.PublicKey import RSA

# --- коды операций устройства (из frame.js) ---
TDDP_INSTRUCT = 0     # текстовая команда (add/delete)
TDDP_WRITE = 1        # запись блока данных
TDDP_READ = 2         # чтение блока данных
TDDP_AUTH = 7         # логин / получение authInfo
HTTP_OP_GDPRCFG = 16  # RSA-параметры (nn, ee, seq) и регистрация AES-ключа

BLACK_LIST_ID = 59
WHITE_LIST_ID = 60
BEHAVMANG_ID = 31     # конфиг Access Control (bhavEnable, bhavRule)
RULE = {"blacklist": "0", "whitelist": "1"}
RULE_NAME = {"0": "blacklist", "1": "whitelist"}

# Словарь по умолчанию для securityEncode (если authInfo[4] пуст) — из su.fun.js
DEFAULT_DICT = ("yLwVl0zKqws7LgKPRQ84Mdt708T1qQ3Ha7xv3H7NyU84p21BriUWBU43odz3iP4rBL3cD02"
                "KZciXTysVXiV8ngg6vL48rPJyAUw0HurW20xqxv9aYb4M9wK1Ae0wlro510qXeU07kV57fQ"
                "Mc8L6aLgMLwygtc0F10a0Dg70TOoouyFhdysuRMO51yY5ZlOZZLEal1h0t9YQW0Ko7oBwmCA"
                "Hoic4HYbUyVeU3sfQ1xtXcPcf1aT303wAQhv66qzW")


def security_encode(e: str, t: str = None, r: str = None) -> str:
    """Портирован из $.su.encrypt (su.fun.js). XOR по позициям с выборкой из словаря r.
    Значения по умолчанию t и r совпадают с дефолтами устройства — вызов с одним
    аргументом эквивалентен doEncrypt() поля (предварительное кодирование пароля)."""
    dict_ = r or DEFAULT_DICT
    t = t or "RDpbLfCPsJZ7fiv"
    o, l, u = len(e), len(t), len(dict_)
    h = o if l < o else l
    out = []
    for d in range(h):
        s = a = 187
        if o <= d:
            a = ord(t[d])
        elif l <= d:
            s = ord(e[d])
        else:
            s = ord(e[d]); a = ord(t[d])
        out.append(dict_[(s ^ a) % u])
    return "".join(out)


def enc_uri_component(s: str) -> str:
    """Эквивалент JS encodeURIComponent."""
    return quote(s, safe="!~*'()")


class TPLinkAC:
    def __init__(self, host: str, password: str, timeout: int = 15, debug: bool = False):
        self.host = host
        self.base = f"http://{host}/"
        self.password = password
        self.timeout = timeout
        self.debug = debug
        self.s = requests.Session()
        self.s.headers.update({
            "Referer": self.base,
            "Content-Type": "text/plain;charset=UTF-8",
        })
        self.session_id = None
        self.nn = self.ee = None
        self.seq = 0
        self.aes_key = self.aes_iv = None
        self.aes_key_string = None

    # ---------- низкоуровневые запросы ----------
    def _post(self, code, asyn, body="", with_id=True):
        url = f"{self.base}?code={code}&asyn={asyn}"
        if with_id and self.session_id:
            url += "&id=" + self.session_id
        r = self.s.post(url, data=body.encode("utf-8"), timeout=self.timeout)
        return r

    @staticmethod
    def _split_err(text):
        """errorAndDataSplit: первая строка — код ошибки, остальное — данные."""
        m = re.search(r"[\r\n]", text)
        if not m:
            return (int(text) if text.strip() else -1), ""
        i = m.start()
        code = int(text[:i])
        data = text[i + 2:] if text[i:i + 2] == "\r\n" else text[i + 1:]
        return code, data

    def _rsa_encrypt(self, text):
        key = RSA.construct((int(self.nn, 16), int(self.ee, 16)))
        cipher = PKCS1_v1_5.new(key)
        modlen = len(self.nn)
        out = ""
        for i in range(0, len(text), 53):
            out += cipher.encrypt(text[i:i + 53].encode("utf-8")).hex().zfill(modlen)
        return out

    def _aes_encrypt(self, plaintext):
        c = AES.new(self.aes_key.encode(), AES.MODE_CBC, self.aes_iv.encode())
        return base64.b64encode(c.encrypt(pad(plaintext.encode("utf-8"), 16))).decode()

    def _aes_decrypt(self, b64):
        c = AES.new(self.aes_key.encode(), AES.MODE_CBC, self.aes_iv.encode())
        return unpad(c.decrypt(base64.b64decode(b64)), 16).decode("utf-8")

    def _secure_request(self, code, asyn, plaintext):
        """Запрос в шифрованном канале (sign + data), с расшифровкой ответа."""
        ct = self._aes_encrypt(plaintext)
        sign = self._rsa_encrypt(f"{self.aes_key_string}&s={self.seq + len(ct)}")
        body = f"sign={sign}\r\ndata={ct}"
        r = self._post(code, asyn, body)
        if self.debug:
            print(f"[debug] {code}/{asyn} status={r.status_code} raw_len={len(r.text)}", file=sys.stderr)
        if r.status_code != 200:
            raise RuntimeError(f"HTTP {r.status_code} на code={code}: {r.text[:80]!r}")
        dec = self._aes_decrypt(r.text) if r.text else ""
        if self.debug:
            print(f"[debug] decrypted: {dec!r}", file=sys.stderr)
        err, data = self._split_err(dec)
        if err != 0:
            raise RuntimeError(f"Устройство вернуло ошибку {err} на code={code}")
        return data

    # ---------- логин ----------
    def login(self):
        # 1) RSA-параметры (nn, ee, seq) для шифрованного канала
        r = self._post(HTTP_OP_GDPRCFG, 0, "get", with_id=False)
        err, data = self._split_err(r.text)
        lines = data.replace("\r\n", "\n").rstrip("\n").split("\n")
        self.ee, self.nn, self.seq = lines[0], lines[1], int(lines[2])

        # 2) authInfo (ключи securityEncode) — из 401-ответа
        r = self._post(TDDP_AUTH, 1, "", with_id=False)
        _, data = self._split_err(r.text)
        a = data.rstrip("\r\n").split("\r\n")
        auth3, auth4 = a[2], a[3]

        # 3) AES-ключ сессии + хеш
        self.aes_key = (str(int(time.time() * 1000)) + str(random.random() * 1e9))[:16]
        self.aes_iv = (str(int(time.time() * 1000)) + str(random.random() * 1e9))[:16]
        self.aes_key_string = f"k={self.aes_key}&i={self.aes_iv}"

        # 4) собственно логин. Пароль кодируется ДВАЖДЫ:
        #    сначала doEncrypt (дефолтные ключи), затем challenge auth3/auth4.
        pre = security_encode(self.password)                 # doEncrypt()
        login_id = enc_uri_component(security_encode(auth3, pre, auth4))
        url = f"{self.base}?code={TDDP_AUTH}&asyn=0&id={login_id}"
        r = self.s.post(url, data=b"", timeout=self.timeout)
        err, _ = self._split_err(r.text)
        if r.status_code != 200 or err != 0:
            raise RuntimeError(
                f"Логин отклонён (HTTP {r.status_code}, код {err}). "
                f"Проверьте пароль администратора веб-панели."
            )
        self.session_id = login_id  # сессией служит сам id

        # 5) регистрируем AES-ключ сессии (syncEncryptor)
        enc_aes = self._rsa_encrypt(self.aes_key_string)
        self._post(HTTP_OP_GDPRCFG, 0, "set " + enc_aes)
        return True

    # ---------- разбор блока данных ----------
    @staticmethod
    def _parse_block(text):
        """Разбирает ответ чтения блока в dict. Массивы (hList) -> список dict по индексу."""
        result = {}
        cur = result
        for line in text.replace("\r\n", "\n").split("\n"):
            line = line.rstrip("\r")
            if not line or line == "#":
                continue
            parts = line.split(" ")
            name = parts[0]
            if name == "id":
                continue
            if len(parts) >= 3 and parts[1].isdigit():
                idx = int(parts[1])
                val = unquote(" ".join(parts[2:]))
                arr = cur.setdefault("_arr", {})
                arr.setdefault(idx, {"_slot": idx})[name] = val
            elif len(parts) >= 2:
                cur[name] = unquote(" ".join(parts[1:]))
        arr = cur.pop("_arr", {})
        cur["hList"] = [arr[k] for k in sorted(arr)]
        return cur

    def get_list(self, which="blacklist"):
        block = BLACK_LIST_ID if which == "blacklist" else WHITE_LIST_ID
        data = self._secure_request(TDDP_READ, 1, f"{block}|1,0,0")
        parsed = self._parse_block(data)
        # блок содержит фиксированные 16 слотов; реальные записи — с ненулевым MAC
        return [e for e in parsed.get("hList", [])
                if e.get("hMac") and e["hMac"] != "00-00-00-00-00-00"]

    # ---------- изменение ----------
    def add_mac(self, mac, name="device", dev_type="other", which="blacklist"):
        block = BLACK_LIST_ID if which == "blacklist" else WHITE_LIST_ID
        cmd = (f"advanced bm host -add id:{block} "
               f"name:{enc_uri_component(name)} mac:{mac} devType:{dev_type}")
        self._secure_request(TDDP_INSTRUCT, 0, cmd)
        return True

    def del_mac(self, mac, which="blacklist"):
        block = BLACK_LIST_ID if which == "blacklist" else WHITE_LIST_ID
        want = mac.lower().replace("-", ":")
        match = next((e for e in self.get_list(which)
                      if e.get("hMac", "").lower().replace("-", ":") == want), None)
        if match is None:
            raise RuntimeError(f"MAC {mac} не найден в списке {which}")
        # index — это номер слота (0..15) в блоке, а не позиция в отфильтрованном списке
        cmd = f"advanced bm host -delete id:{block} index:{match['_slot']}"
        self._secure_request(TDDP_INSTRUCT, 0, cmd)
        return True

    # ---------- статус / режим Access Control (блок 31) ----------
    def get_status(self):
        data = self._secure_request(TDDP_READ, 1, f"{BEHAVMANG_ID}|1,0,0")
        b = self._parse_block(data)
        return {"enable": b.get("bhavEnable", "0"), "rule": b.get("bhavRule", "0")}

    def set_status(self, enable=None, rule=None):
        """Чтение-модификация-запись блока 31. Неуказанное поле сохраняется."""
        cur = self.get_status()
        en = cur["enable"] if enable is None else ("1" if enable else "0")
        ru = cur["rule"] if rule is None else str(rule)
        payload = f"id {BEHAVMANG_ID}|1,0,0\r\nbhavEnable {en}\r\nbhavRule {ru}\r\n"
        self._secure_request(TDDP_WRITE, 0, payload)
        return {"enable": en, "rule": ru}


def _normalize_mac(mac):
    h = re.sub(r"[^0-9A-Fa-f]", "", mac)
    if len(h) != 12:
        raise argparse.ArgumentTypeError(f"Некорректный MAC: {mac}")
    return "-".join(h[i:i + 2] for i in range(0, 12, 2)).upper()


def main():
    p = argparse.ArgumentParser(description="TP-Link Access Control")
    p.add_argument("action",
                   choices=["list", "add", "del", "status", "enable", "disable", "mode"])
    p.add_argument("value", nargs="?",
                   help="для mode: blacklist | whitelist")
    p.add_argument("-m", "--mac", type=_normalize_mac, help="MAC-адрес")
    p.add_argument("-n", "--name", default="device", help="Имя устройства (для add)")
    p.add_argument("-t", "--type", default="other", help="Тип: pc|phone|pad|other")
    p.add_argument("-l", "--list", dest="which", default="blacklist",
                   choices=["blacklist", "whitelist"], help="Какой список")
    p.add_argument("--host", default=os.environ.get("TPLINK_HOST"),
                   help="Адрес устройства (env TPLINK_HOST)")
    p.add_argument("--password", default=os.environ.get("TPLINK_PASSWORD"),
                   help="Пароль веб-панели (env TPLINK_PASSWORD)")
    p.add_argument("--debug", action="store_true")
    args = p.parse_args()

    if not args.host:
        p.error("Укажите адрес: --host или переменная окружения TPLINK_HOST")
    if not args.password:
        p.error("Укажите пароль: --password или переменная окружения TPLINK_PASSWORD")
    if args.action in ("add", "del") and not args.mac:
        p.error("Для add/del нужен -m/--mac")
    if args.action == "mode" and args.value not in RULE:
        p.error("Для mode укажите режим: blacklist | whitelist")

    c = TPLinkAC(args.host, args.password, debug=args.debug)
    c.login()

    def show_status():
        s = c.get_status()
        print(f"Access Control: {'ВКЛ' if s['enable'] == '1' else 'ВЫКЛ'} | "
              f"режим: {RULE_NAME.get(s['rule'], s['rule'])}")

    if args.action == "list":
        entries = c.get_list(args.which)
        if not entries:
            print(f"Список {args.which} пуст.")
        for e in entries:
            print(f"{e.get('hMac',''):20} {e.get('hDevType',''):8} {e.get('hName','')}")
    elif args.action == "add":
        c.add_mac(args.mac, args.name, args.type, args.which)
        print(f"Добавлен {args.mac} в {args.which}.")
    elif args.action == "del":
        c.del_mac(args.mac, args.which)
        print(f"Удалён {args.mac} из {args.which}.")
    elif args.action == "status":
        show_status()
    elif args.action == "enable":
        c.set_status(enable=True)
        show_status()
    elif args.action == "disable":
        c.set_status(enable=False)
        show_status()
    elif args.action == "mode":
        c.set_status(rule=RULE[args.value])
        show_status()


if __name__ == "__main__":
    main()
