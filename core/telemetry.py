"""Aodı-AetherOS — telemetry funnel. NEVER blocks: daemon threads only."""
import json
import threading
import urllib.parse
import urllib.request

import storage


def _targets():
    import config
    if config.RELAY_URL:
        yield ("relay", config.RELAY_URL, None)
    token = __import__("os").environ.get("AE_TELEGRAM_TOKEN", "")
    chat = __import__("os").environ.get("AE_TELEGRAM_CHAT", "")
    if token and chat:
        yield ("direct", "https://api.telegram.org/bot%s/sendMessage?"
               "chat_id=%s" % (token, chat), None)


def emit(tag, level, message):
    record = {"tag": tag, "level": level, "message": message[:280]}
    storage.log_event(tag, level, record["message"])
    threading.Thread(target=_fire, args=(record,), daemon=True).start()


def _fire(record):
    for kind, url, _payload in _targets():
        try:
            if kind == "relay":
                data = json.dumps(record).encode("utf-8")
                req = urllib.request.Request(
                    url, data=data, method="POST",
                    headers={"Content-Type": "application/json"})
                urllib.request.urlopen(req, timeout=4).read()
            else:
                text = ("[%s] AetherOS#%s\n%s" %
                        (record["level"].upper(), record["tag"],
                         record["message"]))
                urllib.request.urlopen(
                    url + "&text=" + urllib.parse.quote(text),
                    timeout=4).read()
        except Exception:
            pass
