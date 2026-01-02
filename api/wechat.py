import hashlib
import os
import time
import xml.etree.ElementTree as ET
from http.server import BaseHTTPRequestHandler
from urllib.parse import parse_qs, urlparse

TOKEN = os.getenv("WECHAT_TOKEN", "")


def check_signature(signature: str, timestamp: str, nonce: str) -> bool:
    """Validate WeChat signature using shared token + timestamp + nonce."""
    if not TOKEN:
        return False
    combo = "".join(sorted([TOKEN, timestamp, nonce]))
    return hashlib.sha1(combo.encode()).hexdigest() == signature


def build_reply(to_user: str, from_user: str, content: str) -> str:
    now = int(time.time())
    return f"""<xml>
<ToUserName><![CDATA[{to_user}]]></ToUserName>
<FromUserName><![CDATA[{from_user}]]></FromUserName>
<CreateTime>{now}</CreateTime>
<MsgType><![CDATA[text]]></MsgType>
<Content><![CDATA[{content}]]></Content>
<FuncFlag>0</FuncFlag>
</xml>"""


class handler(BaseHTTPRequestHandler):
    def do_GET(self):
        qs = parse_qs(urlparse(self.path).query)
        signature = qs.get("signature", [""])[0]
        timestamp = qs.get("timestamp", [""])[0]
        nonce = qs.get("nonce", [""])[0]
        echostr = qs.get("echostr", [""])[0]

        if check_signature(signature, timestamp, nonce):
            self.send_response(200)
            self.end_headers()
            self.wfile.write(echostr.encode())
        else:
            self.send_response(403)
            self.end_headers()

    def do_POST(self):
        qs = parse_qs(urlparse(self.path).query)
        signature = qs.get("signature", [""])[0]
        timestamp = qs.get("timestamp", [""])[0]
        nonce = qs.get("nonce", [""])[0]

        if not check_signature(signature, timestamp, nonce):
            self.send_response(403)
            self.end_headers()
            return

        length = int(self.headers.get("content-length", 0))
        raw_xml = self.rfile.read(length).decode()
        if not raw_xml:
            self.send_response(200)
            self.end_headers()
            return

        try:
            post_obj = ET.fromstring(raw_xml)
            from_user = post_obj.findtext("FromUserName", default="")
            to_user = post_obj.findtext("ToUserName", default="")
            keyword = (post_obj.findtext("Content", default="") or "").strip()
        except ET.ParseError:
            self.send_response(400)
            self.end_headers()
            return

        content = "Welcome to wechat world!" if keyword else "Input something..."
        reply = build_reply(from_user, to_user, content)

        self.send_response(200)
        self.send_header("Content-Type", "application/xml")
        self.end_headers()
        self.wfile.write(reply.encode())
