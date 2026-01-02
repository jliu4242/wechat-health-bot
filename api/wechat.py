import hashlib
import os
import time
import xml.etree.ElementTree as ET
from fastapi import FastAPI, Request, Response
from mangum import Mangum

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


app = FastAPI()


@app.get("/wechat")
async def verify(signature: str = "", timestamp: str = "", nonce: str = "", echostr: str = ""):
    if check_signature(signature, timestamp, nonce):
        return Response(content=echostr)
    return Response(status_code=403)


@app.post("/wechat")
async def respond(request: Request, signature: str = "", timestamp: str = "", nonce: str = ""):
    if not check_signature(signature, timestamp, nonce):
        return Response(status_code=403)

    raw_xml = await request.body()
    if not raw_xml:
        return Response(content="")

    try:
        post_obj = ET.fromstring(raw_xml.decode())
        from_user = post_obj.findtext("FromUserName", default="")
        to_user = post_obj.findtext("ToUserName", default="")
        keyword = (post_obj.findtext("Content", default="") or "").strip()
    except ET.ParseError:
        return Response(status_code=400)

    content = "Welcome to wechat world!" if keyword else "Input something..."
    reply = build_reply(from_user, to_user, content)
    return Response(content=reply, media_type="application/xml")


# Vercel entrypoint
handler = Mangum(app)
