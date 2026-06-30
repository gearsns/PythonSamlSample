# fake_idp.py
import uvicorn
from fastapi import FastAPI, Form
from fastapi.responses import HTMLResponse
import base64
import json
import os
from datetime import datetime, timedelta

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
import signxml
import lxml.etree as ET

app = FastAPI()

# 1. テスト用のダミー証明書と秘密鍵をその場で自動生成
private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, u"localhost")])
cert = (
    x509.CertificateBuilder()
    .subject_name(subject)
    .issuer_name(issuer)
    .public_key(private_key.public_key())
    .serial_number(x509.random_serial_number())
    .not_valid_before(datetime.utcnow() - timedelta(days=1))
    .not_valid_after(datetime.utcnow() + timedelta(days=365))
    .sign(private_key, hashes.SHA256())
)

# 署名に埋め込むための証明書テキスト（DER base64 = python3-saml の x509cert 形式）
cert_der = cert.public_bytes(serialization.Encoding.DER)
cert_b64 = base64.b64encode(cert_der).decode("utf-8")

# saml/settings.json の idp.x509cert を今回生成した証明書で上書き
# → fastapi-saml-server.py 側がリクエストごとに settings.json を読むため署名検証が通る
_settings_path = os.path.join(os.path.dirname(__file__), "saml", "settings.json")
with open(_settings_path, "r", encoding="utf-8") as _f:
    _saml_settings = json.load(_f)
_saml_settings["idp"]["x509cert"] = cert_b64
with open(_settings_path, "w", encoding="utf-8") as _f:
    json.dump(_saml_settings, _f, indent="\t", ensure_ascii=False)

# 1. ログイン画面を表示する（GET）
@app.get("/mock/login")
async def show_login_page(SAMLRequest: str = None):
    # 本来はここで「ユーザー名とパスワードを入力する画面」を返す
    # SAMLRequest は隠しパラメーター（hidden）としてフォームに埋め込んでおく
    html = f"""
    <html>
        <body>
            <h1>フェイクIDP ログイン画面</h1>
            <form method="POST" action="/mock/login">
                <input type="hidden" name="SAMLRequest" value="{SAMLRequest or ''}" />
                <p>ユーザーID: <input type="text" name="username" value="test-user@example.com" /></p>
                <p>パスワード: <input type="password" name="password" value="password" /></p>
                <button type="submit">ログイン</button>
            </form>
        </body>
    </html>
    """
    return HTMLResponse(content=html)

# 2. ログインボタンが押された後の処理（POST）
@app.post("/mock/login")
async def do_login(username: str = Form(...), SAMLRequest: str = Form(None)):
   # ここでID/PWをチェックする（モックなのでスルー）

   # 署名付きの SAMLResponse を作成する（質問のコードの処理）
    now = (datetime.utcnow() - timedelta(minutes=5)).strftime("%Y-%m-%dT%H:%M:%SZ")
    expire = (datetime.utcnow() + timedelta(days=365)).strftime("%Y-%m-%dT%H:%M:%SZ")

    # 2. 署名する前の生のXMLの器
    raw_xml = f"""<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="pfx123" Version="2.0" IssueInstant="{now}" Destination="{_saml_settings["sp"]["assertionConsumerService"]["url"]}">
    <saml:Issuer>{_saml_settings["idp"]["entityId"]}</saml:Issuer>
    <samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>
    <saml:Assertion ID="pfx456" Version="2.0" IssueInstant="{now}">
        <saml:Issuer>{_saml_settings["idp"]["entityId"]}</saml:Issuer>
        <saml:Subject>
            <saml:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified">{username}</saml:NameID>
            <saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
                <saml:SubjectConfirmationData Recipient="{_saml_settings["sp"]["assertionConsumerService"]["url"]}" NotOnOrAfter="{expire}"/>
            </saml:SubjectConfirmation>
        </saml:Subject>
        <saml:Conditions NotBefore="{now}" NotOnOrAfter="{expire}">
            <saml:AudienceRestriction>
                <saml:Audience>{_saml_settings["sp"]["entityId"]}</saml:Audience>
            </saml:AudienceRestriction>
        </saml:Conditions>
        <saml:AuthnStatement AuthnInstant="{now}">
            <saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:Password</saml:AuthnContextClassRef></saml:AuthnContext>
        </saml:AuthnStatement>
        <saml:AttributeStatement>
            <!-- ユーザーのフルネームのClaim -->
            <saml:Attribute Name="User.FullName" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic">
                <saml:AttributeValue xsi:type="xs:string" xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">Taro Yamada</saml:AttributeValue>
            </saml:Attribute>
            
            <!-- 所属部署のClaim -->
            <saml:Attribute Name="User.Department" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic">
                <saml:AttributeValue xsi:type="xs:string" xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">Development</saml:AttributeValue>
            </saml:Attribute>

            <!-- ロール（複数値も可能） -->
            <saml:Attribute Name="User.Roles" NameFormat="urn:oasis:names:tc:SAML:2.0:attrname-format:basic">
                <saml:AttributeValue xsi:type="xs:string" xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">admin</saml:AttributeValue>
                <saml:AttributeValue xsi:type="xs:string" xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">developer</saml:AttributeValue>
            </saml:Attribute>
        </saml:AttributeStatement>
    </saml:Assertion>
</samlp:Response>"""

    # 3. XMLに電子署名をガチで付与する（Response全体に署名）
    root = ET.fromstring(raw_xml.encode("utf-8"))
    signed_root = signxml.XMLSigner().sign(root, key=private_key, cert=[cert])
    signed_xml = ET.tostring(signed_root, encoding="utf-8")

    # 4. ベース64エンコード
    saml_response_encoded = base64.b64encode(signed_xml).decode("utf-8")

    # 5. 自動POSTで送り返す
    html_content = f"""
    <html>
        <body onload="document.forms[0].submit()">
            <p>トップ画面に自動でリダイレクト</p>
            <form method="POST" action="{_saml_settings["sp"]["assertionConsumerService"]["url"]}">
                <input type="hidden" name="SAMLResponse" value="{saml_response_encoded}" />
                <button>Login</button>
            </form>
        </body>
    </html>
    """
    return HTMLResponse(content=html_content)

if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=9000)