import os
import json 
from fastapi import FastAPI, Request, HTTPException, Cookie
from fastapi.responses import RedirectResponse, Response, JSONResponse
from onelogin.saml2.auth import OneLogin_Saml2_Auth
from urllib.parse import quote, unquote
import uvicorn


app = FastAPI()

# SAMLの設定ファイルが置いてあるフォルダのパス
SAML_PATH = os.path.join(os.path.dirname(__file__), "saml")

async def prepare_saml_request(request: Request) -> dict:
    """FastAPIのリクエストオブジェクトをpython3-samlが処理できる形式に変換する"""
    try:
        form_data = await request.form()
    except Exception:
        form_data = {}
    
    return {
        'https': 'on' if request.url.scheme == 'https' else 'off',
        'http_host': request.headers.get('x-forwarded-host', request.url.netloc),
        'script_name': request.url.path,
        'server_port': str(request.url.port or (443 if request.url.scheme == 'https' else 80)),
        'get_data': dict(request.query_params),
        'post_data': dict(form_data)
    }

@app.get("/")
def index():
    return {"message": "Welcome! Go to /login to trigger SSO."}

@app.get("/api/me")
async def get_me(session_user: str = Cookie(None)):
    """
    ブラウザが自動で連れてくるCookie（session_user）をチェックし、
    ログインしていればそのユーザーID（NameID）を返します。
    """
    if not session_user:
        # クッキーがない、または空の場合は未ログイン状態（401エラー）を返す
        raise HTTPException(status_code=401, detail="Not authenticated")
        
    decoded_cookie = unquote(session_user)
    user_data = json.loads(decoded_cookie)

    return {
        "logged_in": True,
        "user_id": user_data.get("name_id"),  # これでメールアドレスだけを綺麗に取り出せます！
        "attributes": user_data.get("attributes")  # 必要ならIdPからもらったクレーム情報（属性）も一緒に返せます
    }

@app.get("/login")
async def login(request: Request):
    """ログイン開始：IdP（認証プロバイダ）のログイン画面へリダイレクト"""
    req = await prepare_saml_request(request)
    auth = OneLogin_Saml2_Auth(req, custom_base_path=SAML_PATH)
    
    login_url = auth.login()
    return RedirectResponse(url=login_url)

@app.post("/saml/acs")
async def acs(request: Request):
    """Assertion Consumer Service: IdPからログイン後にデータがPOSTされるエンドポイント"""
    req = await prepare_saml_request(request)
    auth = OneLogin_Saml2_Auth(req, custom_base_path=SAML_PATH)
    
    auth.process_response()
    errors = auth.get_errors()
    
    if not errors:
        if auth.is_authenticated():
            user_data = auth.get_attributes()
            name_id = auth.get_nameid()
            cookie_payload = {
                "name_id": name_id,
                "attributes": user_data
            }
            cookie_val = quote(json.dumps(cookie_payload)) 
            response = RedirectResponse(url="/", status_code=303)
            response.set_cookie(
                key="session_user",
                value=cookie_val,
                httponly=True,
                secure=False,
                samesite="lax"
            )
            return response
        else:
            reason = auth.get_last_error_reason()
            print(f"[ACS] Not authenticated. Reason: {reason}")
            raise HTTPException(status_code=401, detail=f"Not authenticated: {reason}")
    else:
        reason = auth.get_last_error_reason()
        print(f"[ACS] SAML errors: {errors}, reason: {reason}")
        raise HTTPException(status_code=400, detail=f"SAML Error: {', '.join(errors)} | {reason}")

@app.get("/metadata")
async def metadata(request: Request):
    """あなたのアプリ（SP）のメタデータXMLを出力するエンドポイント（IdPへの登録用）"""
    req = await prepare_saml_request(request)
    auth = OneLogin_Saml2_Auth(req, custom_base_path=SAML_PATH)
    settings = auth.get_settings()
    metadata = settings.get_sp_metadata()
    errors = settings.validate_metadata(metadata)
    
    if len(errors) == 0:
        return Response(content=metadata, media_type="text/xml")
    else:
        raise HTTPException(status_code=500, detail=f"Metadata Error: {', '.join(errors)}")

if __name__ == '__main__':
    uvicorn.run(app, host="127.0.0.1", port=8001)
