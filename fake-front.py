import httpx
from fastapi import FastAPI, Request, Response
from fastapi.responses import FileResponse
import os

app = FastAPI()

BACKEND_API_SERVER = "http://127.0.0.1:8001"
STATIC_DIR = "./public"
ROUTED_PREFIXES = ("/api/", "/login", "/saml/", "/metadata")

# httpxの非同期クライアントを作成（接続を使い回すので高速）
client = httpx.AsyncClient()

@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"])
async def catch_all_balancer(request: Request, path: str):
    full_path = f"/{path}"
    
    # 1. パス判定（指定プレフィックスならFastAPIへフォワード）
    if any(full_path.startswith(prefix) for prefix in ROUTED_PREFIXES):
        target_url = f"{BACKEND_API_SERVER}{full_path}"
        if request.query_params:
            target_url += f"?{request.query_params}"
            
        print(f"[ASGI] Forwarding {request.method} {full_path} -> {target_url}")
        
        # クライアントからのリクエストデータを準備
        body = await request.body()
        headers = {k: v for k, v in request.headers.items() if k.lower() != 'host'}
        
        # バックエンドに非同期でリクエストを転送 (リダイレクトは追跡しない)
        try:
            backend_response = await client.request(
                method=request.method,
                url=target_url,
                headers=headers,
                content=body,
                follow_redirects=False # 303リダイレクトを勝手に追わせない
            )
        except httpx.ConnectError:
            return Response(content="Error: Bad Gateway(API Server offline)", status_code=502)

        # バックエンドからのレスポンスヘッダーをコピー
        response_headers = dict(backend_response.headers)
        
        # リダイレクトポートの書き換え (8001 -> 8080)
        if "location" in response_headers:
            loc = response_headers["location"]
            response_headers["location"] = loc.replace(":8001", ":8080").replace(":8000", ":8080")

        # ブラウザにレスポンスをそのまま返す
        return Response(
            content=backend_response.content,
            status_code=backend_response.status_code,
            headers=response_headers
        )

    # 2. 静的ファイルの処理（それ以外はローカルファイルを返す）
    else:
        # 安全のためにパスをクレンジングし、実ファイルパスを作る
        filepath = os.path.join(STATIC_DIR, path if path else "index.html")
        if os.path.exists(filepath) and os.path.isfile(filepath):
            return FileResponse(filepath)
        else:
            # index.htmlフォールバック（SPAなどでよく使う挙動）
            fallback = os.path.join(STATIC_DIR, "index.html")
            if os.path.exists(fallback):
                return FileResponse(fallback)
            return Response(content="Not Found", status_code=404)