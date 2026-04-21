# Digest 认证使用说明

## 1. FastAPI HTTP 中间件

```python
from fastapi import Request, Response
from fastapi.responses import JSONResponse
from digest_auth import digest_auth

# 用户数据（实际应使用数据库）
USERS = {
    'alice': 'alice123',
    'bob': 'bob456',
}

def get_user_password(username: str) -> str | None:
    return USERS.get(username)

@app.middleware("http")
async def digest_auth_middleware(request: Request, call_next):
    # 跳过公开接口
    if request.url.path in ['/public']:
        return await call_next(request)

    auth_header = request.headers.get('Authorization')
    username = digest_auth.authenticate(
        auth_header,
        request.method,
        str(request.url.path),
        get_user_password,
    )

    # nonce 过期：返回 stale challenge
    if username is ...:
        return JSONResponse(
            status_code=401,
            content={'error': 'Stale nonce, please retry'},
            headers={'WWW-Authenticate': digest_auth.generate_challenge(is_stale=True)}
        )

    # 认证失败：返回 401 challenge
    if username is None:
        return JSONResponse(
            status_code=401,
            content={'error': 'Authentication required'},
            headers={'WWW-Authenticate': digest_auth.generate_challenge()}
        )

    # 认证成功，将用户名存入请求状态
    request.state.username = username
    return await call_next(request)
```

## 2. 依赖注入获取当前用户

```python
from typing import Annotated
from fastapi import Depends, Request

def get_current_user(request: Request) -> str:
    """从请求状态中获取当前用户名"""
    return request.state.username

@app.get("/profile")
async def profile(username: Annotated[str, Depends(get_current_user)]):
    return {"username": username}
```
