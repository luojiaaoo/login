# JWT 认证使用说明

## 1. 配置

```python
from jwt_auth import JWTAuth

jwt_auth = JWTAuth(
    secret='your-secret',           # JWT 密钥
    expire_seconds=300,             # access_token 有效期（秒），默认 5 分钟
    refresh_expire_days=30          # refresh_token 有效期（天），默认 30 天
)
```

## 2. 登录接口

```python
from pydantic import BaseModel
from fastapi import HTTPException
from jwt_auth import jwt_auth, AuthenticationError

class LoginRequest(BaseModel):
    username: str
    password: str

class LoginResponse(BaseModel):
    access_token: str
    refresh_token: str

@app.post("/login", response_model=LoginResponse)
async def login(request: LoginRequest):
    try:
        result = jwt_auth.login(request.username, request.password)
        return result
    except AuthenticationError:
        raise HTTPException(status_code=401, detail="用户名或密码错误")
```

## 3. 刷新令牌

```python
from pydantic import BaseModel
from fastapi import HTTPException
from jwt_auth import jwt_auth, AuthenticationError, TokenExpiredError

class RefreshRequest(BaseModel):
    username: str
    refresh_token: str

class RefreshResponse(BaseModel):
    access_token: str

@app.post("/refresh", response_model=RefreshResponse)
async def refresh(request: RefreshRequest):
    try:
        access_token = jwt_auth.refresh(request.username, request.refresh_token)
        return {"access_token": access_token}
    except TokenExpiredError:
        raise HTTPException(status_code=401, detail="登录已过期，请重新登录")
    except AuthenticationError:
        raise HTTPException(status_code=401, detail="刷新失败，请重新登录")
```

## 4. 受保护接口

```python
from typing import Annotated
from pydantic import BaseModel
from jwt_auth import jwt_auth

class UserProfile(BaseModel):
    username: str

@app.get("/profile", response_model=UserProfile)
async def profile(username: Annotated[str, Depends(jwt_auth.get_current_user)]):
    return {"username": username}
```
