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

## 2. FastAPI 依赖注入

```python
from typing import Annotated
from fastapi import HTTPException, status, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jwt_auth import (
    jwt_auth,
    AuthFormatError,
    TokenExpiredError,
    TokenInvalidError,
    RefreshTokenExpiredError,
    AuthenticationError
)

security = HTTPBearer()

async def get_current_user(credentials: Annotated[HTTPAuthorizationCredentials, Depends(security)]) -> str:
    """FastAPI 依赖注入：验证并返回当前用户名"""
    auth_header = credentials.credentials
    try:
        return jwt_auth.authenticate(auth_header)
    except AuthFormatError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"code": "AUTH_FORMAT_ERROR", "message": str(e)}
        )
    except TokenExpiredError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"code": "TOKEN_EXPIRED", "message": str(e)}
        )
    except TokenInvalidError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"code": "TOKEN_INVALID", "message": str(e)}
        )
```

## 3. 登录接口

```python
from pydantic import BaseModel
from fastapi import HTTPException, status

class LoginRequest(BaseModel):
    username: str
    password: str

class LoginResponse(BaseModel):
    access_token: str
    refresh_token: str

@app.post("/login", response_model=LoginResponse)
async def login(request: LoginRequest):
    try:
        return jwt_auth.login(request.username, request.password)
    except AuthenticationError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"code": "INVALID_CREDENTIALS", "message": str(e)}
        )
```

## 4. 刷新令牌

```python
from pydantic import BaseModel
from fastapi import HTTPException, status

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
    except RefreshTokenExpiredError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"code": "REFRESH_TOKEN_EXPIRED", "message": str(e)}
        )
    except AuthenticationError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"code": "INVALID_REFRESH_TOKEN", "message": str(e)}
        )
```

## 5. 受保护接口

```python
from typing import Annotated
from pydantic import BaseModel

class UserProfile(BaseModel):
    username: str

@app.get("/profile", response_model=UserProfile)
async def profile(username: Annotated[str, Depends(get_current_user)]):
    return {"username": username}
```

## 6. 前端使用示例

```javascript
async function request(url, options = {}) {
    const response = await fetch(url, {
        ...options,
        headers: {
            ...options.headers,
            'Authorization': 'Bearer ' + localStorage.getItem('access_token')
        }
    });

    if (response.ok) {
        return response.json();
    }

    const data = await response.json();
    const code = data.detail?.code;

    if (code === 'TOKEN_EXPIRED') {
        // 刷新令牌
        const newToken = await refreshToken();
        // 更新本地存储
        localStorage.setItem('access_token', newToken);
        // 重新发起原请求
        return request(url, options);
    }

    if (code === 'REFRESH_TOKEN_EXPIRED') {
        // 跳转登录页
        window.location.href = '/login';
        throw new Error('登录已过期');
    }

    throw new Error(data.detail?.message || '请求失败');
}

// 使用
const profile = await request('/profile');
```
