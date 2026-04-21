# JWT 认证使用说明

## 1. 登录

```python
from jwt_auth import jwt_auth, AuthenticationError

try:
    result = jwt_auth.login('alice', 'alice123')
    # result = {'access_token': '...', 'refresh_token': '...'}
except AuthenticationError:
    # 用户名或密码错误
    pass
```

## 2. 刷新令牌

```python
from jwt_auth import jwt_auth, AuthenticationError, TokenExpiredError

try:
    new_token = jwt_auth.refresh('alice', 'refresh_token_xxx')
except AuthenticationError:
    # 用户名或 refresh_token 错误
    pass
except TokenExpiredError:
    # refresh_token 已过期，需要重新登录
    pass
```

## 3. 获取当前用户

```python
from jwt_auth import jwt_auth

# 在 Flask 请求上下文中使用
username = jwt_auth.user_id  # 从 Authorization 头解析
```

## 4. 配置

```python
from jwt_auth import JWTAuth

jwt_auth = JWTAuth(
    secret='your-secret',           # JWT 密钥
    expire_seconds=300,             # access_token 有效期（秒），默认 5 分钟
    refresh_expire_days=30          # refresh_token 有效期（天），默认 30 天
)
```
