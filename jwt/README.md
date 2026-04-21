# JWT 认证使用说明

> 单文件实现：`jwt_auth.py`

## 1. 用户字典结构

```python
user_auth = {
    'alice': {'password': '123456', 'refresh_token': None},
    'bob': {'password': 'abcdef', 'refresh_token': None},
}
```

- `sub`：用户名（`username`）
- `exp`：过期时间戳（秒）
- access token 有效期：5 分钟

## 2. 初始化

```python
from jwt_auth import JWTAuth

jwt_auth = JWTAuth(secret='your-secret', expire_seconds=300)  # 300秒=5分钟
```

## 3. 登录接口（用户名/密码 -> access + refresh）

```python
from flask import request, jsonify

@server.post('/login')
def login():
    data = request.get_json(force=True)
    result = jwt_auth.login(data['username'], data['password'], user_auth)
    if result is None:
        return jsonify(error='Invalid username or password'), 401
    return jsonify(result)
```

## 4. 刷新接口（refresh -> 新 access）

```python
@server.post('/refresh')
def refresh():
    data = request.get_json(force=True)
    access_token = jwt_auth.refresh(data['refresh_token'], user_auth)
    if access_token is None:
        return jsonify(error='Invalid refresh token'), 401
    return jsonify(access_token=access_token)
```

## 5. 请求前钩子保护资源（钩子内完成鉴权）

```python
from flask import request, jsonify

@server.before_request
def protected_resource():
    if request.path in {'/login', '/refresh'}:
        return

    auth_header = request.headers.get('Authorization')
    username = jwt_auth.authenticate(auth_header)
    if username is None:
        return jsonify(error='Authentication required'), 401
```

## 6. 业务代码里直接访问用户名

```python
from jwt_auth import jwt_auth

def profile():
    return jwt_auth.user_id
```
