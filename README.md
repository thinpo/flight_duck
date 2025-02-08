# Arrow Flight 认证服务器示例

这个项目展示了如何使用 Apache Arrow Flight 实现一个带有认证和授权功能的数据服务。支持基本认证和 Okta OAuth 认证。

## 功能特性

- 多种认证方式：
  * 基于用户名和密码的基本认证
  * Okta OAuth认证
- 基于角色的数据库访问控制
- 支持多个数据库的数据访问
- 完整的日志记录
- 错误处理和友好的错误提示

## 系统要求

- Python 3.7+
- pyarrow
- pandas
- requests (用于OAuth)
- okta-jwt-verifier (用于OAuth)
- python-dotenv (用于环境变量管理)

## 安装

1. 克隆仓库：
```bash
git clone <repository-url>
cd p8
```

2. 创建并激活虚拟环境：
```bash
python -m venv venv
source venv/bin/activate  # Linux/Mac
# 或
.\venv\Scripts\activate  # Windows
```

3. 安装依赖：
```bash
pip install -r requirements.txt
```

## 使用说明

### 基本认证模式

1. 启动服务器：
```bash
python src/p8_flight/basic_auth_server.py
```

2. 运行测试客户端：
```bash
python src/p8_flight/basic_auth_client.py
```

### OAuth认证模式

1. 配置Okta（在开始之前）：
   - 在Okta开发者控制台创建应用
   - 获取必要的配置信息
   - 创建用户和组

2. 设置环境变量：
   创建 `.env` 文件并添加以下配置：
   ```
   OKTA_DOMAIN=your-domain.okta.com
   OKTA_CLIENT_ID=your-client-id
   OKTA_CLIENT_SECRET=your-client-secret
   OKTA_AUDIENCE=your-audience
   ```

3. 启动OAuth服务器：
```bash
python src/p8_flight/oauth_auth_server.py
```

4. 运行OAuth测试客户端：
```bash
python src/p8_flight/oauth_auth_client.py
```

### 用户角色和权限

#### 基本认证模式

| 用户名 | 密码 | 可访问的数据库 |
|--------|------|----------------|
| admin  | admin123 | db1, db2 |
| user1  | pass1 | db1 |
| user2  | pass2 | db2 |

#### OAuth模式

| Okta组 | 可访问的数据库 |
|--------|----------------|
| admin_role | db1, db2 |
| user_role | db1 |
| readonly_role | db2 |

### 示例数据

系统包含两个示例数据库：

1. db1:
```
   id name
0   1    a
1   2    b
2   3    c
```

2. db2:
```
   id name
0   4    x
1   5    y
2   6    z
```

## API 说明

### 服务器端

#### 基本认证 (BasicAuthServer)
- `BasicAuthHandler`: 处理用户名密码认证
- `BasicAuthServer`: 处理数据请求和访问控制

#### OAuth认证 (OAuthFlightServer)
- `OktaAuthHandler`: 处理OAuth令牌验证
- `OAuthFlightServer`: 处理OAuth认证的数据请求

### 客户端

#### 基本认证 (BasicAuthClient)
- `BasicAuthHandler`: 处理客户端认证
- `BasicAuthClient`: 提供数据访问接口

#### OAuth认证 (OAuthClient)
- `OAuthHandler`: 处理OAuth令牌
- `OAuthClient`: 提供OAuth认证和数据访问

### 认证流程

#### 基本认证流程
1. 客户端发送用户名和密码
2. 服务器验证凭证
3. 服务器生成并返回令牌
4. 客户端使用令牌访问数据

#### OAuth认证流程
1. 客户端从Okta获取访问令牌
2. 客户端发送Bearer令牌到服务器
3. 服务器验证令牌并检查权限
4. 客户端使用验证后的令牌访问数据

### 错误处理

系统会处理以下类型的错误：
- 认证错误（无效的凭证或令牌）
- 权限错误（未授权的数据库访问）
- 连接错误
- 数据访问错误

## 开发说明

### 日志记录

系统使用 Python 的 logging 模块记录操作日志，包括：
- 认证尝试
- 数据访问请求
- 错误和异常

### 扩展建议

1. 添加新的认证方式：
```python
class NewAuthHandler(flight.ServerAuthHandler):
    def __init__(self):
        super().__init__()
        # 初始化认证处理器
```

2. 添加新的权限规则：
```python
auth_handler.user_permissions["new_role"] = ["db1", "db2"]
```

3. 添加新数据库：
```python
server.databases["new_db"] = pa.Table.from_arrays(
    [pa.array([...]), pa.array([...])],
    names=['column1', 'column2']
)
```

## 安全注意事项

- 在生产环境中使用HTTPS/TLS
- 定期轮换Okta客户端密钥
- 实现令牌过期和刷新机制
- 添加请求频率限制
- 启用详细的审计日志

## 故障排除

1. 端口占用错误：
```bash
lsof -i :8815 | grep LISTEN | awk '{print $2}' | xargs kill -9
```

2. OAuth认证失败：
- 检查Okta配置是否正确
- 验证环境变量是否设置
- 检查用户权限和组成员身份

3. 权限错误：
- 检查用户角色映射
- 验证OAuth令牌中的组信息
- 查看服务器日志获取详细信息

## 贡献指南

1. Fork 项目
2. 创建特性分支
3. 提交更改
4. 推送到分支
5. 创建 Pull Request

## 许可证

[MIT License](LICENSE)
