# 认证和并发的Arrow Flight服务

这是一个基于Apache Arrow Flight的数据服务系统，实现了认证、权限控制和并发访问功能。

## 功能特点

1. 认证系统
   - 支持多用户认证
   - 基于令牌的身份验证
   - 令牌自动过期（1小时）

2. 权限控制
   - 三种用户角色：
     * admin：完整权限（读、写、删除）
     * user1：基本权限（读、写）
     * readonly：只读权限
   - 细粒度的操作权限控制
   - 安全的权限检查机制

3. 并发控制
   - 连接池管理
   - 线程池处理并发请求
   - 事务级别的原子性保证
   - 支持多客户端并发访问

4. 数据操作
   - 支持基本的CRUD操作
   - 查询（SELECT）
   - 插入（INSERT）
   - 更新（UPDATE）
   - 删除（DELETE）

## 系统要求

- Python 3.7+
- pyarrow
- pandas
- duckdb

## 安装

```bash
pip install pyarrow pandas duckdb
```

## 使用方法

1. 启动服务器：
```bash
python src/p8_flight/auth_server.py
```

2. 运行基本测试：
```bash
python src/p8_flight/auth_client.py
```

3. 运行并发测试：
```bash
python src/p8_flight/concurrent_auth_client.py
```

## 用户凭据

1. 管理员用户
   - 用户名：admin
   - 密码：admin123
   - 权限：读、写、删除

2. 普通用户
   - 用户名：user1
   - 密码：user123
   - 权限：读、写

3. 只读用户
   - 用户名：readonly
   - 密码：read123
   - 权限：只读

## 性能指标

在标准测试环境下（5个并发客户端，每个执行10个操作）：
- 平均操作耗时：~3ms
- 吞吐量：~20-25 ops/s
- 查询比例：70%
- 修改比例：30%

## 安全特性

1. 密码安全
   - 密码使用SHA-256哈希存储
   - 不存储明文密码

2. 令牌管理
   - 基于随机生成的安全令牌
   - 令牌自动过期机制
   - 令牌验证和权限检查

3. 并发安全
   - 连接池管理
   - 原子性操作保证
   - 事务级别的一致性

## 项目结构

```
src/p8_flight/
├── auth_server.py      # 认证服务器实现
├── auth_client.py      # 基本认证客户端
└── concurrent_auth_client.py  # 并发测试客户端
```

## 开发说明

1. 服务器组件
   - `AuthHandler`：处理认证和权限
   - `DuckDBConnectionPool`：管理数据库连接
   - `AuthenticatedFlightServer`：主服务器实现

2. 客户端组件
   - `AuthClientHandler`：客户端认证处理
   - `AuthenticatedFlightClient`：基本客户端实现
   - `ConcurrentAuthClient`：并发测试客户端

## 注意事项

1. 数据库文件默认保存在 `data/test.db`
2. 服务器默认监听 `localhost:8815`
3. 建议在生产环境中修改默认密码
4. 可以通过修改服务器参数调整并发度
