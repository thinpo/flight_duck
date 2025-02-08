import pyarrow.flight as flight
import pandas as pd
import json
import pyarrow as pa

class AuthClientHandler(flight.ClientAuthHandler):
    """Flight客户端认证处理器"""
    
    def __init__(self, username, password):
        super().__init__()
        self.username = username
        self.password = password
        self.token = None
    
    def authenticate(self, outgoing, incoming):
        """发送认证信息"""
        auth_data = {
            "username": self.username,
            "password": self.password
        }
        outgoing.write(json.dumps(auth_data).encode())
        self.token = incoming.read()
    
    def get_token(self):
        """获取认证令牌"""
        return self.token

class AuthenticatedFlightClient:
    def __init__(self, location="grpc://localhost:8815", username=None, password=None):
        self.client = flight.connect(location)
        if username and password:
            self.authenticate(username, password)
    
    def authenticate(self, username, password):
        """进行身份认证"""
        auth_handler = AuthClientHandler(username, password)
        self.client.authenticate(auth_handler)
        self.token = auth_handler.get_token()
        print(f"认证成功: {username}")
    
    def execute_query(self, query):
        """执行查询操作"""
        print(f"\n执行查询: {query}")
        descriptor = flight.FlightDescriptor.for_command(query.encode('utf-8'))
        flight_info = self.client.get_flight_info(descriptor)
        
        # 获取第一个endpoint的ticket
        if not flight_info.endpoints:
            raise Exception("No endpoints returned from server")
        
        endpoint = flight_info.endpoints[0]
        reader = self.client.do_get(endpoint.ticket)
        return reader.read_pandas()
    
    def execute_modification(self, operation, query):
        """执行数据修改操作"""
        print(f"\n执行{operation}: {query}")
        
        # 准备命令
        command = {
            "operation": operation,
            "query": query
        }
        command_bytes = json.dumps(command).encode("utf-8")
        
        # 发送修改请求
        descriptor = flight.FlightDescriptor.for_command(command_bytes)
        
        # 创建一个空的 schema
        schema = pa.schema([])
        
        # 获取响应
        writer, reader = self.client.do_put(descriptor, schema)
        writer.done_writing()
        
        # 读取结果
        result = reader.read()
        if result:
            response = json.loads(result.to_pybytes().decode("utf-8"))
            print(f"响应: {response}")
            return response
        return None
    
    def close(self):
        """关闭连接"""
        self.client.close()

def test_admin():
    """测试管理员权限"""
    print("\n=== 测试管理员权限 ===")
    client = AuthenticatedFlightClient()
    
    try:
        # 管理员登录
        client.authenticate("admin", "admin123")
        
        # 1. 查看初始数据
        print("\n初始数据:")
        df = client.execute_query("SELECT * FROM test")
        print(df)
        
        # 2. 插入新数据
        client.execute_modification(
            "INSERT",
            "INSERT INTO test VALUES (3, 'Charlie')"
        )
        
        # 3. 更新数据
        client.execute_modification(
            "UPDATE",
            "UPDATE test SET name = 'Charles' WHERE id = 3"
        )
        
        # 4. 删除数据
        client.execute_modification(
            "DELETE",
            "DELETE FROM test WHERE id = 3"
        )
        
        # 5. 查看最终数据
        print("\n最终数据:")
        df = client.execute_query("SELECT * FROM test")
        print(df)
        
    finally:
        client.close()

def test_readonly():
    """测试只读用户权限"""
    print("\n=== 测试只读用户权限 ===")
    client = AuthenticatedFlightClient()
    
    try:
        # 只读用户登录
        client.authenticate("readonly", "read123")
        
        # 1. 查看数据（应该成功）
        print("\n查询数据:")
        df = client.execute_query("SELECT * FROM test")
        print(df)
        
        # 2. 尝试插入数据（应该失败）
        try:
            client.execute_modification(
                "INSERT",
                "INSERT INTO test VALUES (4, 'Dave')"
            )
        except Exception as e:
            print(f"\n预期的权限错误: {str(e)}")
        
    finally:
        client.close()

def test_invalid_auth():
    """测试无效认证"""
    print("\n=== 测试无效认证 ===")
    client = AuthenticatedFlightClient()
    
    try:
        # 尝试使用错误的密码登录
        try:
            client.authenticate("admin", "wrongpass")
        except Exception as e:
            print(f"\n预期的认证错误: {str(e)}")
        
    finally:
        client.close()

def main():
    # 测试不同用户场景
    test_admin()
    test_readonly()
    test_invalid_auth()

if __name__ == "__main__":
    main() 