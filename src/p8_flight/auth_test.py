import pyarrow.flight as flight
import pandas as pd
import json
import pyarrow as pa
import time
from datetime import datetime

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

class AuthTestClient:
    def __init__(self, location="grpc://localhost:8815"):
        self.client = flight.connect(location)
        self.test_results = []
    
    def run_test(self, test_name, test_func):
        """运行测试并记录结果"""
        start_time = time.time()
        try:
            test_func()
            duration = time.time() - start_time
            self.test_results.append({
                "name": test_name,
                "status": "通过",
                "duration": duration,
                "error": None
            })
            print(f"✅ {test_name} - 通过 ({duration:.3f}秒)")
        except Exception as e:
            duration = time.time() - start_time
            self.test_results.append({
                "name": test_name,
                "status": "失败",
                "duration": duration,
                "error": str(e)
            })
            print(f"❌ {test_name} - 失败: {str(e)} ({duration:.3f}秒)")
    
    def authenticate(self, username, password):
        """进行身份认证"""
        auth_handler = AuthClientHandler(username, password)
        self.client.authenticate(auth_handler)
        self.token = auth_handler.get_token()
        return self.token
    
    def execute_query(self, query):
        """执行查询操作"""
        descriptor = flight.FlightDescriptor.for_command(query.encode('utf-8'))
        flight_info = self.client.get_flight_info(descriptor)
        
        if not flight_info.endpoints:
            raise Exception("No endpoints returned from server")
        
        endpoint = flight_info.endpoints[0]
        reader = self.client.do_get(endpoint.ticket)
        return reader.read_pandas()
    
    def execute_modification(self, operation, query):
        """执行数据修改操作"""
        try:
            command = {
                "operation": operation,
                "query": query
            }
            command_bytes = json.dumps(command).encode("utf-8")
            descriptor = flight.FlightDescriptor.for_command(command_bytes)
            schema = pa.schema([])
            
            writer, reader = self.client.do_put(descriptor, schema)
            writer.done_writing()
            
            result = reader.read()
            if result:
                response = json.loads(result.to_pybytes().decode("utf-8"))
                if response.get("status") == "error":
                    raise flight.FlightServerError(response.get("message", "Unknown error"))
                return response
            return None
        except flight.FlightServerError:
            raise
        except Exception as e:
            raise flight.FlightServerError(str(e))
    
    def test_valid_auth(self):
        """测试有效认证"""
        token = self.authenticate("admin", "admin123")
        if not token:
            raise Exception("认证失败")
    
    def test_invalid_auth(self):
        """测试无效认证"""
        try:
            self.authenticate("admin", "wrongpass")
            raise Exception("应该拒绝错误的密码")
        except flight.FlightUnauthenticatedError:
            pass  # 预期的错误
    
    def test_admin_permissions(self):
        """测试管理员权限"""
        self.authenticate("admin", "admin123")
        
        # 测试查询
        df = self.execute_query("SELECT * FROM test")
        if len(df) < 1:
            raise Exception("查询失败")
        
        # 测试插入
        response = self.execute_modification(
            "INSERT",
            "INSERT INTO test VALUES (100, 'TestUser')"
        )
        if response["status"] != "success":
            raise Exception("插入失败")
        
        # 测试更新
        response = self.execute_modification(
            "UPDATE",
            "UPDATE test SET name = 'UpdatedUser' WHERE id = 100"
        )
        if response["status"] != "success":
            raise Exception("更新失败")
        
        # 测试删除
        response = self.execute_modification(
            "DELETE",
            "DELETE FROM test WHERE id = 100"
        )
        if response["status"] != "success":
            raise Exception("删除失败")
    
    def test_readonly_permissions(self):
        """测试只读用户权限"""
        self.authenticate("readonly", "read123")
        
        # 测试查询（应该成功）
        df = self.execute_query("SELECT * FROM test")
        if len(df) < 1:
            raise Exception("查询失败")
        
        # 测试插入（应该失败）
        try:
            self.execute_modification(
                "INSERT",
                "INSERT INTO test VALUES (101, 'TestUser')"
            )
        except flight.FlightServerError as e:
            if "Permission denied" not in str(e):
                raise
        else:
            raise Exception("应该拒绝插入操作")
    
    def test_user_permissions(self):
        """测试普通用户权限"""
        self.authenticate("user1", "user123")
        
        # 测试查询
        df = self.execute_query("SELECT * FROM test")
        if len(df) < 1:
            raise Exception("查询失败")
        
        # 测试插入
        response = self.execute_modification(
            "INSERT",
            "INSERT INTO test VALUES (102, 'TestUser')"
        )
        if response["status"] != "success":
            raise Exception("插入失败")
        
        # 测试更新
        response = self.execute_modification(
            "UPDATE",
            "UPDATE test SET name = 'UpdatedUser' WHERE id = 102"
        )
        if response["status"] != "success":
            raise Exception("更新失败")
        
        # 测试删除（应该失败）
        try:
            self.execute_modification(
                "DELETE",
                "DELETE FROM test WHERE id = 102"
            )
        except flight.FlightServerError as e:
            if "Permission denied" not in str(e):
                raise
        else:
            raise Exception("应该拒绝删除操作")
    
    def test_token_reuse(self):
        """测试令牌重用"""
        # 首次认证
        self.authenticate("admin", "admin123")
        first_token = self.token
        
        # 使用相同令牌执行操作
        df = self.execute_query("SELECT * FROM test")
        if len(df) < 1:
            raise Exception("使用首次令牌查询失败")
        
        # 再次认证
        self.authenticate("admin", "admin123")
        second_token = self.token
        
        # 验证令牌不同
        if first_token == second_token:
            raise Exception("新旧令牌不应该相同")
    
    def print_summary(self):
        """打印测试总结"""
        print("\n=== 测试总结 ===")
        total_tests = len(self.test_results)
        passed_tests = sum(1 for r in self.test_results if r["status"] == "通过")
        total_time = sum(r["duration"] for r in self.test_results)
        
        print(f"总测试数: {total_tests}")
        print(f"通过测试: {passed_tests}")
        print(f"失败测试: {total_tests - passed_tests}")
        print(f"总耗时: {total_time:.3f}秒")
        print("\n详细结果:")
        
        for result in self.test_results:
            status_symbol = "✅" if result["status"] == "通过" else "❌"
            print(f"{status_symbol} {result['name']} - {result['status']} ({result['duration']:.3f}秒)")
            if result["error"]:
                print(f"   错误: {result['error']}")
    
    def close(self):
        """关闭连接"""
        self.client.close()

def main():
    client = AuthTestClient()
    try:
        print("\n=== 开始认证测试 ===")
        
        # 运行所有测试
        client.run_test("有效认证测试", client.test_valid_auth)
        client.run_test("无效认证测试", client.test_invalid_auth)
        client.run_test("管理员权限测试", client.test_admin_permissions)
        client.run_test("只读用户权限测试", client.test_readonly_permissions)
        client.run_test("普通用户权限测试", client.test_user_permissions)
        client.run_test("令牌重用测试", client.test_token_reuse)
        
        # 打印测试总结
        client.print_summary()
        
    finally:
        client.close()

if __name__ == "__main__":
    main() 