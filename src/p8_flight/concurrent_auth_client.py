import pyarrow.flight as flight
import pandas as pd
import json
import pyarrow as pa
import threading
import time
import random
from concurrent.futures import ThreadPoolExecutor
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

class ConcurrentAuthClient:
    def __init__(self, location="grpc://localhost:8815", username=None, password=None, client_id=None):
        self.client = flight.connect(location)
        self.client_id = client_id
        self.stats = {
            "queries": 0,
            "modifications": 0,
            "errors": 0,
            "total_time": 0
        }
        if username and password:
            self.authenticate(username, password)
    
    def authenticate(self, username, password):
        """进行身份认证"""
        auth_handler = AuthClientHandler(username, password)
        self.client.authenticate(auth_handler)
        self.token = auth_handler.get_token()
        print(f"客户端 {self.client_id} - {username} 认证成功")
    
    def execute_query(self, query):
        """执行查询操作"""
        start_time = time.time()
        try:
            print(f"\n客户端 {self.client_id} 执行查询: {query}")
            descriptor = flight.FlightDescriptor.for_command(query.encode('utf-8'))
            flight_info = self.client.get_flight_info(descriptor)
            
            if not flight_info.endpoints:
                raise Exception("No endpoints returned from server")
            
            endpoint = flight_info.endpoints[0]
            reader = self.client.do_get(endpoint.ticket)
            df = reader.read_pandas()
            
            self.stats["queries"] += 1
            self.stats["total_time"] += time.time() - start_time
            return df
            
        except Exception as e:
            print(f"客户端 {self.client_id} 查询错误: {str(e)}")
            self.stats["errors"] += 1
            self.stats["total_time"] += time.time() - start_time
            raise
    
    def execute_modification(self, operation, query):
        """执行数据修改操作"""
        start_time = time.time()
        try:
            print(f"\n客户端 {self.client_id} 执行{operation}: {query}")
            
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
                print(f"客户端 {self.client_id} 响应: {response}")
                
                self.stats["modifications"] += 1
                self.stats["total_time"] += time.time() - start_time
                return response
                
            return None
            
        except Exception as e:
            print(f"客户端 {self.client_id} 修改错误: {str(e)}")
            self.stats["errors"] += 1
            self.stats["total_time"] += time.time() - start_time
            raise
    
    def close(self):
        """关闭连接"""
        self.client.close()

def random_operation(client):
    """执行随机操作"""
    try:
        # 随机选择操作类型：70%查询，30%修改
        if random.random() < 0.7:
            # 执行查询
            client.execute_query("SELECT * FROM test")
        else:
            # 获取当前数据
            df = client.execute_query("SELECT * FROM test")
            existing_ids = df['id'].tolist()
            
            # 随机选择修改操作类型
            operation = random.choice(['INSERT', 'UPDATE', 'DELETE'])
            
            if operation == 'INSERT':
                # 插入新记录
                new_id = max(existing_ids + [0]) + 1
                name = f"User{new_id}"
                query = f"INSERT INTO test VALUES ({new_id}, '{name}')"
                
            elif operation == 'UPDATE' and existing_ids:
                # 更新现有记录
                target_id = random.choice(existing_ids)
                new_name = f"Updated{target_id}"
                query = f"UPDATE test SET name = '{new_name}' WHERE id = {target_id}"
                
            elif operation == 'DELETE' and existing_ids:
                # 删除记录
                target_id = random.choice(existing_ids)
                query = f"DELETE FROM test WHERE id = {target_id}"
                
            else:
                # 如果没有数据可以更新或删除，执行插入
                new_id = max(existing_ids + [0]) + 1
                name = f"User{new_id}"
                operation = 'INSERT'
                query = f"INSERT INTO test VALUES ({new_id}, '{name}')"
            
            client.execute_modification(operation, query)
            
    except Exception as e:
        print(f"客户端 {client.client_id} 操作错误: {str(e)}")

def client_worker(client_id, username, password, num_operations):
    """客户端工作线程"""
    client = ConcurrentAuthClient(client_id=client_id, username=username, password=password)
    
    try:
        for _ in range(num_operations):
            random_operation(client)
            # 随机等待0-0.5秒
            time.sleep(random.random() * 0.5)
        
        return client.stats
        
    finally:
        client.close()

def run_concurrent_test(num_clients=5, num_operations=10):
    """运行并发测试"""
    print(f"\n=== 开始并发测试 (客户端数: {num_clients}, 每个客户端操作数: {num_operations}) ===")
    start_time = datetime.now()
    
    # 准备用户凭据
    users = [
        ("admin", "admin123"),
        ("user1", "user123"),
        ("readonly", "read123")
    ]
    
    # 创建线程池
    with ThreadPoolExecutor(max_workers=num_clients) as executor:
        # 提交任务
        futures = []
        for i in range(num_clients):
            username, password = random.choice(users)  # 随机选择用户
            future = executor.submit(client_worker, i+1, username, password, num_operations)
            futures.append(future)
        
        # 收集结果
        total_stats = {
            "queries": 0,
            "modifications": 0,
            "errors": 0,
            "total_time": 0
        }
        
        for future in futures:
            stats = future.result()
            for key in total_stats:
                total_stats[key] += stats[key]
    
    end_time = datetime.now()
    duration = end_time - start_time
    
    # 打印统计信息
    print("\n=== 测试结果 ===")
    print(f"总耗时: {duration}")
    print(f"总查询次数: {total_stats['queries']}")
    print(f"总修改次数: {total_stats['modifications']}")
    print(f"总错误次数: {total_stats['errors']}")
    print(f"平均操作耗时: {total_stats['total_time'] / (total_stats['queries'] + total_stats['modifications']):.3f}秒")
    print(f"每秒操作数: {(total_stats['queries'] + total_stats['modifications']) / duration.total_seconds():.2f}")

def main():
    # 运行并发测试
    run_concurrent_test(num_clients=5, num_operations=10)

if __name__ == "__main__":
    main() 