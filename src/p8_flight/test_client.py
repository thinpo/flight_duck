import pyarrow.flight as flight
import logging
import json

# 配置日志
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class ClientAuthHandler(flight.ClientAuthHandler):
    """客户端认证处理器"""
    def __init__(self, username, password):
        super().__init__()
        self.username = username
        self.password = password
        self.token = None
    
    def authenticate(self, outgoing, incoming):
        """发送认证信息"""
        auth = f"{self.username}:{self.password}".encode()
        outgoing.write(auth)
        self.token = incoming.read()
    
    def get_token(self):
        """获取认证令牌"""
        return self.token

def get_data_from_server(username, password, database):
    """使用指定用户身份从服务器获取数据"""
    try:
        # 连接到服务器
        client = flight.FlightClient("grpc://localhost:8815")
        logger.info(f"Connected to server as {username}")
        
        # 进行认证
        auth_handler = ClientAuthHandler(username, password)
        client.authenticate(auth_handler)
        logger.info("Authentication successful")
        
        # 创建查询命令
        command = json.dumps({"database": database}).encode()
        flight_desc = flight.FlightDescriptor.for_command(command)
        
        # 获取数据
        flight_info = client.get_flight_info(flight_desc)
        reader = client.do_get(flight_info.endpoints[0].ticket)
        table = reader.read_all()
        
        print(f"\nData from database {database} (user: {username}):")
        print(table.to_pandas())
        
    except Exception as e:
        logger.error(f"Error accessing database {database} as user {username}: {e}")

def main():
    # 测试不同用户访问不同数据库
    test_cases = [
        ("admin", "admin123", "db1"),  # 管理员访问db1
        ("admin", "admin123", "db2"),  # 管理员访问db2
        ("user1", "pass1", "db1"),     # user1访问db1（允许）
        ("user1", "pass1", "db2"),     # user1访问db2（不允许）
        ("user2", "pass2", "db1"),     # user2访问db1（不允许）
        ("user2", "pass2", "db2"),     # user2访问db2（允许）
        ("unknown", "wrong", "db1"),    # 未知用户（认证失败）
    ]
    
    for username, password, database in test_cases:
        print(f"\n测试用例: 用户={username}, 数据库={database}")
        get_data_from_server(username, password, database)

if __name__ == "__main__":
    main() 