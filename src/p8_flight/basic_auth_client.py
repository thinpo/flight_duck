import pyarrow.flight as flight
import logging

# 配置日志
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class BasicAuthHandler(flight.ClientAuthHandler):
    """基本认证处理器"""
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

class BasicAuthClient:
    def __init__(self, location="grpc://localhost:8815"):
        self.client = flight.FlightClient(location)
        self.username = None
    
    def authenticate(self, username, password):
        """进行认证"""
        try:
            auth_handler = BasicAuthHandler(username, password)
            self.client.authenticate(auth_handler)
            self.username = username
            logger.info(f"Authenticated as {username}")
        except Exception as e:
            logger.error(f"Authentication error: {e}")
            raise
    
    def get_data(self, db_name):
        """获取数据"""
        try:
            # 创建请求
            flight_desc = flight.FlightDescriptor.for_command(db_name.encode())
            
            # 获取Flight信息
            flight_info = self.client.get_flight_info(flight_desc)
            
            # 获取数据
            reader = self.client.do_get(flight_info.endpoints[0].ticket)
            table = reader.read_all()
            
            return table
        except Exception as e:
            logger.error(f"Error getting data: {e}")
            raise

def test_client():
    """测试客户端"""
    client = BasicAuthClient()
    
    # 测试不同用户访问不同数据库
    test_cases = [
        ("admin", "admin123", "db1"),  # 管理员访问db1（允许）
        ("admin", "admin123", "db2"),  # 管理员访问db2（允许）
        ("user1", "pass1", "db1"),     # user1访问db1（允许）
        ("user1", "pass1", "db2"),     # user1访问db2（不允许）
        ("user2", "pass2", "db1"),     # user2访问db1（不允许）
        ("user2", "pass2", "db2"),     # user2访问db2（允许）
        ("unknown", "wrong", "db1")    # 未知用户（不允许）
    ]
    
    for username, password, db_name in test_cases:
        print(f"\n测试用例: 用户={username}, 数据库={db_name}")
        try:
            client.authenticate(username, password)
            table = client.get_data(db_name)
            print(f"成功获取数据:")
            print(table.to_pandas())
        except Exception as e:
            print(f"访问失败: {str(e)}")

if __name__ == "__main__":
    test_client() 