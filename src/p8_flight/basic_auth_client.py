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
    """Test client functionality"""
    client = BasicAuthClient()
    
    # Test different users accessing different databases
    test_cases = [
        ("admin", "admin123", "db1"),  # Admin accessing db1 (allowed)
        ("admin", "admin123", "db2"),  # Admin accessing db2 (allowed)
        ("user1", "pass1", "db1"),     # user1 accessing db1 (allowed)
        ("user1", "pass1", "db2"),     # user1 accessing db2 (not allowed)
        ("user2", "pass2", "db1"),     # user2 accessing db1 (not allowed)
        ("user2", "pass2", "db2"),     # user2 accessing db2 (allowed)
        ("unknown", "wrong", "db1")    # Unknown user (not allowed)
    ]
    
    for username, password, db_name in test_cases:
        print(f"\nTest case: user={username}, database={db_name}")
        try:
            client.authenticate(username, password)
            table = client.get_data(db_name)
            print(f"Successfully retrieved data:")
            print(table.to_pandas())
        except Exception as e:
            print(f"Access failed: {str(e)}")

if __name__ == "__main__":
    test_client() 