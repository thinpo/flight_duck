import pyarrow.flight as flight
import logging
import requests
import os

# 配置日志
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class OAuthHandler(flight.ClientAuthHandler):
    """OAuth客户端认证处理器"""
    def __init__(self, token):
        super().__init__()
        self.token = token
        self.bearer_token = None
    
    def authenticate(self, outgoing, incoming):
        """发送认证信息"""
        auth_str = f"Bearer {self.token}"
        outgoing.write(auth_str.encode())
        self.bearer_token = incoming.read()
    
    def get_token(self):
        """获取认证令牌"""
        return self.bearer_token

class OAuthClient:
    def __init__(self, location="grpc://localhost:8815"):
        self.client = flight.FlightClient(location)
        self.okta_domain = os.getenv('OKTA_DOMAIN')
        self.client_id = os.getenv('OKTA_CLIENT_ID')
        self.client_secret = os.getenv('OKTA_CLIENT_SECRET')
        self.token = None
    
    def get_token_from_okta(self, username, password):
        """从Okta获取访问令牌"""
        token_url = f"https://{self.okta_domain}/oauth2/default/v1/token"
        
        # 准备请求数据
        data = {
            'grant_type': 'password',
            'username': username,
            'password': password,
            'scope': 'openid profile',
            'client_id': self.client_id,
            'client_secret': self.client_secret
        }
        
        try:
            response = requests.post(token_url, data=data)
            response.raise_for_status()
            
            token_data = response.json()
            return token_data['access_token']
            
        except Exception as e:
            logger.error(f"Error getting token from Okta: {e}")
            raise
    
    def authenticate(self, username, password):
        """进行认证"""
        try:
            # 从Okta获取令牌
            self.token = self.get_token_from_okta(username, password)
            
            # 使用令牌进行Flight认证
            auth_handler = OAuthHandler(self.token)
            self.client.authenticate(auth_handler)
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
    # 验证环境变量
    required_env_vars = ['OKTA_DOMAIN', 'OKTA_CLIENT_ID', 'OKTA_CLIENT_SECRET']
    missing_vars = [var for var in required_env_vars if not os.getenv(var)]
    if missing_vars:
        raise ValueError(f"Missing environment variables: {', '.join(missing_vars)}")
    
    client = OAuthClient()
    
    # 测试用例
    test_cases = [
        {
            'username': 'admin@example.com',
            'password': 'admin_password',
            'databases': ['db1', 'db2'],
            'description': '管理员用户（完全访问权限）'
        },
        {
            'username': 'user@example.com',
            'password': 'user_password',
            'databases': ['db1'],
            'description': '普通用户（仅db1访问权限）'
        },
        {
            'username': 'readonly@example.com',
            'password': 'readonly_password',
            'databases': ['db2'],
            'description': '只读用户（仅db2访问权限）'
        }
    ]
    
    for test_case in test_cases:
        print(f"\n测试用例: {test_case['description']}")
        try:
            # 认证
            client.authenticate(test_case['username'], test_case['password'])
            
            # 测试数据库访问
            for db_name in test_case['databases']:
                try:
                    table = client.get_data(db_name)
                    print(f"\n成功访问数据库 {db_name}:")
                    print(table.to_pandas())
                except Exception as e:
                    print(f"访问数据库 {db_name} 失败: {str(e)}")
                    
        except Exception as e:
            print(f"认证失败: {str(e)}")

if __name__ == "__main__":
    test_client() 