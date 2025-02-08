import pyarrow.flight as flight
import logging
import requests
import os

# Configure logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class OAuthHandler(flight.ClientAuthHandler):
    """OAuth Client Authentication Handler"""
    def __init__(self, token):
        super().__init__()
        self.token = token
        self.bearer_token = None
    
    def authenticate(self, outgoing, incoming):
        """Send authentication information"""
        auth_str = f"Bearer {self.token}"
        outgoing.write(auth_str.encode())
        self.bearer_token = incoming.read()
    
    def get_token(self):
        """Get authentication token"""
        return self.bearer_token

class OAuthClient:
    def __init__(self, location="grpc://localhost:8815"):
        self.client = flight.FlightClient(location)
        self.okta_domain = os.getenv('OKTA_DOMAIN')
        self.client_id = os.getenv('OKTA_CLIENT_ID')
        self.client_secret = os.getenv('OKTA_CLIENT_SECRET')
        self.token = None
    
    def get_token_from_okta(self, username, password):
        """Get access token from Okta"""
        token_url = f"https://{self.okta_domain}/oauth2/default/v1/token"
        
        # Prepare request data
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
        """Perform authentication"""
        try:
            # Get token from Okta
            self.token = self.get_token_from_okta(username, password)
            
            # Use token for Flight authentication
            auth_handler = OAuthHandler(self.token)
            self.client.authenticate(auth_handler)
            logger.info(f"Authenticated as {username}")
            
        except Exception as e:
            logger.error(f"Authentication error: {e}")
            raise
    
    def get_data(self, db_name):
        """Get data from server"""
        try:
            # Create request
            flight_desc = flight.FlightDescriptor.for_command(db_name.encode())
            
            # Get Flight info
            flight_info = self.client.get_flight_info(flight_desc)
            
            # Get data
            reader = self.client.do_get(flight_info.endpoints[0].ticket)
            table = reader.read_all()
            
            return table
        except Exception as e:
            logger.error(f"Error getting data: {e}")
            raise

def test_client():
    """Test client functionality"""
    # Validate environment variables
    required_env_vars = ['OKTA_DOMAIN', 'OKTA_CLIENT_ID', 'OKTA_CLIENT_SECRET']
    missing_vars = [var for var in required_env_vars if not os.getenv(var)]
    if missing_vars:
        raise ValueError(f"Missing environment variables: {', '.join(missing_vars)}")
    
    client = OAuthClient()
    
    # Test cases
    test_cases = [
        {
            'username': 'admin@example.com',
            'password': 'admin_password',
            'databases': ['db1', 'db2'],
            'description': 'Admin user (full access)'
        },
        {
            'username': 'user@example.com',
            'password': 'user_password',
            'databases': ['db1'],
            'description': 'Regular user (db1 access only)'
        },
        {
            'username': 'readonly@example.com',
            'password': 'readonly_password',
            'databases': ['db2'],
            'description': 'Read-only user (db2 access only)'
        }
    ]
    
    for test_case in test_cases:
        print(f"\nTest case: {test_case['description']}")
        try:
            # Authenticate
            client.authenticate(test_case['username'], test_case['password'])
            
            # Test database access
            for db_name in test_case['databases']:
                try:
                    table = client.get_data(db_name)
                    print(f"\nSuccessfully accessed database {db_name}:")
                    print(table.to_pandas())
                except Exception as e:
                    print(f"Failed to access database {db_name}: {str(e)}")
                    
        except Exception as e:
            print(f"Authentication failed: {str(e)}")

if __name__ == "__main__":
    test_client() 