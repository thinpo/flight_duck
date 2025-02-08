import pyarrow as pa
import pyarrow.flight as flight
import logging
import json
import requests
from okta_jwt_verifier import JWTVerifier
from datetime import datetime, timedelta

# Configure logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class OktaAuthHandler(flight.ServerAuthHandler):
    """Okta OAuth Authentication Handler"""
    def __init__(self, okta_domain, client_id, client_secret, audience):
        super().__init__()
        self.okta_domain = okta_domain
        self.client_id = client_id
        self.client_secret = client_secret
        self.audience = audience
        self.jwt_verifier = JWTVerifier(
            issuer=f"https://{okta_domain}/oauth2/default",
            client_id=client_id,
            audience=audience
        )
        # User permissions mapping
        self.user_permissions = {
            "admin_role": ["db1", "db2"],
            "user_role": ["db1"],
            "readonly_role": ["db2"]
        }
        # Token cache
        self.token_cache = {}
    
    def verify_token(self, token):
        """Verify JWT token"""
        try:
            # Verify token synchronously
            jwt_token = self.jwt_verifier.verify_access_token_sync(token)
            return jwt_token
        except Exception as e:
            logger.error(f"Token verification failed: {e}")
            return None
    
    def authenticate(self, outgoing, incoming):
        """Handle authentication request"""
        try:
            auth_data = incoming.read()
            if not auth_data:
                raise flight.FlightUnauthenticatedError("No credentials")
            
            # Parse authentication data
            auth_str = auth_data.decode('utf-8')
            auth_type, token = auth_str.split(' ', 1)
            
            if auth_type.lower() != 'bearer':
                raise flight.FlightUnauthenticatedError("Invalid authentication type")
            
            # Verify token
            jwt_token = self.verify_token(token)
            if not jwt_token:
                raise flight.FlightUnauthenticatedError("Invalid token")
            
            # Get user roles
            roles = jwt_token.get('groups', [])
            if not roles:
                raise flight.FlightUnauthenticatedError("No roles found in token")
            
            # Cache token information
            self.token_cache[token] = {
                'roles': roles,
                'exp': jwt_token['exp']
            }
            
            # Return token
            outgoing.write(token.encode())
            logger.info(f"Authentication successful for user with roles: {roles}")
            
        except Exception as e:
            logger.error(f"Authentication error: {e}")
            raise
    
    def is_valid(self, token):
        """Validate token"""
        try:
            if not token:
                return None
            
            token_str = token.decode()
            token_info = self.token_cache.get(token_str)
            
            if not token_info:
                return None
            
            # Check if token is expired
            if datetime.utcnow().timestamp() > token_info['exp']:
                del self.token_cache[token_str]
                return None
            
            return token
            
        except Exception as e:
            logger.error(f"Token validation error: {e}")
            return None
    
    def get_user_permissions(self, token):
        """Get user permissions"""
        if not token:
            return []
        
        token_str = token.decode()
        token_info = self.token_cache.get(token_str)
        if not token_info:
            return []
        
        permissions = set()
        for role in token_info['roles']:
            if role in self.user_permissions:
                permissions.update(self.user_permissions[role])
        
        return list(permissions)

class OAuthFlightServer(flight.FlightServerBase):
    """OAuth-enabled Flight Server"""
    def __init__(self, location="grpc://localhost:8815", 
                 okta_domain=None, client_id=None, 
                 client_secret=None, audience=None):
        auth_handler = OktaAuthHandler(
            okta_domain=okta_domain,
            client_id=client_id,
            client_secret=client_secret,
            audience=audience
        )
        super().__init__(location, auth_handler=auth_handler)
        
        # Create sample data
        self.databases = {
            "db1": pa.Table.from_arrays(
                [pa.array([1, 2, 3]), pa.array(['a', 'b', 'c'])],
                names=['id', 'name']
            ),
            "db2": pa.Table.from_arrays(
                [pa.array([4, 5, 6]), pa.array(['x', 'y', 'z'])],
                names=['id', 'name']
            )
        }
    
    def do_get(self, context, ticket):
        """Handle data retrieval request"""
        try:
            # Get user identity
            token = context.peer_identity()
            if not token:
                raise flight.FlightUnauthenticatedError("Authentication required")
            
            # Get requested database
            db_name = ticket.ticket.decode()
            
            # Check permissions
            permissions = self.auth_handler.get_user_permissions(token)
            if db_name not in permissions:
                raise flight.FlightServerError(f"Access denied to database {db_name}")
            
            # Return data
            return flight.RecordBatchStream(self.databases[db_name])
            
        except Exception as e:
            logger.error(f"Error in do_get: {e}")
            raise
    
    def get_flight_info(self, context, descriptor):
        """Handle Flight info request"""
        try:
            # Get user identity
            token = context.peer_identity()
            if not token:
                raise flight.FlightUnauthenticatedError("Authentication required")
            
            # Get requested database
            db_name = descriptor.command.decode()
            
            # Check permissions
            permissions = self.auth_handler.get_user_permissions(token)
            if db_name not in permissions:
                raise flight.FlightServerError(f"Access denied to database {db_name}")
            
            # Return data info
            data = self.databases[db_name]
            return flight.FlightInfo(
                data.schema,
                descriptor,
                [flight.FlightEndpoint(descriptor.command, [])],
                data.num_rows,
                data.nbytes
            )
            
        except Exception as e:
            logger.error(f"Error in get_flight_info: {e}")
            raise

def main():
    # Get Okta configuration from environment variables
    import os
    okta_config = {
        'okta_domain': os.getenv('OKTA_DOMAIN'),
        'client_id': os.getenv('OKTA_CLIENT_ID'),
        'client_secret': os.getenv('OKTA_CLIENT_SECRET'),
        'audience': os.getenv('OKTA_AUDIENCE')
    }
    
    # Validate configuration
    missing_configs = [k for k, v in okta_config.items() if not v]
    if missing_configs:
        raise ValueError(f"Missing Okta configurations: {', '.join(missing_configs)}")
    
    try:
        logger.info("Starting OAuth Flight server on port 8815...")
        server = OAuthFlightServer(**okta_config)
        server.serve()
    except Exception as e:
        logger.error(f"Server error: {e}")
        raise
    finally:
        logger.info("Server stopped")

if __name__ == "__main__":
    main() 