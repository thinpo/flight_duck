import pyarrow as pa
import pyarrow.flight as flight
import logging
import json

# Configure logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class AuthHandler(flight.ServerAuthHandler):
    """Authentication Handler"""
    def __init__(self):
        super().__init__()
        # User database
        self.users = {
            "admin": "admin123",
            "user1": "pass1",
            "user2": "pass2"
        }
        # User permissions
        self.permissions = {
            "admin": ["db1", "db2"],
            "user1": ["db1"],
            "user2": ["db2"]
        }
        # Active tokens
        self.tokens = {}
    
    def authenticate(self, outgoing, incoming):
        """Handle authentication request"""
        try:
            auth_data = incoming.read()
            if not auth_data:
                raise flight.FlightUnauthenticatedError("No credentials")
            
            auth_str = auth_data.decode('utf-8')
            username, password = auth_str.split(':')
            
            if username not in self.users or self.users[username] != password:
                raise flight.FlightUnauthenticatedError("Invalid credentials")
            
            # Use username as token
            token = username.encode()
            self.tokens[token] = username
            outgoing.write(token)
            
        except Exception as e:
            logger.error(f"Authentication error: {e}")
            raise
    
    def is_valid(self, token):
        """Validate token"""
        if not token:
            return None
        return token if token in self.tokens else None
    
    def get_user_permissions(self, token):
        """Get user permissions"""
        if not token:
            return []
        username = self.tokens.get(token)
        return self.permissions.get(username, [])

class FlightServer1(flight.FlightServerBase):
    def __init__(self):
        auth_handler = AuthHandler()
        super().__init__("grpc://localhost:8815", auth_handler=auth_handler)
        
        # Create different databases
        self.databases = {
            "db1": pa.Table.from_arrays(
                [pa.array([1, 2, 3]), pa.array(['db1-a', 'db1-b', 'db1-c'])],
                names=['id', 'name']
            ),
            "db2": pa.Table.from_arrays(
                [pa.array([4, 5, 6]), pa.array(['db2-x', 'db2-y', 'db2-z'])],
                names=['id', 'name']
            )
        }
        logger.info("Server 1 initialized with multiple databases")
    
    def _get_user_from_context(self, context):
        """Get user information from context"""
        if not context.peer_identity():
            raise flight.FlightUnauthenticatedError("No authentication token")
        return self.auth_handler.tokens.get(context.peer_identity())
    
    def do_get(self, context, ticket):
        """Handle data retrieval request"""
        try:
            # Get user information
            username = self._get_user_from_context(context)
            if not username:
                raise flight.FlightUnauthenticatedError("Invalid token")
            
            # Parse requested database
            ticket_data = json.loads(ticket.ticket.decode())
            db_name = ticket_data.get("database")
            
            # Check permissions
            user_permissions = self.auth_handler.get_user_permissions(context.peer_identity())
            if db_name not in user_permissions:
                raise flight.FlightForbiddenError(f"User {username} cannot access database {db_name}")
            
            # Get data
            if db_name not in self.databases:
                raise flight.FlightServerError(f"Database {db_name} not found")
            
            logger.info(f"User {username} accessing database {db_name}")
            return flight.RecordBatchStream(self.databases[db_name])
            
        except Exception as e:
            logger.error(f"Error in do_get: {e}")
            raise
    
    def get_flight_info(self, context, descriptor):
        """Handle Flight information request"""
        try:
            # Get user information
            username = self._get_user_from_context(context)
            if not username:
                raise flight.FlightUnauthenticatedError("Invalid token")
            
            # Parse requested database
            command_data = json.loads(descriptor.command.decode())
            db_name = command_data.get("database")
            
            # Check permissions
            user_permissions = self.auth_handler.get_user_permissions(context.peer_identity())
            if db_name not in user_permissions:
                raise flight.FlightForbiddenError(f"User {username} cannot access database {db_name}")
            
            # Get database information
            if db_name not in self.databases:
                raise flight.FlightServerError(f"Database {db_name} not found")
            
            data = self.databases[db_name]
            logger.info(f"User {username} requesting info for database {db_name}")
            
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
    try:
        logger.info("Starting server 1 on port 8815...")
        server = FlightServer1()
        server.serve()
    except Exception as e:
        logger.error(f"Server 1 error: {e}")
        raise
    finally:
        logger.info("Server 1 stopped")

if __name__ == "__main__":
    main() 