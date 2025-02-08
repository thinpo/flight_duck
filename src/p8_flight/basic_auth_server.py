import pyarrow as pa
import pyarrow.flight as flight
import logging

# Configure logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class BasicAuthHandler(flight.ServerAuthHandler):
    def __init__(self):
        super().__init__()
        # User credentials
        self.users = {
            "admin": "admin123",
            "user1": "pass1",
            "user2": "pass2"
        }
        # User permissions
        self.basic_auth = {
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
            logger.info(f"User {username} authenticated successfully")
            
        except Exception as e:
            logger.error(f"Auth error: {e}")
            raise
    
    def is_valid(self, token):
        """Validate token"""
        try:
            if not token:
                return None
            username = token.decode()
            return token if username in self.basic_auth else None
        except Exception as e:
            logger.error(f"Token validation error: {e}")
            return None

class BasicAuthServer(flight.FlightServerBase):
    def __init__(self, location="grpc://localhost:8815", auth_handler=None):
        super().__init__(location, auth_handler=auth_handler or BasicAuthHandler())
        self.auth_handler = auth_handler or BasicAuthHandler()
        
        # Create example data
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
            # Get user and requested database
            username = context.peer_identity().decode()
            db_name = ticket.ticket.decode()
            
            # Check permissions
            if db_name not in self.auth_handler.basic_auth.get(username, []):
                raise flight.FlightServerError(f"User {username} cannot access {db_name}")
            
            # Return data
            return flight.RecordBatchStream(self.databases[db_name])
        except Exception as e:
            logger.error(f"Error in do_get: {e}")
            raise
    
    def get_flight_info(self, context, descriptor):
        """Handle Flight information request"""
        try:
            # Get user and requested database
            username = context.peer_identity().decode()
            db_name = descriptor.command.decode()
            
            # Check permissions
            if db_name not in self.auth_handler.basic_auth.get(username, []):
                raise flight.FlightServerError(f"User {username} cannot access {db_name}")
            
            # Return data information
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
    try:
        logger.info("Starting basic auth server on port 8815...")
        server = BasicAuthServer()
        server.serve()
    except Exception as e:
        logger.error(f"Server error: {e}")
        raise
    finally:
        logger.info("Server stopped")

if __name__ == "__main__":
    main() 