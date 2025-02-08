import pyarrow as pa
import pyarrow.flight as flight
import duckdb
import threading
import queue
import logging
import json
import os
import base64
import hashlib
import secrets
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor

class AuthHandler(flight.ServerAuthHandler):
    """Flight server authentication processor"""
    
    def __init__(self):
        super().__init__()
        self.logger = logging.getLogger(__name__)
        self.logger.setLevel(logging.DEBUG)
        
        # Add console handler
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.DEBUG)
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        console_handler.setFormatter(formatter)
        self.logger.addHandler(console_handler)
        
        # Simulated user database
        self.users = {
            "admin": "admin123",
            "user1": "user123",
            "readonly": "read123"
        }
        # User permissions
        self.permissions = {
            "admin": ["read", "write", "delete"],
            "user1": ["read", "write"],
            "readonly": ["read"]
        }
        # Active tokens
        self.tokens = {}
    
    def authenticate(self, outgoing, incoming):
        """Handle client authentication"""
        try:
            self.logger.debug("Starting authentication process")
            auth_data = incoming.read()
            
            if not auth_data:
                self.logger.error("No authentication data received")
                raise flight.FlightUnauthenticatedError("No credentials")
            
            self.logger.debug(f"Received auth data: {auth_data}")
            
            try:
                auth_str = auth_data.decode('utf-8')
                self.logger.debug(f"Decoded auth string: {auth_str}")
                
                username, password = auth_str.split(':', 1)
                self.logger.debug(f"Extracted username: {username}")
                
                if not username or not password:
                    self.logger.error("Missing username or password")
                    raise flight.FlightUnauthenticatedError("Invalid credentials format")
                
                stored_password = self.users.get(username)
                if not stored_password:
                    self.logger.error(f"User not found: {username}")
                    raise flight.FlightUnauthenticatedError("Invalid username or password")
                
                if stored_password != password:
                    self.logger.error("Invalid password")
                    raise flight.FlightUnauthenticatedError("Invalid username or password")
                
                # Use username as token
                token = username
                self.tokens[token] = username
                
                self.logger.debug(f"Generated token for user {username}: {token}")
                outgoing.write(token.encode())
                self.logger.info(f"Authentication successful for user: {username}")
                
            except Exception as e:
                self.logger.error(f"Error during authentication: {str(e)}")
                raise flight.FlightUnauthenticatedError(str(e))
                
        except Exception as e:
            self.logger.error(f"Authentication error: {str(e)}")
            raise
    
    def is_valid(self, token):
        """Validate token validity"""
        try:
            self.logger.debug(f"Validating token: {token}")
            
            if not token:
                self.logger.debug("No token provided")
                return None
            
            token_str = token.decode() if isinstance(token, bytes) else str(token)
            self.logger.debug(f"Looking up token: {token_str}")
            
            username = self.tokens.get(token_str)
            if not username:
                self.logger.debug("Token not found")
                return None
            
            self.logger.debug(f"Token valid for user: {username}")
            return token_str.encode()
            
        except Exception as e:
            self.logger.error(f"Token validation error: {str(e)}")
            return None
    
    def get_user_permissions(self, token):
        """Get user permissions"""
        if not token:
            return []
        
        token_str = token.decode() if isinstance(token, bytes) else str(token)
        username = self.tokens.get(token_str)
        if not username:
            return []
        
        return self.permissions.get(username, [])

class DuckDBConnectionPool:
    """DuckDB Connection Pool"""
    def __init__(self, db_path="test.db", max_connections=10):
        self.db_path = db_path
        self.max_connections = max_connections
        self.connections = queue.Queue(maxsize=max_connections)
        self.lock = threading.Lock()
        
        # Ensure database directory exists
        os.makedirs(os.path.dirname(os.path.abspath(db_path)), exist_ok=True)
        
        # Create main database connection and initialize
        self.main_conn = duckdb.connect(db_path)
        self._init_db(self.main_conn)
        
        # Initialize connections in the pool
        for _ in range(max_connections):
            conn = duckdb.connect(db_path)
            self.connections.put(conn)
    
    def _init_db(self, conn):
        """Initialize database schema"""
        with self.lock:
            conn.execute("DROP TABLE IF EXISTS test")
            conn.execute("CREATE TABLE test (id INTEGER, name VARCHAR)")
            conn.execute("INSERT INTO test VALUES (1, 'Alice'), (2, 'Bob')")
    
    def get_connection(self):
        """Get a connection from the pool"""
        try:
            return self.connections.get(timeout=5)
        except queue.Empty:
            raise Exception("Cannot get database connection, pool is full")
    
    def return_connection(self, conn):
        """Return a connection to the pool"""
        self.connections.put(conn)
    
    def close(self):
        """Close all connections"""
        while not self.connections.empty():
            conn = self.connections.get()
            conn.close()
        self.main_conn.close()

class RemoteServerManager:
    """Remote server connection manager"""
    
    def __init__(self):
        self.remote_servers = {}
        self.clients = {}
        self.lock = threading.Lock()
        self.logger = logging.getLogger(__name__)
    
    def add_remote_server(self, server_id, host, port, username=None, password=None):
        """Add remote server configuration"""
        with self.lock:
            self.remote_servers[server_id] = {
                "host": host,
                "port": port,
                "username": username,
                "password": password
            }
    
    def get_client(self, server_id):
        """Get or create a client connection to the remote server"""
        if server_id not in self.clients:
            with self.lock:
                if server_id not in self.clients:
                    server_info = self.remote_servers.get(server_id)
                    if not server_info:
                        raise ValueError(f"Server configuration not found: {server_id}")
                    
                    location = f"grpc://{server_info['host']}:{server_info['port']}"
                    client = flight.FlightClient(location)
                    
                    # If authentication information is provided, authenticate
                    if server_info["username"] and server_info["password"]:
                        auth_data = json.dumps({
                            "username": server_info["username"],
                            "password": server_info["password"]
                        }).encode()
                        writer, reader = client.authenticate_basic_token()
                        writer.write(auth_data)
                        writer.done_writing()
                        token = reader.read()
                        self.logger.info(f"Successfully authenticated with remote server {server_id}")
                    
                    self.clients[server_id] = client
        
        return self.clients[server_id]
    
    def get_remote_data(self, server_id, query):
        """Get data from the remote server"""
        try:
            client = self.get_client(server_id)
            flight_desc = flight.FlightDescriptor.for_command(query)
            
            # Get Flight information
            flight_info = client.get_flight_info(flight_desc)
            
            # Get data
            reader = client.do_get(flight_info.endpoints[0].ticket)
            table = reader.read_all()
            
            return table
        except Exception as e:
            self.logger.error(f"Failed to get data from remote server {server_id}: {str(e)}")
            raise

class AuthenticatedFlightServer(flight.FlightServerBase):
    def __init__(self, location, db_path="test.db", max_workers=10, max_connections=10):
        self.auth_handler = AuthHandler()
        super().__init__(location, auth_handler=self.auth_handler)
        self.location = location
        self.connection_pool = DuckDBConnectionPool(db_path, max_connections)
        self.executor = ThreadPoolExecutor(max_workers=max_workers)
        self.remote_manager = RemoteServerManager()
        self.setup_logging()
    
    def setup_logging(self):
        """Set up logging"""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger(__name__)
    
    def _check_permission(self, context, required_permission):
        """Check user permissions"""
        try:
            peer = context.peer()
            peer_identity = context.peer_identity()
            self.logger.info(f"Peer: {peer}, Identity: {peer_identity}")
            
            if not peer_identity:
                raise flight.FlightUnauthenticatedError("Authentication required")
            
            token_str = peer_identity.decode() if isinstance(peer_identity, bytes) else str(peer_identity)
            permissions = self.auth_handler.get_user_permissions(token_str)
            
            if required_permission not in permissions:
                raise flight.FlightServerError(f"Permission denied: {required_permission} required")
        except Exception as e:
            self.logger.error(f"Permission check failed: {str(e)}")
            raise

    def get_flight_info(self, context, descriptor):
        """Process Flight descriptor and return metadata"""
        self._check_permission(context, "read")
        
        start_time = datetime.now()
        query = descriptor.command.decode("utf-8")
        self.logger.info(f"Received query request: {query}")
        
        conn = self.connection_pool.get_connection()
        try:
            # Get schema from DuckDB
            result = conn.execute(f"SELECT * FROM ({query}) LIMIT 0")
            arrow_table = result.fetch_arrow_table()
            
            # Build Flight information
            ticket = flight.Ticket(descriptor.command)  # Use original command as ticket
            endpoint = flight.FlightEndpoint(
                ticket,
                [flight.Location.for_grpc_tcp("localhost", 8815)]
            )
            
            flight_info = flight.FlightInfo(
                arrow_table.schema,
                descriptor,
                [endpoint],
                -1,
                -1
            )
            
            end_time = datetime.now()
            self.logger.info(f"Query metadata processing completed, time taken: {end_time - start_time}")
            return flight_info
            
        finally:
            self.connection_pool.return_connection(conn)

    def do_get(self, context, ticket):
        """Execute query and return Arrow data stream"""
        self._check_permission(context, "read")
        
        start_time = datetime.now()
        query = ticket.ticket.decode("utf-8")
        self.logger.info(f"Executing query: {query}")
        
        conn = self.connection_pool.get_connection()
        try:
            # Use thread pool to execute query
            future = self.executor.submit(self._execute_query, conn, query)
            table = future.result()
            
            end_time = datetime.now()
            self.logger.info(f"Query execution completed, time taken: {end_time - start_time}")
            return flight.RecordBatchStream(table)
            
        finally:
            self.connection_pool.return_connection(conn)
    
    def do_put(self, context, descriptor, reader, writer):
        """Handle data modification request"""
        start_time = datetime.now()
        try:
            # Parse command
            command = json.loads(descriptor.command.decode("utf-8"))
            operation = command.get("operation")
            query = command.get("query")
            
            # Check permissions
            if operation == "DELETE":
                self._check_permission(context, "delete")
            else:
                self._check_permission(context, "write")
            
            self.logger.info(f"Received data modification request: {operation} - {query}")
            
            conn = self.connection_pool.get_connection()
            try:
                # Get row count before modification
                before_count = conn.execute("SELECT COUNT(*) FROM test").fetchone()[0]
                
                # Execute modification operation
                with self.connection_pool.lock:  # Use lock to ensure atomic modification
                    conn.execute(query)
                
                # Get row count after modification
                after_count = conn.execute("SELECT COUNT(*) FROM test").fetchone()[0]
                
                # Calculate affected rows
                affected_rows = abs(after_count - before_count)
                if operation == "UPDATE":
                    # For UPDATE, we need to execute query to get affected rows
                    if "WHERE" in query.upper():
                        where_clause = query.upper().split("WHERE")[1]
                        affected_rows = conn.execute(f"SELECT COUNT(*) FROM test WHERE {where_clause}").fetchone()[0]
                
                # Return result
                response = {
                    "status": "success",
                    "affected_rows": affected_rows,
                    "message": f"{operation} operation completed successfully"
                }
                
                end_time = datetime.now()
                self.logger.info(f"Data modification completed, time taken: {end_time - start_time}")
                
                # Write response
                writer.write(json.dumps(response).encode("utf-8"))
                
            finally:
                self.connection_pool.return_connection(conn)
                
        except Exception as e:
            error_response = {
                "status": "error",
                "message": str(e)
            }
            writer.write(json.dumps(error_response).encode("utf-8"))
            raise
    
    def _execute_query(self, conn, query):
        """Execute query, support remote data retrieval"""
        try:
            # Check if remote query marker is included
            if "/*remote_server:" in query:
                # Parse remote server ID
                server_id = query[query.find("/*remote_server:") + 15:query.find("*/")].strip()
                # Extract actual query
                actual_query = query[query.find("*/") + 2:].strip()
                
                # Get data from remote server
                self.logger.info(f"Getting data from remote server {server_id}")
                return self.remote_manager.get_remote_data(server_id, actual_query)
            else:
                # Local query
                result = conn.execute(query)
                return result.fetch_arrow_table()
        except Exception as e:
            self.logger.error(f"Query execution failed: {str(e)}")
            raise
    
    def shutdown(self):
        """Shut down server"""
        self.connection_pool.close()
        super().shutdown()

def main():
    # Set server parameters
    max_workers = 10  # Maximum number of worker threads
    max_connections = 10  # Maximum number of database connections
    db_path = "data/test.db"  # Database file path
    
    # Ensure data directory exists
    os.makedirs(os.path.dirname(os.path.abspath(db_path)), exist_ok=True)
    
    server = AuthenticatedFlightServer(
        "grpc://0.0.0.0:8815",
        db_path=db_path,
        max_workers=max_workers,
        max_connections=max_connections
    )
    print(f"Server started on port 8815 (max_workers={max_workers}, max_connections={max_connections})")
    server.serve()

if __name__ == "__main__":
    main() 