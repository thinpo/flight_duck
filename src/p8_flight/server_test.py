import os
import time
import logging
import pyarrow.flight as flight
from auth_server import AuthenticatedFlightServer
import threading

# 配置日志
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def run_server(port, db_path):
    """Run server"""
    try:
        server = AuthenticatedFlightServer(
            f"grpc://localhost:{port}",
            db_path=db_path,
            max_workers=5,
            max_connections=5
        )
        server.serve()
    except Exception as e:
        logger.error(f"Server error: {e}")

def test_remote_query():
    """Test remote query"""
    try:
        # Connect to server
        client = flight.FlightClient("grpc://localhost:8815")
        
        # Authenticate
        auth = b"admin:admin123"
        client.authenticate_basic_token(auth)
        
        # Execute query
        query = "SELECT * FROM test"
        flight_desc = flight.FlightDescriptor.for_command(query)
        
        # Get Flight information
        flight_info = client.get_flight_info(flight_desc)
        
        # Get data
        reader = client.do_get(flight_info.endpoints[0].ticket)
        table = reader.read_all()
        
        print("\nQuery result:")
        print(table.to_pandas())
        
    except Exception as e:
        logger.error(f"Test error: {e}")

def main():
    # Create data directory
    os.makedirs("data", exist_ok=True)
    
    # Start server
    server_thread = threading.Thread(
        target=run_server,
        args=(8815, "data/test.db")
    )
    server_thread.daemon = True
    
    try:
        logger.info("Starting server...")
        server_thread.start()
        
        # Wait for server to start
        time.sleep(2)
        
        # Run tests
        logger.info("Running test...")
        test_remote_query()
        
        # Keep main thread running
        while True:
            time.sleep(1)
            
    except KeyboardInterrupt:
        logger.info("Shutting down...")
    except Exception as e:
        logger.error(f"Main error: {e}")

if __name__ == "__main__":
    main() 