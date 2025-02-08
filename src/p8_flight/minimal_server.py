import pyarrow as pa
import pyarrow.flight as flight
import logging

# Configure logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class MinimalFlightServer(flight.FlightServerBase):
    def __init__(self):
        super().__init__("grpc://0.0.0.0:8815")
        self.logger = logging.getLogger(__name__)
        
        # Create sample data
        self.data = pa.Table.from_arrays(
            [pa.array([1, 2, 3]), pa.array(['a', 'b', 'c'])],
            names=['id', 'name']
        )
        
        self.logger.debug("Server initialized")
    
    def do_get(self, context, ticket):
        """Handle data retrieval request"""
        self.logger.debug(f"Received get request with ticket: {ticket}")
        return flight.RecordBatchStream(self.data)
    
    def get_flight_info(self, context, descriptor):
        """Handle Flight information request"""
        self.logger.debug(f"Received flight info request with descriptor: {descriptor}")
        
        endpoints = [flight.FlightEndpoint(
            descriptor.command,
            [flight.Location.for_grpc_tcp("localhost", 8815)]
        )]
        
        return flight.FlightInfo(
            self.data.schema,
            descriptor,
            endpoints,
            self.data.num_rows,
            self.data.nbytes
        )

def main():
    try:
        logger.info("Starting server...")
        server = MinimalFlightServer()
        server.serve()
    except Exception as e:
        logger.error(f"Server error: {e}")
        raise
    finally:
        logger.info("Server stopped")

if __name__ == "__main__":
    main() 