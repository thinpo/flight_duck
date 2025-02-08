import pyarrow as pa
import pyarrow.flight as flight
import logging

# 配置日志
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class FlightServer2(flight.FlightServerBase):
    def __init__(self):
        super().__init__("grpc://localhost:8816")
        # 创建服务器2的示例数据
        self.data = pa.Table.from_arrays(
            [pa.array([4, 5, 6]), pa.array(['server2-x', 'server2-y', 'server2-z'])],
            names=['id', 'name']
        )
        logger.info("Server 2 initialized")
    
    def do_get(self, context, ticket):
        logger.info("Server 2 handling get request")
        return flight.RecordBatchStream(self.data)
    
    def get_flight_info(self, context, descriptor):
        logger.info("Server 2 handling flight info request")
        return flight.FlightInfo(
            self.data.schema,
            descriptor,
            [flight.FlightEndpoint(descriptor.command, [])],
            self.data.num_rows,
            self.data.nbytes
        )

def main():
    try:
        logger.info("Starting server 2 on port 8816...")
        server = FlightServer2()
        server.serve()
    except Exception as e:
        logger.error(f"Server 2 error: {e}")
        raise
    finally:
        logger.info("Server 2 stopped")

if __name__ == "__main__":
    main() 