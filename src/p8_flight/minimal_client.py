import pyarrow.flight as flight
import logging

# 配置日志
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def main():
    try:
        # 连接到服务器
        client = flight.FlightClient("grpc://localhost:8815")
        logger.info("Connected to server")
        
        # 创建查询描述符并获取数据
        flight_desc = flight.FlightDescriptor.for_command(b"select")
        flight_info = client.get_flight_info(flight_desc)
        reader = client.do_get(flight_info.endpoints[0].ticket)
        table = reader.read_all()
        
        print("\nQuery result:")
        print(table.to_pandas())
        
    except Exception as e:
        logger.error(f"Client error: {e}")
        raise

if __name__ == "__main__":
    main() 