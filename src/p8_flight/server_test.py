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
    """运行服务器"""
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
    """测试远程查询"""
    try:
        # 连接到服务器
        client = flight.FlightClient("grpc://localhost:8815")
        
        # 认证
        auth = b"admin:admin123"
        client.authenticate_basic_token(auth)
        
        # 执行查询
        query = "SELECT * FROM test"
        flight_desc = flight.FlightDescriptor.for_command(query)
        
        # 获取Flight信息
        flight_info = client.get_flight_info(flight_desc)
        
        # 获取数据
        reader = client.do_get(flight_info.endpoints[0].ticket)
        table = reader.read_all()
        
        print("\nQuery result:")
        print(table.to_pandas())
        
    except Exception as e:
        logger.error(f"Test error: {e}")

def main():
    # 创建数据目录
    os.makedirs("data", exist_ok=True)
    
    # 启动服务器
    server_thread = threading.Thread(
        target=run_server,
        args=(8815, "data/test.db")
    )
    server_thread.daemon = True
    
    try:
        logger.info("Starting server...")
        server_thread.start()
        
        # 等待服务器启动
        time.sleep(2)
        
        # 运行测试
        logger.info("Running test...")
        test_remote_query()
        
        # 保持主线程运行
        while True:
            time.sleep(1)
            
    except KeyboardInterrupt:
        logger.info("Shutting down...")
    except Exception as e:
        logger.error(f"Main error: {e}")

if __name__ == "__main__":
    main() 