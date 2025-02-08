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
    """Flight服务器认证处理器"""
    
    def __init__(self):
        super().__init__()
        self.logger = logging.getLogger(__name__)
        self.logger.setLevel(logging.DEBUG)
        
        # 添加控制台处理器
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.DEBUG)
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        console_handler.setFormatter(formatter)
        self.logger.addHandler(console_handler)
        
        # 模拟用户数据库
        self.users = {
            "admin": "admin123",
            "user1": "user123",
            "readonly": "read123"
        }
        # 用户权限
        self.permissions = {
            "admin": ["read", "write", "delete"],
            "user1": ["read", "write"],
            "readonly": ["read"]
        }
        # 活跃令牌
        self.tokens = {}
    
    def authenticate(self, outgoing, incoming):
        """处理客户端认证"""
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
                
                # 使用用户名作为令牌
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
        """验证令牌有效性"""
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
        """获取用户权限"""
        if not token:
            return []
        
        token_str = token.decode() if isinstance(token, bytes) else str(token)
        username = self.tokens.get(token_str)
        if not username:
            return []
        
        return self.permissions.get(username, [])

class DuckDBConnectionPool:
    """DuckDB连接池"""
    def __init__(self, db_path="test.db", max_connections=10):
        self.db_path = db_path
        self.max_connections = max_connections
        self.connections = queue.Queue(maxsize=max_connections)
        self.lock = threading.Lock()
        
        # 确保数据库目录存在
        os.makedirs(os.path.dirname(os.path.abspath(db_path)), exist_ok=True)
        
        # 创建主数据库连接并初始化
        self.main_conn = duckdb.connect(db_path)
        self._init_db(self.main_conn)
        
        # 初始化连接池中的连接
        for _ in range(max_connections):
            conn = duckdb.connect(db_path)
            self.connections.put(conn)
    
    def _init_db(self, conn):
        """初始化数据库schema"""
        with self.lock:
            conn.execute("DROP TABLE IF EXISTS test")
            conn.execute("CREATE TABLE test (id INTEGER, name VARCHAR)")
            conn.execute("INSERT INTO test VALUES (1, 'Alice'), (2, 'Bob')")
    
    def get_connection(self):
        """获取连接"""
        try:
            return self.connections.get(timeout=5)
        except queue.Empty:
            raise Exception("无法获取数据库连接，连接池已满")
    
    def return_connection(self, conn):
        """归还连接"""
        self.connections.put(conn)
    
    def close(self):
        """关闭所有连接"""
        while not self.connections.empty():
            conn = self.connections.get()
            conn.close()
        self.main_conn.close()

class RemoteServerManager:
    """远程服务器连接管理器"""
    
    def __init__(self):
        self.remote_servers = {}
        self.clients = {}
        self.lock = threading.Lock()
        self.logger = logging.getLogger(__name__)
    
    def add_remote_server(self, server_id, host, port, username=None, password=None):
        """添加远程服务器配置"""
        with self.lock:
            self.remote_servers[server_id] = {
                "host": host,
                "port": port,
                "username": username,
                "password": password
            }
    
    def get_client(self, server_id):
        """获取或创建到远程服务器的客户端连接"""
        if server_id not in self.clients:
            with self.lock:
                if server_id not in self.clients:
                    server_info = self.remote_servers.get(server_id)
                    if not server_info:
                        raise ValueError(f"未找到服务器配置: {server_id}")
                    
                    location = f"grpc://{server_info['host']}:{server_info['port']}"
                    client = flight.FlightClient(location)
                    
                    # 如果提供了认证信息，进行认证
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
        """从远程服务器获取数据"""
        try:
            client = self.get_client(server_id)
            flight_desc = flight.FlightDescriptor.for_command(query)
            
            # 获取Flight信息
            flight_info = client.get_flight_info(flight_desc)
            
            # 获取数据
            reader = client.do_get(flight_info.endpoints[0].ticket)
            table = reader.read_all()
            
            return table
        except Exception as e:
            self.logger.error(f"从远程服务器 {server_id} 获取数据失败: {str(e)}")
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
        """设置日志"""
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger(__name__)
    
    def _check_permission(self, context, required_permission):
        """检查用户权限"""
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
        """处理Flight描述符并返回元数据"""
        self._check_permission(context, "read")
        
        start_time = datetime.now()
        query = descriptor.command.decode("utf-8")
        self.logger.info(f"收到查询请求: {query}")
        
        conn = self.connection_pool.get_connection()
        try:
            # 从DuckDB获取schema
            result = conn.execute(f"SELECT * FROM ({query}) LIMIT 0")
            arrow_table = result.fetch_arrow_table()
            
            # 构建Flight信息
            ticket = flight.Ticket(descriptor.command)  # 使用原始命令作为ticket
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
            self.logger.info(f"查询元数据处理完成，耗时: {end_time - start_time}")
            return flight_info
            
        finally:
            self.connection_pool.return_connection(conn)

    def do_get(self, context, ticket):
        """执行查询并返回Arrow数据流"""
        self._check_permission(context, "read")
        
        start_time = datetime.now()
        query = ticket.ticket.decode("utf-8")
        self.logger.info(f"执行查询: {query}")
        
        conn = self.connection_pool.get_connection()
        try:
            # 使用线程池执行查询
            future = self.executor.submit(self._execute_query, conn, query)
            table = future.result()
            
            end_time = datetime.now()
            self.logger.info(f"查询执行完成，耗时: {end_time - start_time}")
            return flight.RecordBatchStream(table)
            
        finally:
            self.connection_pool.return_connection(conn)
    
    def do_put(self, context, descriptor, reader, writer):
        """处理数据修改请求"""
        start_time = datetime.now()
        try:
            # 解析命令
            command = json.loads(descriptor.command.decode("utf-8"))
            operation = command.get("operation")
            query = command.get("query")
            
            # 检查权限
            if operation == "DELETE":
                self._check_permission(context, "delete")
            else:
                self._check_permission(context, "write")
            
            self.logger.info(f"收到数据修改请求: {operation} - {query}")
            
            conn = self.connection_pool.get_connection()
            try:
                # 获取修改前的行数
                before_count = conn.execute("SELECT COUNT(*) FROM test").fetchone()[0]
                
                # 执行修改操作
                with self.connection_pool.lock:  # 使用锁来确保修改操作的原子性
                    conn.execute(query)
                
                # 获取修改后的行数
                after_count = conn.execute("SELECT COUNT(*) FROM test").fetchone()[0]
                
                # 计算影响的行数
                affected_rows = abs(after_count - before_count)
                if operation == "UPDATE":
                    # 对于UPDATE，我们需要实际执行查询来获取影响的行数
                    if "WHERE" in query.upper():
                        where_clause = query.upper().split("WHERE")[1]
                        affected_rows = conn.execute(f"SELECT COUNT(*) FROM test WHERE {where_clause}").fetchone()[0]
                
                # 返回结果
                response = {
                    "status": "success",
                    "affected_rows": affected_rows,
                    "message": f"{operation} 操作成功完成"
                }
                
                end_time = datetime.now()
                self.logger.info(f"数据修改完成，耗时: {end_time - start_time}")
                
                # 写入响应
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
        """执行查询，支持远程数据获取"""
        try:
            # 检查是否包含远程查询标记
            if "/*remote_server:" in query:
                # 解析远程服务器ID
                server_id = query[query.find("/*remote_server:") + 15:query.find("*/")].strip()
                # 提取实际查询
                actual_query = query[query.find("*/") + 2:].strip()
                
                # 从远程服务器获取数据
                self.logger.info(f"从远程服务器 {server_id} 获取数据")
                return self.remote_manager.get_remote_data(server_id, actual_query)
            else:
                # 本地查询
                result = conn.execute(query)
                return result.fetch_arrow_table()
        except Exception as e:
            self.logger.error(f"查询执行失败: {str(e)}")
            raise
    
    def shutdown(self):
        """关闭服务器"""
        self.connection_pool.close()
        super().shutdown()

def main():
    # 设置服务器参数
    max_workers = 10  # 最大工作线程数
    max_connections = 10  # 最大数据库连接数
    db_path = "data/test.db"  # 数据库文件路径
    
    # 确保数据目录存在
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