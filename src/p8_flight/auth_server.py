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
        # 模拟用户数据库
        self.users = {
            "admin": self._hash_password("admin123"),
            "user1": self._hash_password("user123"),
            "readonly": self._hash_password("read123")
        }
        # 用户权限
        self.permissions = {
            "admin": ["read", "write", "delete"],
            "user1": ["read", "write"],
            "readonly": ["read"]
        }
        # 活跃令牌
        self.tokens = {}
        # 令牌过期时间（1小时）
        self.token_expiry = timedelta(hours=1)
    
    def _hash_password(self, password):
        """密码哈希"""
        return hashlib.sha256(password.encode()).hexdigest()
    
    def _generate_token(self):
        """生成随机令牌"""
        return base64.b64encode(secrets.token_bytes(32)).decode()
    
    def authenticate(self, outgoing, incoming):
        """处理客户端认证"""
        auth_data = incoming.read()
        if not auth_data:
            raise flight.FlightUnauthenticatedError("No credentials")
        
        try:
            auth = json.loads(auth_data)
            username = auth.get("username")
            password = auth.get("password")
            
            if not username or not password:
                raise flight.FlightUnauthenticatedError("Invalid credentials format")
            
            stored_hash = self.users.get(username)
            if not stored_hash or stored_hash != self._hash_password(password):
                raise flight.FlightUnauthenticatedError("Invalid username or password")
            
            # 生成新令牌
            token = self._generate_token()
            self.tokens[token] = {
                "username": username,
                "expires": datetime.now() + self.token_expiry
            }
            
            # 返回令牌给客户端
            outgoing.write(token.encode())
            
        except json.JSONDecodeError:
            raise flight.FlightUnauthenticatedError("Invalid credentials format")
    
    def is_valid(self, token):
        """验证令牌有效性"""
        if not token:
            return None
        
        token_str = token.decode() if isinstance(token, bytes) else str(token)
        token_info = self.tokens.get(token_str)
        if not token_info:
            return None
        
        # 检查令牌是否过期
        if datetime.now() > token_info["expires"]:
            del self.tokens[token_str]
            return None
        
        return token_str.encode()
    
    def get_user_permissions(self, token):
        """获取用户权限"""
        if not token:
            return []
        
        token_str = token.decode() if isinstance(token, bytes) else str(token)
        token_info = self.tokens.get(token_str)
        if not token_info:
            return []
        
        username = token_info["username"]
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

class AuthenticatedFlightServer(flight.FlightServerBase):
    def __init__(self, location, db_path="test.db", max_workers=10, max_connections=10):
        self.auth_handler = AuthHandler()
        super().__init__(location, auth_handler=self.auth_handler)
        self.location = location
        self.connection_pool = DuckDBConnectionPool(db_path, max_connections)
        self.executor = ThreadPoolExecutor(max_workers=max_workers)
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
        """在线程池中执行查询"""
        return conn.execute(query).fetch_arrow_table()
    
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