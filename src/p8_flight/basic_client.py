import pyarrow.flight as flight

def main():
    client = flight.FlightClient("grpc://localhost:8815")
    
    # 获取数据
    flight_desc = flight.FlightDescriptor.for_command(b"select")
    flight_info = client.get_flight_info(flight_desc)
    reader = client.do_get(flight_info.endpoints[0].ticket)
    table = reader.read_all()
    
    print("\nQuery result:")
    print(table.to_pandas())

if __name__ == "__main__":
    main() 