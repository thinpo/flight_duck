import pyarrow as pa
import pyarrow.flight as flight

class BasicFlightServer(flight.FlightServerBase):
    def __init__(self):
        super().__init__("grpc://localhost:8815")
        self.data = pa.Table.from_arrays(
            [pa.array([1, 2, 3]), pa.array(['a', 'b', 'c'])],
            names=['id', 'name']
        )
    
    def do_get(self, context, ticket):
        return flight.RecordBatchStream(self.data)
    
    def get_flight_info(self, context, descriptor):
        return flight.FlightInfo(
            self.data.schema,
            descriptor,
            [flight.FlightEndpoint(descriptor.command, [])],
            self.data.num_rows,
            self.data.nbytes
        )

if __name__ == "__main__":
    server = BasicFlightServer()
    print("Server starting on localhost:8815")
    server.serve() 