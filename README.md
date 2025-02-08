# Arrow Flight Authentication Server Example

This project demonstrates how to implement an Apache Arrow Flight service with authentication and authorization features. It supports both basic authentication and Okta OAuth authentication.

## Features

- Multiple authentication methods:
  * Username/password basic authentication
  * Okta OAuth authentication
- Role-based database access control
- Support for multiple database access
- Complete logging
- Error handling and friendly error messages

## System Requirements

- Python 3.7+
- pyarrow
- pandas
- requests (for OAuth)
- okta-jwt-verifier (for OAuth)
- python-dotenv (for environment variable management)

## Installation

1. Clone repository:
```bash
git clone <repository-url>
cd p8
```

2. Create and activate virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # Linux/Mac
# or
.\venv\Scripts\activate  # Windows
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

## Usage

### Basic Authentication Mode

1. Start server:
```bash
python src/p8_flight/basic_auth_server.py
```

2. Run test client:
```bash
python src/p8_flight/basic_auth_client.py
```

### OAuth Authentication Mode

1. Configure Okta (before starting):
   - Create application in Okta Developer Console
   - Get necessary configuration information
   - Create users and groups

2. Set environment variables:
   Create `.env` file and add the following configuration:
   ```
   OKTA_DOMAIN=your-domain.okta.com
   OKTA_CLIENT_ID=your-client-id
   OKTA_CLIENT_SECRET=your-client-secret
   OKTA_AUDIENCE=your-audience
   ```

3. Start OAuth server:
```bash
python src/p8_flight/oauth_auth_server.py
```

4. Run OAuth test client:
```bash
python src/p8_flight/oauth_auth_client.py
```

### User Roles and Permissions

#### Basic Authentication Mode

| Username | Password | Accessible Databases |
|----------|----------|---------------------|
| admin    | admin123 | db1, db2 |
| user1    | pass1    | db1 |
| user2    | pass2    | db2 |

#### OAuth Mode

| Okta Group | Accessible Databases |
|------------|---------------------|
| admin_role | db1, db2 |
| user_role  | db1 |
| readonly_role | db2 |

### Sample Data

The system contains two sample databases:

1. db1:
```
   id name
0   1    a
1   2    b
2   3    c
```

2. db2:
```
   id name
0   4    x
1   5    y
2   6    z
```

## API Documentation

### Server Side

#### Basic Authentication (BasicAuthServer)
- `BasicAuthHandler`: Handles username/password authentication
- `BasicAuthServer`: Handles data requests and access control

#### OAuth Authentication (OAuthFlightServer)
- `OktaAuthHandler`: Handles OAuth token validation
- `OAuthFlightServer`: Handles OAuth-authenticated data requests

### Client Side

#### Basic Authentication (BasicAuthClient)
- `BasicAuthHandler`: Handles client authentication
- `BasicAuthClient`: Provides data access interface

#### OAuth Authentication (OAuthClient)
- `OAuthHandler`: Handles OAuth tokens
- `OAuthClient`: Provides OAuth authentication and data access

### Authentication Flow

#### Basic Authentication Flow
1. Client sends username and password
2. Server validates credentials
3. Server generates and returns token
4. Client uses token to access data

#### OAuth Authentication Flow
1. Client obtains access token from Okta
2. Client sends Bearer token to server
3. Server validates token and checks permissions
4. Client uses validated token to access data

### Error Handling

The system handles the following types of errors:
- Authentication errors (invalid credentials or tokens)
- Permission errors (unauthorized database access)
- Connection errors
- Data access errors

## Development Guide

### Logging

The system uses Python's logging module to record operations, including:
- Authentication attempts
- Data access requests
- Errors and exceptions

### Extension Suggestions

1. Add new authentication method:
```python
class NewAuthHandler(flight.ServerAuthHandler):
    def __init__(self):
        super().__init__()
        # Initialize authentication handler
```

2. Add new permission rules:
```python
auth_handler.user_permissions["new_role"] = ["db1", "db2"]
```

3. Add new database:
```python
server.databases["new_db"] = pa.Table.from_arrays(
    [pa.array([...]), pa.array([...])],
    names=['column1', 'column2']
)
```

## Security Considerations

- Use HTTPS/TLS in production environment
- Rotate Okta client secrets regularly
- Implement token expiration and refresh mechanism
- Add request rate limiting
- Enable detailed audit logging

## Troubleshooting

1. Port in use error:
```bash
lsof -i :8815 | grep LISTEN | awk '{print $2}' | xargs kill -9
```

2. OAuth authentication failure:
- Check Okta configuration
- Verify environment variables are set
- Check user permissions and group membership

3. Permission errors:
- Check user role mappings
- Verify OAuth token group information
- Check server logs for details

## Contributing

1. Fork the project
2. Create a feature branch
3. Submit changes
4. Push to branch
5. Create Pull Request

## License

[MIT License](LICENSE)
