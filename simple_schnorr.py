from easyzkp import SchnorrClient, SchnorrServer
import getpass

client = SchnorrClient(rounds=3)
server = SchnorrServer(rounds=3)

print("\nREGISTRATION")

username = input("Enter username: ").strip()
password = getpass.getpass("Enter password: ")

if not username or not password:
    print("Username and password are required!")
    exit(1)

reg_data = client.register_user(username, password)
server.store_user(
    username=reg_data.username,
    public_key_bytes=reg_data.public_key_bytes,
    salt=reg_data.salt
)
print("User registered!")

print("\nLOGIN")

login_username = input("Username: ").strip()
login_password = getpass.getpass("Password: ")

result = client.login(login_username, login_password, server)

print()
if result.success:
    print("LOGIN SUCCESSFUL!")
else:
    print("LOGIN FAILED!")
