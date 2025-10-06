import os
import sys
from easyzkp import SchnorrClient, SchnorrServer, CommitmentData, ResponseData

class NetworkLogger:
    @staticmethod
    def log_transmission(direction, endpoint, data_type, data_preview):
        print(f"\n  {direction} TRANSMISSION:")
        print(f"     Endpoint: {endpoint}")
        print(f"     Type: {data_type}")
        print(f"     Data: {data_preview}")

class LoggedSchnorrServer(SchnorrServer):
    def get_user_salt(self, username):
        NetworkLogger.log_transmission('→', 'get_user_salt()', 'REQUEST', f"username='{username}'")
        result = super().get_user_salt(username)
        if result:
            NetworkLogger.log_transmission('←', 'get_user_salt()', 'RESPONSE (salt)', f"{result.hex()[:32]}... ({len(result)} bytes)")
        else:
            NetworkLogger.log_transmission('←', 'get_user_salt()', 'RESPONSE', 'None (user not found)')
        return result

    def get_user_public_key(self, username):
        NetworkLogger.log_transmission('→', 'get_user_public_key()', 'REQUEST', f"username='{username}'")
        result = super().get_user_public_key(username)
        if result:
            NetworkLogger.log_transmission('←', 'get_user_public_key()', 'RESPONSE (public_key)', f"{result.hex()[:32]}... ({len(result)} bytes)")
        else:
            NetworkLogger.log_transmission('←', 'get_user_public_key()', 'RESPONSE', 'None (user not found)')
        return result

    def generate_challenge(self, username, commitment):
        NetworkLogger.log_transmission('→', 'generate_challenge()', 'REQUEST (CommitmentData)', f"username='{username}', R={commitment.R_bytes.hex()[:32]}...")
        result = super().generate_challenge(username, commitment)
        NetworkLogger.log_transmission('←', 'generate_challenge()', 'RESPONSE (ChallengeData)', f"challenge={result.challenge.hex()[:32]}..., round={result.round_num}")
        return result

    def verify_response(self, username, response):
        NetworkLogger.log_transmission('→', 'verify_response()', 'REQUEST (ResponseData)', f"username='{username}', s={str(response.s)[:32]}..., round={response.round_num}")
        result = super().verify_response(username, response)
        NetworkLogger.log_transmission('←', 'verify_response()', 'RESPONSE (bool)', f"verified={result}")
        return result

    def store_user(self, username, public_key_bytes, salt):
        NetworkLogger.log_transmission('→', 'store_user()', 'REQUEST (RegistrationData)', f"username='{username}', salt={salt.hex()[:32]}..., pubkey={public_key_bytes.hex()[:32]}...")
        result = super().store_user(username, public_key_bytes, salt)
        NetworkLogger.log_transmission('←', 'store_user()', 'RESPONSE (bool)', f"success={result}")
        return result

class TerminalApp:
    def __init__(self):
        self.client = SchnorrClient(rounds=3, verbose=False)
        self.server = LoggedSchnorrServer(rounds=3, verbose=False)
        self.running = True
        self.show_network_log = True

    def clear_screen(self):
        os.system('cls' if os.name == 'nt' else 'clear')

    def print_header(self):
        print("\n" + "="*70)
        print("     SCHNORR AUTH - Zero-Knowledge Proof Authentication")
        if self.show_network_log:
            print("              [NETWORK LOG ACTIVE]")
        print("="*70)

    def print_separator(self):
        print("-"*70)

    def print_menu(self):
        self.print_separator()
        print("\n  MAIN MENU:")
        print("  [1]  Register")
        print("  [2]  Login")
        print("  [3]  List Registered Users")
        print(f"  [4]  Network Log: {'ON' if self.show_network_log else 'OFF'}")
        print("  [5]  Exit")
        print()
        self.print_separator()

    def input_with_prompt(self, prompt, password=False):
        if password:
            import getpass
            return getpass.getpass(f"  {prompt}: ")
        else:
            return input(f"  {prompt}: ").strip()

    def press_enter_to_continue(self):
        print()
        input("  Press ENTER to continue...")

    def register_user(self):
        self.clear_screen()
        self.print_header()
        print("\n   REGISTER NEW USER")
        self.print_separator()

        username = self.input_with_prompt("Username")
        if not username:
            print("\n   Username required!")
            self.press_enter_to_continue()
            return

        if self.server.get_user_salt(username) is not None:
            print(f"\n   User '{username}' already exists!")
            self.press_enter_to_continue()
            return

        password = self.input_with_prompt("Password", password=True)
        if not password:
            print("\n   Password required!")
            self.press_enter_to_continue()
            return

        password_confirm = self.input_with_prompt("Confirm Password", password=True)
        if password != password_confirm:
            print("\n   Passwords do not match!")
            self.press_enter_to_continue()
            return

        print("\n" + "="*70)
        print("   PHASE 1: CLIENT-SIDE DATA GENERATION")
        print("="*70)
        print("\n   Password + Salt → Argon2id → Private Key → Public Key")
        print("   (Password is NEVER transmitted!)")

        try:
            reg_data = self.client.register_user(username, password)
            print(f"\n   Locally generated data:")
            print(f"     • Salt: {reg_data.salt.hex()[:32]}...")
            print(f"     • Public Key: {reg_data.public_key_bytes.hex()[:32]}...")

            print("\n" + "="*70)
            print("   PHASE 2: TRANSMISSION TO SERVER")
            print("="*70)

            success = self.server.store_user(reg_data.username, reg_data.public_key_bytes, reg_data.salt)
            if success:
                print(f"\n   User '{username}' successfully registered!")
                print(f"\n   NOTE: Password remains ONLY on the client!")
                print(f"         Server only received: username, salt, public_key")
            else:
                print("\n   Registration error!")

        except Exception as e:
            print(f"\n   Error: {e}")

        self.press_enter_to_continue()

    def login_user(self):
        self.clear_screen()
        self.print_header()
        print("\n   USER LOGIN")
        self.print_separator()

        username = self.input_with_prompt("Username")
        if not username:
            print("\n   Username required!")
            self.press_enter_to_continue()
            return

        if self.server.get_user_salt(username) is None:
            print(f"\n   User '{username}' not found!")
            self.press_enter_to_continue()
            return

        password = self.input_with_prompt("Password", password=True)
        if not password:
            print("\n   Password required!")
            self.press_enter_to_continue()
            return

        print("\n" + "="*70)
        print("   SCHNORR MULTI-ROUND AUTHENTICATION")
        print("="*70)
        print("\n   Password is NEVER transmitted!")
        print("   Only used locally for cryptographic calculations.\n")

        try:
            result = self.client.login(username, password, self.server)
            print("\n" + "="*70)
            print("   LOGIN SUCCESS!" if result.success else "   LOGIN FAILED!")
            print("="*70)

            print(f"\n   Authentication Result:")
            print(f"     • Status: {'SUCCESS' if result.success else 'FAILED'}")
            print(f"     • Total Time: {result.elapsed_time:.3f}s")
            print(f"     • Rounds Completed: {result.rounds_completed}/3")
            print(f"     • Security Bits: {result.security_bits}")
            print(f"     • Message: {result.message}")

            print("\n   Transmission Summary:")
            print("     1. Client → Server: request salt")
            print("     2. Server → Client: send salt")
            print("     3. Client computes: password + salt → private_key")
            print("     4. Client → Server: request registered public_key")
            print("     5. Server → Client: send public_key")
            print("     6. Client checks locally: do public keys match?")
            print("     7. FOR EACH ROUND (3x):")
            print("        a. Client computes: commitment R = k*G")
            print("        b. Client → Server: send R")
            print("        c. Server → Client: send challenge c")
            print("        d. Client computes: response s = k + c*x")
            print("        e. Client → Server: send s")
            print("        f. Server verifies: s*G == R + c*PubKey")

            print("\n   Access Granted!" if result.success else "\n   Access Denied!")

        except Exception as e:
            print(f"\n   Login error: {e}")

        self.press_enter_to_continue()

    def list_users(self):
        self.clear_screen()
        self.print_header()
        print("\n   REGISTERED USERS")
        self.print_separator()

        users = self.server._users
        if not users:
            print("\n   No users registered.")
        else:
            print(f"\n  Total users: {len(users)}\n")
            for idx, (username, data) in enumerate(users.items(), 1):
                import datetime
                reg_time = datetime.datetime.fromtimestamp(data['registered_at'])
                print(f"  [{idx}] {username}")
                print(f"      • Registered: {reg_time.strftime('%d/%m/%Y %H:%M:%S')}")
                print(f"      • Salt: {data['salt'].hex()[:32]}...")
                print(f"      • Public Key: {data['public_key_bytes'].hex()[:32]}...\n")

        self.press_enter_to_continue()

    def toggle_network_log(self):
        self.show_network_log = not self.show_network_log
        self.server = LoggedSchnorrServer(rounds=3, verbose=False) if self.show_network_log else SchnorrServer(rounds=3, verbose=False)

    def run(self):
        while self.running:
            self.clear_screen()
            self.print_header()
            self.print_menu()

            choice = input("  Choose an option [1-5]: ").strip()
            if choice == '1':
                self.register_user()
            elif choice == '2':
                self.login_user()
            elif choice == '3':
                self.list_users()
            elif choice == '4':
                self.toggle_network_log()
            elif choice == '5':
                self.clear_screen()
                self.print_header()
                print("\n   Thanks for using Schnorr Auth!")
                print("   Stay secure!\n")
                self.print_separator()
                print()
                self.running = False
            else:
                print("\n   Invalid option! Choose a number from 1 to 5.")
                self.press_enter_to_continue()

def main():
    try:
        app = TerminalApp()
        app.run()
    except KeyboardInterrupt:
        print("\n\n   Application interrupted by user.\n")
        sys.exit(0)
    except Exception as e:
        print(f"\n   Critical error: {e}\n")
        sys.exit(1)

if __name__ == "__main__":
    main()
