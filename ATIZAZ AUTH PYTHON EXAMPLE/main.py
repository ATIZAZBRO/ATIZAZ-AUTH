import sys
from AtizazAuth import AtizazAuthAPI

def main():
    print("=" * 40)
    print("  Welcome to Atizaz Auth Python Example  ")
    print("=" * 40)
    print("\n[+] Initializing with server...")
    
    api = AtizazAuthAPI(
        api_url="https://cmatizaz-cfire.atizazfayaz78.workers.dev",
        secret_key="ATIZAZ-4XOG3LQSUY8", 
        application_name="ATIZAZ AUTH",
        version="1.0"
    )
    
    api.init()
    print(f"[+] Initialization Success! Session ID: {api.sessionid}")
    print(f"[+] Hardware ID: {api.get_hwid()}")
    
    while True:
        print("\n" + "-" * 30)
        print("1. Login (Username/Password)")
        print("2. Register")
        print("3. License Only Login")
        print("4. Exit")
        print("-" * 30)
        
        choice = input("Enter your choice: ")
        
        if choice == '1':
            username = input("Username: ")
            password = input("Password: ")
            resp = api.login(username, password)
            if resp.get('success'):
                print("\n[SUCCESS] Login Authenticated!")
                print(f" > User: {resp.get('username')}")
                print(f" > Subscription: {resp.get('subscription')}")
                print(f" > Expiry: {resp.get('expiry')}")
            else:
                print(f"\n[ERROR] Login Failed: {resp.get('message')}")
                
        elif choice == '2':
            username = input("Username: ")
            password = input("Password: ")
            license_key = input("License Key: ")
            resp = api.register(username, password, license_key)
            if resp.get('success'):
                print("\n[SUCCESS] Account Registered! You can now login.")
            else:
                print(f"\n[ERROR] Registration Failed: {resp.get('message')}")
                
        elif choice == '3':
            license_key = input("License Key: ")
            resp = api.license(license_key)
            if resp.get('success'):
                print("\n[SUCCESS] License Authenticated!")
                print(f" > Subscription: {resp.get('subscription')}")
                print(f" > Expiry: {resp.get('expiry')}")
            else:
                print(f"\n[ERROR] Login Failed: {resp.get('message')}")
                
        elif choice == '4':
            print("Exiting...")
            sys.exit(0)
        else:
            print("Invalid choice, please select 1-4.")

if __name__ == "__main__":
    main()
