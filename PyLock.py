import random
import string
import os
import base64
from termcolor import colored
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

##############################################HEADER#############################################

banner_text ="""
______      _                _    
| ___ \    | |              | |   
| |_/ /   _| |     ___   ___| | __
|  __/ | | | |    / _ \ / __| |/ /
| |  | |_| | |___| (_) | (__|   < 
\_|   \__, \_____/\___/ \___|_|\_|
       __/ |                      
      |___/                                                                                                                                  
"""
colored_banner = colored(banner_text, 'blue')
print(colored_banner)

########################################GENERATE PASSWORD########################################

def generate_password(length):
    if length < 8 or length > 16:
        raise ValueError("Password length must be at least 8 characters or at most 16 characters")
    
    all_characters = string.ascii_letters + string.digits + string.punctuation
    password = ''.join(random.choice(all_characters) for i in range(length))

    while (not any(c.islower() for c in password) or
           not any(c.isupper() for c in password) or
           not any(c.isdigit() for c in password) or
           not any(c in string.punctuation for c in password)):
        password = ''.join(random.choice(all_characters) for i in range(length))

    return password

###########################################ENCRYPT FILE##########################################

def save_credentials(website, username, password, key):
    cipher_suite = Fernet(key)
    credentials = f"Website: {website}\nUsername: {username}\nPassword: {password}".encode()
    encrypted_credentials = cipher_suite.encrypt(credentials)
    with open("credentials.enc", "ab") as file:  # uses "ab" to append to the file
        file.write(encrypted_credentials + b'\n')

def load_key(salt, password):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key

def generate_salt():
    return os.urandom(16)

def view_credentials(key):
    cipher_suite = Fernet(key)
    if not os.path.exists("credentials.enc"):
        print("No credentials found.")
        return
    
    credentials_list = []
    with open("credentials.enc", "rb") as file:
        for line in file:
            encrypted_credentials = line.strip()
            try:
                decrypted_credentials = cipher_suite.decrypt(encrypted_credentials).decode()
                credentials_list.append(decrypted_credentials)
            except InvalidToken:
                print("[!] Wrong Master Password [!]")
                return
    
    if not credentials_list:
        print("No credentials found.")
        return
    
    while True:
        for i, credentials in enumerate(credentials_list, 1):
            entry_header = colored(f"Entry {i}:", 'magenta', attrs=['bold'])
            print(entry_header)
            print(credentials)
            print("-" * 50)  # Separator line
        
        search_query = input("Enter a website to search for (or press Enter to return to the main menu): ").strip()
        if not search_query:
            break
        
        found = False
        for i, credentials in enumerate(credentials_list, 1):
            if search_query.lower() in credentials.lower():
                entry_header = colored(f"Entry {i}:", 'magenta', attrs=['bold'])
                print(entry_header)
                print(credentials)
                print("-" * 50)  # Separator line
                found = True
        
        if not found:
            print("No credentials found for the given website.")
        
        delete_choice = input(f"Do you want to delete an entry? ({colored('y', 'green')}/{colored('n', 'red')}): ").strip().lower()
        if delete_choice == 'y':
            entry_number = int(input("Enter the entry number to delete: "))
            if 1 <= entry_number <= len(credentials_list):
                confirm_delete = input(f"Are you sure you want to delete Entry {entry_number}? This action cannot be undone. ({colored('y', 'green')}/{colored('n', 'red')}): ").strip().lower()
                if confirm_delete == 'y':
                    del credentials_list[entry_number - 1]
                    with open("credentials.enc", "wb") as file:
                        for credentials in credentials_list:
                            encrypted_credentials = cipher_suite.encrypt(credentials.encode())
                            file.write(encrypted_credentials + b'\n')
                    print("Entry deleted successfully!")
                else:
                    print("Deletion cancelled.")
            else:
                print("Invalid entry number.")

def main():
    salt_path = "salt.key"
    if not os.path.exists(salt_path):
        salt = generate_salt()
        with open(salt_path, "wb") as salt_file:
            salt_file.write(salt)
    else:
        with open(salt_path, "rb") as salt_file:
            salt = salt_file.read()

    tries = 0
    while tries < 3:
        master_password = input("Enter your master password: ")
        key = load_key(salt, master_password)

        try:
            # Test if the master password is correct by attempting to decrypt
            if os.path.exists("credentials.enc"):
                with open("credentials.enc", "rb") as file:
                    test_line = file.readline().strip()
                    cipher_suite = Fernet(key)
                    cipher_suite.decrypt(test_line)
            break  # If decryption is successful, break out of the loop
        except InvalidToken:
            tries += 1
            remaining_tries = 3 - tries
            print(f"[!] Wrong Master Password [!] You have {remaining_tries} {'try' if remaining_tries == 1 else 'tries'} left.")
            if tries == 3:
                print("Too many incorrect attempts. Exiting.")
                return

    print(colored("Welcome to PyLock!", 'yellow', attrs=['bold']))

    while True:
        try:
            choice = input(f"Do you want to ({colored('g', 'cyan', attrs=['bold'])})enerate a new password, ({colored('v', 'magenta', attrs=['bold'])})iew saved credentials, or ({colored('q', 'yellow', attrs=['bold'])})uit? ").strip().lower()
            if choice == 'g':
                length = int(input("Enter the length of the password (8-16): "))
                while True:
                    password = generate_password(length)
                    print(f"Generated password: {password}")
                    user_input = input(f"Do you want to save this password? ({colored('y', 'green')}/{colored('n', 'red')}): ").strip().lower()
                    if user_input == 'y':
                        username = input("Enter the username: ")
                        website = input("Enter the name of the website or the link: ")
                        save_credentials(website, username, password, key)
                        print("Website, Username, and Password have been saved securely!")
                        break
                    else:
                        another_password = input(f"Do you want to generate another password? ({colored('y', 'green')}/{colored('n', 'red')}): ").strip().lower()
                        if another_password != 'y':
                            print("Thank you for using PyLock!")
                            break
            elif choice == 'v':
                view_credentials(key)
            elif choice == 'q':
                print("Thank you for using PyLock!")
                break
            else:
                print("Invalid choice. Please select 'g', 'v', or 'q'.")
        except ValueError as e:
            print(e)

if __name__ == "__main__":
    main()