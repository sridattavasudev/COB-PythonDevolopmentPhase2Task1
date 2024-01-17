from cryptography.fernet import Fernet
import json
import os

# task1


class PasswordManager:
    def __init__(self, password, file_path="passwords.json"):
        self.file_path = file_path
        self.master_password = password.encode()
        self.key = self.generate_key()
        self.passwords = {}

        try:
            self.load_passwords()
        except (json.decoder.JSONDecodeError, FileNotFoundError):
            self.passwords = {}

    def generate_key(self):
        if os.path.exists("key.key"):
            return open("key.key", "rb").read()
        else:
            key = Fernet.generate_key()
            with open("key.key", "wb") as key_file:
                key_file.write(key)
            return key

    def add_password(self, website, username, password):
        self.passwords[website] = {"username": username, "password": password}
        self.save_passwords()

    def encrypt_password(self, password):
        cipher_suite = Fernet(self.key)
        cipher_text = cipher_suite.encrypt(password.encode())
        return cipher_text

    def save_passwords(self):
        encrypted_passwords = {
            key: {"username": value["username"], "password": value["password"]}
            for key, value in self.passwords.items()
        }
        with open(self.file_path, "w") as file:
            json.dump(encrypted_passwords, file)

    def decrypt_password(self, cipher_text):
        cipher_suite = Fernet(self.key)
        plain_text = cipher_suite.decrypt(cipher_text).decode()
        return plain_text

    def load_passwords(self):
        with open(self.file_path, "r") as file:
            encrypted_passwords = json.load(file)

        self.passwords = {
            key: {
                "username": value.get("username", ""),
                "password": value.get("password", ""),
            }
            for key, value in encrypted_passwords.items()
            if isinstance(value, dict)  # Ensure value is a dictionary
        }

    def get_password(self, website):
        if website in self.passwords:
            return self.passwords[website]
        else:
            return None


# Function to create a master password
def main_password():
    return input("Create your main password: ")


# Function to add websites and passwords
def add_websites_and_passwords(password_manager):
    num_websites = int(input("Enter the number of websites you want to add: "))
    for _ in range(num_websites):
        website = input("Enter the website: ")
        username = input("Enter the username: ")
        password = input("Enter the password: ")
        password_manager.add_password(website, username, password)


# Function to get a password for a specific website
def get_password_from_site(password_manager):
    website_to_check = input(
        "Enter the website for which you want to retrieve the password: "
    )
    retrieved_password = password_manager.get_password(website_to_check)
    if retrieved_password:
        print(f"Username: {retrieved_password['username']}")
        print(f"Password: {retrieved_password['password']}")
    else:
        print(f"No password found for {website_to_check}")


# Main program
password = main_password()
password_manager = PasswordManager(password)

while True:
    print("Choose an option:")
    print("1. Add websites and passwords")
    print("2. Get password for a website")
    print("3. Quit")

    choice = input("Enter your choice (1/2/3): ")

    if choice == "1":
        add_websites_and_passwords(password_manager)
    elif choice == "2":
        get_password_from_site(password_manager)
    elif choice == "3":
        break
    else:
        print("Invalid choice. Please enter 1, 2, or 3.")
