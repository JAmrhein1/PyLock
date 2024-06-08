# PyLock

PyLock is a simple and secure password manager implemented in Python. It allows users to generate strong passwords, save credentials securely, and view saved credentials. All credentials are encrypted using the AES encryption provided by the Fernet module from the `cryptography` package.

## Features
- **Password Generation:** Generate strong passwords of specified length.
- **Secure Storage:** Save website credentials (username and password) securely in an encrypted file.
- **View Credentials:** View and search through saved credentials.

## Installation

### Prerequisites
- Python 3.x

### Steps
1. Clone the repository:
   ```bash
   git clone https://github.com/jamrhein1/pylock.git
   cd pylock

2. Install the required packages:
   pip install -r requirements.txt

### Usage
1. Run the script
   python pylock.py

2. When prompted, enter your master password, make sure you write this password down or remember it as i've yet to add an option to reset this password. This password is used to encrypt and decrypt your credentials.

3. Choose an option from the menu:

g: Generate a new password.
v: View saved credentials.
q: Quit the application.

### Example
![image](https://github.com/JAmrhein1/PyLock/assets/167656090/b1bd792f-e8aa-4b24-8e42-675fc91ac8ff)

### Security Notes

Master Password: Make sure to remember your master password. If you forget it, you will not be able to decrypt your saved credentials.
Encryption: The credentials are encrypted using AES encryption with a key derived from your master password using PBKDF2HMAC.

### License
This project is licensed under the MIT License. See the LICENSE file for details.

### Contributing
Feel free to contribute, I am a 3rd year computer science student who is trying to get more projects on my resume. This code might not be the most clean or well formated but it works for me and it was a fun project to do regardless.

### Contact
For any suggestions, please open an issue on this repository
   
