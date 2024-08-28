# Password Manager

A simple password manager built with Python and Tkinter that allows you to securely store and manage your passwords. The application uses encryption to protect your passwords and provides a user-friendly graphical interface for easy interaction.

## Features

- **Master Password Protection**: Secure your passwords with a master password that must be entered to access the manager.
- **Encryption**: All stored passwords are encrypted using the `Fernet` encryption method from the `cryptography` library.
- **User-Friendly Interface**: A simple and intuitive GUI built with `Tkinter` for adding and viewing passwords.
- **Environment Variable Management**: Configuration paths are loaded from a `.env` file using `python-dotenv`.
- **Password Management**: Add and view passwords for different websites with ease.

## Requirements

- Python 3.x
- `python-dotenv` for environment variable management
- `cryptography` for encryption and decryption of passwords
- `tkinter` (usually included with Python) for the graphical interface

## Installation

1. **Clone the repository:**
```bash
git clone https://github.com/Ronak-Kumar1023/Password-Manager.git
```
2. **Install the required Python libraries:**
```bash
pip install python-dotenv cryptography
```
3. **Create a `.env` file in the root directory with the following content:**
```plaintext
DIRECTORY_PATH=./your_directory_path_here
```
4. **Replace `your_directory_path_here` with the path where you want to store your encryption key, password file, and master password hash.**

## Usage

1. Run the script:
```bash
python password_manager.py
```
2. If no master password is set, you will be prompted to create one.
3. After setting the master password, use it to log in to the application.
4. The main interface allows you to:
   - **Add Passwords**: Enter a website, username, and password, and then click "Add Password".
   - **View Passwords**: View all stored passwords in a table format. The passwords are decrypted before display.

## File Structure

- **password_manager.py**: The main script containing the password manager logic.
- **.env**: Configuration file for environment variables.
- **passwords.txt**: The file where encrypted passwords are stored.
- **key.key**: The file containing the encryption key.
- **master_password_hash.txt**: The file storing the hashed master password.

## Security

- The master password is encrypted using the `Fernet` encryption method and stored securely.
- All passwords are stored in an encrypted format and are only decrypted when viewed.
- Ensure that the `.env` file and other files containing sensitive information are kept secure.

## Future Improvements
- Implement two-factor authentication (2FA) and biometrics for enhanced security.
- Add strong password generation and customizable complexity options.
- Enable secure password import/export and backup/recovery systems.
