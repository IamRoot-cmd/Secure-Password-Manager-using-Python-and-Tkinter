# Secure-Password-Manager-using-Python-and-Tkinter
📝 Project Title:
Secure Password Manager using Python and Tkinter

👨‍💻 Developed By:
Amit Satappa Pawar

MCA Intern – YBI Foundation

Internship Domain: Python Programming

🔧 Technologies Used:

Python 3

Tkinter (GUI)

Cryptography (Fernet encryption)

JSON, CSV

File handling

🎯 Objective:

To develop a GUI-based Password Manager that allows users to securely store, search, and export login credentials using encryption. The application includes a Master Password login for enhanced security.


✅ Features:

🔐 Master Password for access

🗂️ Add / Search / View saved credentials

🔐 Encrypted data storage using Fernet

📤 Export credentials to CSV

🌓 Clean, modern GUI with dark mode styling

📂 File Structure:

PasswordManager/
│
├── main.py                 # Main Python file
├── credentials.enc         # Encrypted credentials (auto-generated)
├── vault.key               # Encryption key (auto-generated)
├── README.txt              # How to run the app


🛡️ How Security is Implemented:

Credentials are stored in an encrypted file (credentials.enc)

Uses Fernet encryption from the cryptography library

A separate key is stored in vault.key

App access is protected with a Master Password


▶️ How to Run the App:

Install dependencies:

pip install cryptography

Enter Master Password (admin123 )




