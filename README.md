# 🔐 Secure Data Encryption System

A simple yet powerful Streamlit app to **securely store and retrieve encrypted data** using a passkey. This project is for **educational purposes**, helping you understand the concepts of encryption, passkey hashing, and Streamlit UI development.

---

## 🚀 Features

- 🔒 Encrypt sensitive data using a secure passkey
- 🔑 Retrieve data with the correct passkey and data ID
- 🛑 Locks the app after 3 failed attempts
- 🔐 Reauthorization system with a master password
- 🧠 Built for educational purposes using Streamlit and Python

---

## 🛠️ Technologies Used

- **Streamlit** – for the interactive frontend
- **hashlib** – to hash user passkeys
- **cryptography (Fernet)** – for data encryption and decryption
- **uuid** – to generate unique Data IDs
- **json** – to save encrypted data locally in `data.json`

---

## 📥 Installation & Running

1. **Clone the repository:**

```bash
git clone https://github.com/Huzaifaabdulrab/Secure_Data_Python_Project
live  https://securedatapython.streamlit.app/