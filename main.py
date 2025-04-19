import streamlit as st
import hashlib
import json
import time
from cryptography.fernet import Fernet
import base64
import uuid
import os

DATA_FILE = "data.json"

def load_data_from_file():
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, "r") as f:
            return json.load(f)
    return {}

# Save current stored data to file
def save_data_to_file(data):
    with open(DATA_FILE, "w") as f:
        json.dump(data, f, indent=4)


def main():
    if 'failed_attempts' not in st.session_state:
        st.session_state.failed_attempts = 0
    if 'stored_data' not in st.session_state:
        st.session_state.stored_data = load_data_from_file()
    if 'current_page' not in st.session_state:
        st.session_state.current_page = "Home"
    if 'last_attempt_time' not in st.session_state:
        st.session_state.last_attempt_time = 0

    def hash_passkey(passkey):
        return hashlib.sha256(passkey.encode()).hexdigest()

    def generate_key_from_passkey(passkey):
        hashed = hashlib.sha256(passkey.encode()).digest()
        return base64.urlsafe_b64encode(hashed[:32])

    def encrypt_data(text, passkey):
        key = generate_key_from_passkey(passkey)
        cipher = Fernet(key)
        return cipher.encrypt(text.encode()).decode()

    def decrypt_data(encrypted_text, passkey, data_id):
        try:
            hashed_passkey = hash_passkey(passkey)
            if data_id in st.session_state.stored_data:
                stored = st.session_state.stored_data[data_id]
                if stored["passkey"] != hashed_passkey:
                    raise Exception("Wrong passkey")
                key = generate_key_from_passkey(passkey)
                cipher = Fernet(key)
                decrypted = cipher.decrypt(encrypted_text.encode()).decode()
                st.session_state.failed_attempts = 0
                return decrypted
            else:
                st.session_state.failed_attempts += 1
                st.session_state.last_attempt_time = time.time()
                return None
        except Exception:
            st.session_state.failed_attempts += 1
            st.session_state.last_attempt_time = time.time()
            return None

    def generate_data_id():
        return str(uuid.uuid4())

    def reset_failed_attempts():
        st.session_state.failed_attempts = 0

    def change_page(page):
        st.session_state.current_page = page

    st.title("🔒 Secure Data Encryption System")

    menu = ["Home", "Store Data", "Retrieve Data", "Login"]
    choice = st.sidebar.selectbox("Navigation", menu, index=menu.index(st.session_state.current_page))
    st.session_state.current_page = choice

    if st.session_state.failed_attempts >= 3:
        st.session_state.current_page = "Login"
        st.warning("🔒 Too many failed attempts! Reauthorization required.")

    if st.session_state.current_page == "Home":
        st.subheader("Welcome to Secure Data System")
        st.write("Use this app to **Securely store and retrieve data**.")

        col1, col2 = st.columns(2)
        with col1:
            if st.button("Store New Data", use_container_width=True):
                change_page("Store Data")
        with col2:
            if st.button("Retrieve Data", use_container_width=True):
                change_page("Retrieve Data")

        st.info(f"Currently storing {len(st.session_state.stored_data)} encrypted items.")

    elif st.session_state.current_page == "Store Data":
        st.subheader("Store Data Securely")

        user_name = st.text_input("Enter Your Name")
        user_data = st.text_area("Enter Data:")
        passkey = st.text_input("Enter Passkey:", type="password")
        confirm_passkey = st.text_input("Confirm Passkey:", type="password")

        if st.button("Encrypt & Save"):
            if user_data and passkey and confirm_passkey:
                if passkey != confirm_passkey:
                    st.error("🚨 Passkey mismatch! Please try again.")
                else:
                    data_id = generate_data_id()
                    hashed_passkey = hash_passkey(passkey)
                    encrypted_text = encrypt_data(user_data, passkey)

                    st.session_state.stored_data[data_id] = {
                        "encrypted_text": encrypted_text,
                        "passkey": hashed_passkey
                    }

                    save_data_to_file(st.session_state.stored_data)

                    st.success("Data stored securely!")
                    st.code(data_id, language='text')
                    st.info("Save this Data ID! You'll need it to retrieve your data.")
            else:
                st.error("🚨 Please fill all fields!")

    elif st.session_state.current_page == "Retrieve Data":
        st.subheader("Retrieve Data Securely")

        attempts_remaining = 3 - st.session_state.failed_attempts
        st.info(f"Attempts remaining: {attempts_remaining}")

        data_id = st.text_input("Enter Data ID:")
        passkey = st.text_input("Enter Passkey:", type="password")

        if st.button("Decrypt"):
            if data_id and passkey:
                if data_id in st.session_state.stored_data:
                    encrypted_text = st.session_state.stored_data[data_id]["encrypted_text"]
                    decrypted_text = decrypt_data(encrypted_text, passkey, data_id)

                    if decrypted_text:
                        st.success("Data retrieved successfully!")
                        st.markdown("### Your Decrypted Data:")
                        st.code(decrypted_text, language="text")
                    else:
                        st.error(f"Incorrect Passkey! Attempts remaining: {3 - st.session_state.failed_attempts}")
                else:
                    st.error("Data ID not found! Please try again.")
            else:
                st.error("Both fields are required.")

            if st.session_state.failed_attempts >= 3:
                st.warning("Too many failed attempts! Please try again later.")
                st.session_state.current_page = "Login"
                st.rerun()

    elif st.session_state.current_page == "Login":
        st.subheader("Reauthorization Required")

        wait_time = 10  # seconds
        time_diff = time.time() - st.session_state.last_attempt_time

        if time_diff < wait_time:
            remaining = int(wait_time - time_diff)
            st.warning(f"Please wait for {remaining} seconds before trying again.")
        else:
            login_pass = st.text_input("Enter Master Password:", type="password")
            if st.button("Login"):
                if login_pass == "admin123":
                    reset_failed_attempts()
                    st.success("Reauthorized successfully!")
                    st.session_state.current_page = "Home"
                    st.rerun()
                else:
                    st.error("Incorrect Password!")

    st.markdown("---")
    st.markdown("Secure Data Encryption System | Educational Project")


if __name__ == "__main__":
    main()
