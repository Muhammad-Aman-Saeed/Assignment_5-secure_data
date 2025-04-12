import streamlit as st
import hashlib
import json
import os
import time
from cryptography.fernet import Fernet
from base64 import urlsafe_b64decode
from hashlib import pbkdf2_hmac

# data imformation of user
DATA_FILE = "secure_data.json"
SALT = b"secure_salt_value"
LOCKOUT_DURATION = 60


# section login
if "authenticated_user" not in st.session_state:
    st.session_state.authenticated_user = None

if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = 0

if "lockout_time" not in st.session_state:
    st.session_state.lockout_time = 0


# if data is load
def load_data():
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, "r") as f:
            return json.load(f)
    return {}


def save_data(data):
    with open(DATA_FILE,"w") as f:
        json.dump(data, f)

def generate_key(passkey):
    key = pbkdf2_hmac("sha256", passkey.encode(), SALT, 100000)
    return urlsafe_b64decode(key)


def hash_password(password):
    return hashlib.pbkdf2_hmac("sha256", password.encode(), SALT, 100000).hex()


# cryptography.fernet 
def encrypt_text (text, key):
    cipher = Fernet(generate_key(key))
    return cipher.encrypt(text.encode()).decode()

def decrypt_text(encrypt_text, key):
    try:
        cipher = Fernet(generate_key(key))
        return cipher.decrypt(encrypt_text.encode()).decode()
    except:
        return None
    
stored_data = load_data()

# navigation bar
st.title("Secure Data Encryption System")
menu = ["Home", "Register", "Login", "Stored Data", "Recover Data"]
Choice = st.sidebar.selectbox("Navigation", menu)

if Choice == "Home":
    st.subheader("Welcome To My Data Encryption System Using Streamlit")
    st.markdown("""Welcome to a simple and safe way to protect your personal data.This system lets you:

    🔑 Register and log in securely
    🔒 Encrypt your private information
    🔓 Decrypt and recover your data safely

    All your data is protected using strong encryption, so only you can access it.""")

# registration
elif Choice == "Register":
    st.subheader("➕ Register New User")
    username = st.text_input("Enter Username: ")
    password = st.text_input("Enter Password: ", type="password")

    if st.button("Register"):
        if username and password:
            if username and stored_data:
                st.warning("User already exists.")
            else:
                stored_data[username] = {
                    "password": hash_password(password),
                    "data" : []
                }
                save_data(stored_data)
                st.success("✅ User register successfully!")
        else:
            st.error("Both fields are required.")
elif Choice == "Login":
        st.subheader("🔓 User Login")

        if time.time() < st.session_state.lockout_time:
            remaining = int(st.session_state.lockout_time - time.time())
            st.error(f"Oops! Too many tries. Please wait {remaining} seconds before trying again.")
            st.stop()
            
        username = st.text_input("Username")
        password = st.text_input("Password", type = "password")

        if st.button("Login"):
            if username in stored_data and stored_data[username]["password"] == hash_password(password):
                st.session_state.authenticated_user = username
                st.session_state.failed_attempts = 0
                st.success(f"Welcome {username}!")
            else:
                st.session_state.failed_attempts += 1
                remaining = 3 - st.session_state.failed_attempts
                st.error(f"⚠ Invalid Credentials! Attempts left: {remaining}")

                if st.session_state.failed_attempts >= 3:
                    st.session_state.lockout_time = time.time() + LOCKOUT_DURATION
                    st.error("Oops! Too many tries. Locked for 60 seconds")
                    st.stop()

# data store section

elif Choice == "Stored Data":
    if not st.session_state.authenticated_user:
        st.warning("Please login first.")
    else:
        st.subheader("Store Encrypted Data")
        data = st.text_area("Enter data to enccrypt")
        passkey = st.text_input("Encryption key (passphrase)", type = "password")

        if st.button("Encrypt and Save"):
            if data and passkey:
                encrypted = encrypt_text(data, passkey)
                stored_data[st.session_state.authenticated_user]["data"].append(encrypted)
                save_data(stored_data) 
                st.success("✅ Data encrypted and save successfully.")
            else:
                st.error("All fields are reuired to fill.")

# data recover section

elif Choice == "Recover Data":
    if not st.session_state.authenticated_user:
        st.warning("Please login first.")
    else:
        st.subheader("Recover data")
        user_data = stored_data.get(st.session_state.authenticated_user, {}).get("data", [])

        if not user_data:
            st.info("No data found!")
        else:
            st.write("Encrypted data entries")
            for i, item in enumerate(user_data):
                st.code(item, language= "text")

            encrypted_input = st.text_area("Enter encrypted text")
            passkey = st.text_input ("Enter passkey to decrypt", type = "password")

            if st.button("Decrypt"):
                result = decrypt_text(encrypted_input, passkey)
                if result:
                    st.success(f"✅ Decrypted: {result}")
                else:
                    st.error("❌ Incorrect passkey or corrupted data.")
