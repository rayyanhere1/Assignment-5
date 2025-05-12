import streamlit as st
import hashlib
from cryptography.fernet import Fernet
import base64
import os

# In-memory data storage
if 'stored_data' not in st.session_state:
    st.session_state.stored_data = {}

# Encryption key generation (derived from passkey)
def generate_fernet_key(passkey):
    # Use SHA-256 to hash the passkey and then use the first 32 bytes for Fernet key
    hashed = hashlib.sha256(passkey.encode()).digest()
    return base64.urlsafe_b64encode(hashed[:32])

# Encrypt data
def encrypt_data(text, passkey):
    fernet_key = generate_fernet_key(passkey)
    cipher_suite = Fernet(fernet_key)
    encrypted_text = cipher_suite.encrypt(text.encode())
    return encrypted_text.decode()

# Decrypt data
def decrypt_data(encrypted_text, passkey):
    try:
        fernet_key = generate_fernet_key(passkey)
        cipher_suite = Fernet(fernet_key)
        decrypted_text = cipher_suite.decrypt(encrypted_text.encode())
        return decrypted_text.decode()
    except:
        return None

# Hash passkey for storage
def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()

# Login page
def login_page():
    st.title("🔒 Reauthorization Required")
    st.warning("You've exceeded the maximum attempts. Please login to continue.")
    
    login_passkey = st.text_input("Enter your login passkey:", type="password")
    if st.button("Login"):
        # For this simple system, any non-empty passkey will work for reauthorization
        if login_passkey:
            st.session_state.attempts = 0
            st.session_state.current_page = "home"
            st.rerun()
        else:
            st.error("Please enter a valid passkey")

# Home page
def home_page():
    st.title("🔐 Secure Data Encryption System")
    st.write("Choose an option below:")
    
    col1, col2 = st.columns(2)
    with col1:
        if st.button("Store New Data"):
            st.session_state.current_page = "store"
            st.rerun()
    with col2:
        if st.button("Retrieve Data"):
            st.session_state.current_page = "retrieve"
            st.rerun()

# Store data page
def store_data_page():
    st.title("💾 Store New Data")
    
    data_key = st.text_input("Enter a unique name for your data:")
    user_text = st.text_area("Enter text to encrypt:")
    passkey = st.text_input("Enter a passkey:", type="password")
    confirm_passkey = st.text_input("Confirm passkey:", type="password")
    
    if st.button("Encrypt and Store"):
        if not data_key or not user_text or not passkey:
            st.error("Please fill in all fields")
        elif passkey != confirm_passkey:
            st.error("Passkeys do not match!")
        else:
            if data_key in st.session_state.stored_data:
                st.error("This data name already exists. Please choose another.")
            else:
                encrypted_text = encrypt_data(user_text, passkey)
                hashed_passkey = hash_passkey(passkey)
                
                st.session_state.stored_data[data_key] = {
                    "encrypted_text": encrypted_text,
                    "passkey": hashed_passkey
                }
                
                st.success("Data encrypted and stored successfully!")
                st.session_state.current_page = "home"
                st.rerun()
    
    if st.button("Back to Home"):
        st.session_state.current_page = "home"
        st.rerun()

# Retrieve data page
def retrieve_data_page():
    st.title("🔓 Retrieve Data")
    
    if 'attempts' not in st.session_state:
        st.session_state.attempts = 0
    
    data_key = st.selectbox("Select data to retrieve:", list(st.session_state.stored_data.keys()))
    passkey = st.text_input("Enter passkey:", type="password")
    
    if st.button("Decrypt Data"):
        if data_key in st.session_state.stored_data:
            stored_entry = st.session_state.stored_data[data_key]
            hashed_input = hash_passkey(passkey)
            
            if hashed_input == stored_entry["passkey"]:
                decrypted_text = decrypt_data(stored_entry["encrypted_text"], passkey)
                
                if decrypted_text is not None:
                    st.success("Data decrypted successfully!")
                    st.text_area("Decrypted Text:", value=decrypted_text, height=200)
                    st.session_state.attempts = 0
                else:
                    st.error("Decryption failed!")
            else:
                st.session_state.attempts += 1
                st.error(f"Incorrect passkey! Attempts: {st.session_state.attempts}/3")
                
                if st.session_state.attempts >= 3:
                    st.session_state.current_page = "login"
                    st.rerun()
        else:
            st.error("Selected data not found!")
    
    if st.button("Back to Home"):
        st.session_state.current_page = "home"
        st.rerun()

# Main app logic
def main():
    # Initialize session state
    if 'current_page' not in st.session_state:
        st.session_state.current_page = "home"
    
    # Page routing
    if st.session_state.current_page == "home":
        home_page()
    elif st.session_state.current_page == "store":
        store_data_page()
    elif st.session_state.current_page == "retrieve":
        retrieve_data_page()
    elif st.session_state.current_page == "login":
        login_page()

if __name__ == "_main_":
    main()