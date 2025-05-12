import streamlit as st
import hashlib
from cryptography.fernet import Fernet
import base64

# Initialize session state
if 'stored_data' not in st.session_state:
    st.session_state.stored_data = {}
if 'login_attempts' not in st.session_state:
    st.session_state.login_attempts = 0
if 'logged_in' not in st.session_state:
    st.session_state.logged_in = False
if 'current_page' not in st.session_state:
    st.session_state.current_page = "save"

# Security functions
def encrypt(text, password):
    key = base64.urlsafe_b64encode(hashlib.sha256(password.encode()).digest()[:32])
    return Fernet(key).encrypt(text.encode()).decode()

def decrypt(encrypted, password):
    try:
        key = base64.urlsafe_b64encode(hashlib.sha256(password.encode()).digest()[:32])
        return Fernet(key).decrypt(encrypted.encode()).decode()
    except:
        return None

# Beautiful button styling
st.markdown("""
<style>
    .nav-btn {
        border-radius: 15px !important;
        padding: 15px !important;
        font-weight: bold !important;
        font-size: 16px !important;
        transition: all 0.3s !important;
        box-shadow: 0 4px 8px rgba(0,0,0,0.1) !important;
        margin: 5px !important;
    }
    .nav-btn:hover {
        transform: translateY(-2px) !important;
        box-shadow: 0 6px 12px rgba(0,0,0,0.15) !important;
    }
    .save-btn {
        background: linear-gradient(135deg, #4CAF50, #2E7D32) !important;
        color: white !important;
        border: none !important;
    }
    .retrieve-btn {
        background: linear-gradient(135deg, #2196F3, #1565C0) !important;
        color: white !important;
        border: none !important;
    }
    .action-btn {
        background: linear-gradient(135deg, #FF9800, #F57C00) !important;
        color: white !important;
        border: none !important;
    }
    .logout-btn {
        background: linear-gradient(135deg, #f44336, #d32f2f) !important;
        color: white !important;
        border: none !important;
        width: 150px !important;
        margin: 20px auto !important;
    }
</style>
""", unsafe_allow_html=True)

def main():
    if not st.session_state.logged_in:
        # Login Page
        st.title("🔐 Secret Vault Login")
        col1, col2 = st.columns([1,2])
        with col1:
            st.image("https://cdn-icons-png.flaticon.com/512/295/295128.png", width=80)
        with col2:
            password = st.text_input("Enter Password", type="password")
            if st.button("Unlock Vault", key="login_btn", help="Enter the master password"):
                if password == "admin123":
                    st.session_state.logged_in = True
                    st.rerun()
                else:
                    st.session_state.login_attempts += 1
                    if st.session_state.login_attempts >= 3:
                        st.error("Too many attempts! Try again later.")
                        st.stop()
                    st.error(f"Wrong password! ({st.session_state.login_attempts}/3 tries)")
    else:
        # Main App
        st.title("🔒 My Secret Vault")
        
        # Beautiful navigation buttons
        col1, col2 = st.columns(2)
        with col1:
            if st.button("💾 Save Secret", key="save_btn", help="Store new encrypted data", 
                        use_container_width=True, type="primary", 
                        kwargs={"class": "nav-btn save-btn"}):
                st.session_state.current_page = "save"
                st.rerun()
        with col2:
            if st.button("🔓 View Secrets", key="retrieve_btn", help="Retrieve your saved data", 
                         use_container_width=True, type="primary", 
                         kwargs={"class": "nav-btn retrieve-btn"}):
                st.session_state.current_page = "retrieve"
                st.rerun()
        
        # Page content
        if st.session_state.current_page == "save":
            st.subheader("Store New Secret")
            name = st.text_input("Secret Name", placeholder="e.g. 'Bank Password'")
            text = st.text_area("Your Secret", placeholder="Enter your sensitive data here...")
            key = st.text_input("Encryption Key", type="password", 
                              placeholder="Create a strong encryption key")
            if st.button("🔒 Encrypt & Save", key="encrypt_btn", 
                        use_container_width=True, type="primary", 
                        kwargs={"class": "action-btn"}):
                if name and text and key:
                    st.session_state.stored_data[name] = {
                        "encrypted": encrypt(text, key),
                        "key_hash": hashlib.sha256(key.encode()).hexdigest()
                    }
                    st.success("Secret saved securely!")
                else:
                    st.warning("Please fill all fields!")
        
        elif st.session_state.current_page == "retrieve":
            st.subheader("Your Secrets")
            if st.session_state.stored_data:
                secret = st.selectbox("Select Secret", list(st.session_state.stored_data.keys()))
                if key := st.text_input("Decryption Key", type="password", 
                                       placeholder="Enter your encryption key"):
                    if dec := decrypt(st.session_state.stored_data[secret]["encrypted"], key):
                        st.text_area("Decrypted Secret", dec, height=200)
                    else:
                        st.error("❌ Wrong key! Try again")
            else:
                st.info("No secrets stored yet")
        
        # Centered logout button
        st.markdown("<div style='text-align: center;'>", unsafe_allow_html=True)
        if st.button("🚪 Logout", key="logout_btn", 
                    use_container_width=False, type="primary", 
                    kwargs={"class": "logout-btn"}):
            st.session_state.logged_in = False
            st.rerun()
        st.markdown("</div>", unsafe_allow_html=True)

if __name__ == "__main__":
    main()