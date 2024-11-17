import streamlit as st
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import base64

# Utility Functions
def generate_key():
    """Generate a random 16-byte AES key"""
    return get_random_bytes(16)

def pad_text(text):
    """Add padding to the text to make its length a multiple of 16 bytes"""
    padding_length = 16 - (len(text) % 16)
    return text + chr(padding_length) * padding_length

def unpad_text(text):
    """Remove padding from the text"""
    padding_length = ord(text[-1])
    return text[:-padding_length]

def encrypt_long_text(text, key):
    """Encrypt long text using AES in CBC mode"""
    cipher = AES.new(key, AES.MODE_CBC)
    padded_text = pad_text(text)
    ciphertext = cipher.encrypt(padded_text.encode('utf-8'))
    encrypted_data = {
        "iv": base64.b64encode(cipher.iv).decode('utf-8'),
        "ciphertext": base64.b64encode(ciphertext).decode('utf-8'),
    }
    return encrypted_data

def decrypt_long_text(encrypted_data, key):
    """Decrypt long text using AES in CBC mode"""
    try:
        iv = base64.b64decode(encrypted_data['iv'])
        ciphertext = base64.b64decode(encrypted_data['ciphertext'])
        cipher = AES.new(key, AES.MODE_CBC, iv=iv)
        decrypted_text = cipher.decrypt(ciphertext).decode('utf-8')
        return unpad_text(decrypted_text)
    except Exception as e:
        return f"Decryption failed: {e}"

# Streamlit App
st.title("AES with CBC ( include key and IV )")
st.write("This app uses AES encryption to secure long text. Save the generated key for decryption.")

# Key Generation
if "key" not in st.session_state:
    st.session_state.key = generate_key()

st.subheader("1. Encryption")
text_to_encrypt = st.text_area("Enter text to encrypt (no length limit):")
if st.button("Encrypt"):
    if text_to_encrypt:
        key = st.session_state.key
        encrypted_result = encrypt_long_text(text_to_encrypt, key)
        st.write("**Encrypted Data:**")
        st.json(encrypted_result)
        st.write("**Key (Save this!):**", base64.b64encode(key).decode('utf-8'))
    else:
        st.error("Please enter text to encrypt.")

st.subheader("2. Decryption")
iv = st.text_input("Enter IV:")
ciphertext = st.text_input("Enter Ciphertext:")
key_input = st.text_input("Enter Key (Base64):", type="password")

if st.button("Decrypt"):
    if iv and ciphertext and key_input:
        try:
            key = base64.b64decode(key_input)
            encrypted_data = {"iv": iv, "ciphertext": ciphertext}
            decrypted_text = decrypt_long_text(encrypted_data, key)
            st.write("**Decrypted Text:**", decrypted_text)
        except Exception as e:
            st.error(f"Decryption failed: {e}")
    else:
        st.error("Please fill all the fields for decryption.")
