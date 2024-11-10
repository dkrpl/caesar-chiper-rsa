import streamlit as st
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

# Caesar Cipher Functions
def caesar_encrypt(plain_text, shift):
    """Encrypts the message using Caesar Cipher."""
    encrypted_text = ''
    for char in plain_text:
        if char.isalpha():
            shift_base = 65 if char.isupper() else 97
            encrypted_text += chr((ord(char) - shift_base + shift) % 26 + shift_base)
        else:
            encrypted_text += char
    return encrypted_text

def caesar_decrypt(encrypted_text, shift):
    """Decrypts the message using Caesar Cipher."""
    return caesar_encrypt(encrypted_text, -shift)

# RSA Functions
def generate_rsa_keys():
    """Generate RSA private and public keys."""
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key

def encrypt_with_rsa(public_key, message):
    """Encrypts the message using RSA."""
    public_key = RSA.import_key(public_key)
    cipher = PKCS1_OAEP.new(public_key)
    encrypted_message = cipher.encrypt(message.encode())
    return encrypted_message

def decrypt_with_rsa(private_key, encrypted_message):
    """Decrypts the message using RSA."""
    private_key = RSA.import_key(private_key)
    cipher = PKCS1_OAEP.new(private_key)
    decrypted_message = cipher.decrypt(encrypted_message).decode()
    return decrypted_message

# Generate RSA keys automatically and store in session_state
if 'private_key' not in st.session_state or 'public_key' not in st.session_state:
    private_key, public_key = generate_rsa_keys()
    st.session_state.private_key = private_key
    st.session_state.public_key = public_key

# Streamlit UI
st.title("RSA + Caesar Cipher Encryption/Decryption")

# Encrypt Message (Caesar + RSA)
st.subheader("Encrypt Message with Caesar + RSA")
message = st.text_area("Enter Message to Encrypt")
caesar_shift = st.slider("Caesar Cipher Shift", 1, 25, 3)

if st.button("Encrypt Message") and message:
    # Step 1: Encrypt with Caesar Cipher
    caesar_encrypted_message = caesar_encrypt(message, caesar_shift)
    st.text_area("Caesar Encrypted Message", caesar_encrypted_message, height=150)
    
    # Step 2: Encrypt with RSA
    rsa_encrypted_message = encrypt_with_rsa(st.session_state.public_key, caesar_encrypted_message)
    st.text_area("Encrypted Message (RSA + Caesar)", rsa_encrypted_message.hex(), height=200)

# Decrypt Message (RSA + Caesar)
st.subheader("Decrypt Message with RSA + Caesar")
encrypted_message_hex = st.text_area("Enter Encrypted Message (Hex Format)")

if st.button("Decrypt Message") and encrypted_message_hex:
    try:
        # Convert hex to bytes
        encrypted_message = bytes.fromhex(encrypted_message_hex)
        
        # Step 1: Decrypt with RSA
        decrypted_message_rsa = decrypt_with_rsa(st.session_state.private_key, encrypted_message)
        st.text_area("Decrypted Message (RSA)", decrypted_message_rsa, height=150)
        
        # Step 2: Decrypt with Caesar Cipher
        decrypted_message = caesar_decrypt(decrypted_message_rsa, caesar_shift)
        st.text_area("Decrypted Message (Caesar)", decrypted_message, height=200)
    except ValueError:
        st.error("Invalid hex input.")
