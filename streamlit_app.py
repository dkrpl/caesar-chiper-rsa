import streamlit as st
import sqlite3
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import pandas as pd

# Caesar Cipher Functions
def caesar_encrypt(plain_text, shift):
    encrypted_text = ''
    for char in plain_text:
        if char.isalpha():
            shift_base = 65 if char.isupper() else 97
            encrypted_text += chr((ord(char) - shift_base + shift) % 26 + shift_base)
        else:
            encrypted_text += char
    return encrypted_text

def caesar_decrypt(encrypted_text, shift):
    return caesar_encrypt(encrypted_text, -shift)

# RSA Functions
def generate_rsa_keys():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key

def encrypt_with_rsa(public_key, message):
    public_key = RSA.import_key(public_key)
    cipher = PKCS1_OAEP.new(public_key)
    encrypted_message = cipher.encrypt(message.encode())
    return encrypted_message

def decrypt_with_rsa(private_key, encrypted_message):
    private_key = RSA.import_key(private_key)
    cipher = PKCS1_OAEP.new(private_key)
    decrypted_message = cipher.decrypt(encrypted_message).decode()
    return decrypted_message

# Database Setup
def create_database():
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    cursor.execute(""" 
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            full_name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            encrypted_password TEXT NOT NULL,
            rsa_private_key TEXT NOT NULL,
            rsa_public_key TEXT NOT NULL
        )
    """)
    conn.commit()
    conn.close()

# Store RSA keys in session_state
if 'private_key' not in st.session_state or 'public_key' not in st.session_state:
    private_key, public_key = generate_rsa_keys()
    st.session_state.private_key = private_key
    st.session_state.public_key = public_key

# Initialize database
create_database()

# Streamlit UI
st.title("Secure User Registration & Login System")

# Handle logout
def logout():
    st.session_state.logged_in = False
    st.session_state.username = None
    st.rerun()  # Rerun to show the login page

# Add Logout button if user is logged in
if 'logged_in' in st.session_state and st.session_state.logged_in:
    menu = st.sidebar.selectbox("Menu", ["Encrypt/Decrypt", "Profile", "View Registered Accounts"])

    if st.sidebar.button("Logout"):
        logout()

    if menu == "Encrypt/Decrypt":
        st.subheader("RSA + Caesar Cipher Encryption/Decryption")

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

    elif menu == "Profile":
        st.subheader("User Profile")
        username = st.session_state.username

        # Fetch user data from the database
        conn = sqlite3.connect("users.db")
        cursor = conn.cursor()
        cursor.execute("SELECT full_name, email, encrypted_password FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()
        conn.close()

        if user:
            full_name, email, encrypted_password = user

            st.write("**Username:**", username)
            st.write("**Full Name:**", full_name)
            st.write("**Email:**", email)
            encrypted_password_input = st.text_area("Encrypted Password (RSA + Caesar)", encrypted_password)
            # Decrypt User Password (using session data)
            if 'username' in st.session_state:
                username = st.session_state.username

                # Fetch user data from the database
                conn = sqlite3.connect("users.db")
                cursor = conn.cursor()
                cursor.execute("SELECT encrypted_password, rsa_private_key FROM users WHERE username = ?", (username,))
                user = cursor.fetchone()
                conn.close()

                if user:
                    encrypted_password_hex, rsa_private_key = user

                    # Provide input for Caesar Cipher shift first
                    caesar_shift = st.slider("Caesar Cipher Shift", 1, 25, 3, key="caesar_decrypt")

                    # Provide input for manually entering the encrypted password to decrypt
                    #  = st.text_input("Enter Encrypted Password Hex")

                    if encrypted_password_input and st.button("Decrypt Password"):
                        try:
                            # Convert the entered hex input to bytes
                            encrypted_password = bytes.fromhex(encrypted_password_input)

                            # Step 1: Decrypt password with RSA
                            decrypted_password_rsa = decrypt_with_rsa(rsa_private_key.encode(), encrypted_password)
                            st.text_area("Decrypted Password (RSA)", decrypted_password_rsa, height=150)

                            # Step 2: Decrypt password with Caesar Cipher
                            decrypted_password = caesar_decrypt(decrypted_password_rsa, caesar_shift)
                            st.text_area("Decrypted Password (Caesar)", decrypted_password, height=200)

                        except ValueError:
                            st.error("Invalid hex input or decryption failed.")
                else:
                    st.error("User not found.")

    elif menu == "View Registered Accounts":
        st.subheader("Registered Accounts")
        conn = sqlite3.connect("users.db")
        cursor = conn.cursor()
        cursor.execute("SELECT username, full_name, email, encrypted_password FROM users")
        users = cursor.fetchall()
        conn.close()

        if users:
            # Add Serial Number (No Urut) to each row
            users_with_serial = [(index + 1, *user) for index, user in enumerate(users)]
            
            # Create a dataframe for a better view
            df = pd.DataFrame(users_with_serial, columns=["No Urut", "Username", "Full Name", "Email", "Encrypted Password"])

            # Display table with some styling
            st.write("### User List")
            st.markdown("""
                <style>
                .dataframe td, .dataframe th {
                    padding: 10px;
                    text-align: center;
                }
                .dataframe {
                    border: 1px solid black;
                    border-collapse: collapse;
                    width: 100%;
                }
                .dataframe th {
                    background-color:rgb(22, 20, 20);
                }
                .dataframe tr:nth-child(even) {
                    background-color:rgb(15, 15, 15);
                }
                </style>
            """, unsafe_allow_html=True)

            st.table(df)
        else:
            st.error("No users found.")

else:
    # Registration and Login pages
    menu = st.sidebar.selectbox("Menu", ["Register", "Login"])

    if menu == "Register":
        st.subheader("Register")
        username = st.text_input("Username")
        full_name = st.text_input("Full Name")
        email = st.text_input("Email")
        password = st.text_input("Password", type="password")
        caesar_shift = st.slider("Caesar Cipher Shift", 1, 25, 3)

        if st.button("Register"):
            if username and full_name and email and password:
                try:
                    # Step 1: Encrypt password with Caesar Cipher
                    caesar_encrypted_password = caesar_encrypt(password, caesar_shift)

                    # Step 2: Encrypt Caesar-encrypted password with RSA
                    rsa_encrypted_password = encrypt_with_rsa(st.session_state.public_key, caesar_encrypted_password)

                    # Save user data into the database
                    conn = sqlite3.connect("users.db")
                    cursor = conn.cursor()
                    cursor.execute(""" 
                        INSERT INTO users (username, full_name, email, encrypted_password, rsa_private_key, rsa_public_key)
                        VALUES (?, ?, ?, ?, ?, ?)
                    """, (username, full_name, email, rsa_encrypted_password.hex(), st.session_state.private_key.decode(), st.session_state.public_key.decode()))
                    conn.commit()
                    conn.close()

                    st.success("User registered successfully!")
                except sqlite3.IntegrityError:
                    st.error("Username or email already exists.")
            else:
                st.error("Please fill in all fields.")

    elif menu == "Login":
        st.subheader("Login")
        username = st.text_input("Username")
        password = st.text_input("Password", type="password")
        caesar_shift = st.slider("Caesar Cipher Shift", 1, 25, 3)

        if st.button("Login"):
            if username and password:
                # Fetch user data from the database
                conn = sqlite3.connect("users.db")
                cursor = conn.cursor()
                cursor.execute("SELECT encrypted_password, rsa_private_key FROM users WHERE username = ?", (username,))
                user = cursor.fetchone()
                conn.close()

                if user:
                    encrypted_password_hex, rsa_private_key = user
                    encrypted_password = bytes.fromhex(encrypted_password_hex)

                    try:
                        # Step 1: Decrypt password with RSA
                        decrypted_password_rsa = decrypt_with_rsa(rsa_private_key.encode(), encrypted_password)

                        # Step 2: Decrypt password with Caesar Cipher
                        decrypted_password = caesar_decrypt(decrypted_password_rsa, caesar_shift)

                        if decrypted_password == password:
                            st.session_state.logged_in = True
                            st.session_state.username = username
                            st.success("Login successful!")
                            st.rerun()  # Rerun to show the encryption/decryption page
                        else:
                            st.error("Incorrect password.")
                    except ValueError:
                        st.error("Decryption failed. Check your Caesar Cipher shift.")
                else:
                    st.error("User not found.")
            else:
                st.error("Please fill in all fields.")
