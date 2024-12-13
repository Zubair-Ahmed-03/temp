import streamlit as st
import sqlite3
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes
from tinyec import registry
import hashlib
import secrets
import time

# ECC and RSA key generation functions
def generate_ecc_key_pair():
    curve = registry.get_curve('brainpoolP256r1')
    private_key = secrets.randbelow(curve.field.n)
    public_key = private_key * curve.g
    return private_key, public_key

def generate_rsa_key_pair():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key

def ecc_point_to_256_bit_key(point):
    sha = hashlib.sha256(int.to_bytes(point.x, 32, 'big'))
    sha.update(int.to_bytes(point.y, 32, 'big'))
    return sha.digest()

# Encryption and decryption functions
def encrypt_message(msg, ecc_public_key, rsa_public_key):
    curve = registry.get_curve('brainpoolP256r1')
    ecc_private_key = secrets.randbelow(curve.field.n)
    shared_ecc_key = ecc_private_key * ecc_public_key
    secret_key = ecc_point_to_256_bit_key(shared_ecc_key)

    cipher_aes = AES.new(secret_key, AES.MODE_GCM)
    ciphertext, tag = cipher_aes.encrypt_and_digest(msg.encode('utf-8'))

    cipher_rsa = PKCS1_OAEP.new(RSA.import_key(rsa_public_key))
    enc_aes_key = cipher_rsa.encrypt(secret_key)

    return (cipher_aes.nonce, tag, ciphertext, enc_aes_key)

def decrypt_message(enc_msg, ecc_private_key, rsa_private_key):
    nonce, tag, ciphertext, enc_aes_key = enc_msg

    cipher_rsa = PKCS1_OAEP.new(RSA.import_key(rsa_private_key))
    aes_key = cipher_rsa.decrypt(enc_aes_key)

    cipher_aes = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
    plaintext = cipher_aes.decrypt_and_verify(ciphertext, tag)
    return plaintext.decode('utf-8')

# SQLite setup
conn = sqlite3.connect('messages.db', check_same_thread=False)
cursor = conn.cursor()
cursor.execute('''
CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sender TEXT,
    receiver TEXT,
    encrypted_message BLOB,
    nonce BLOB,
    tag BLOB,
    enc_aes_key BLOB,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
)
''')
conn.commit()

def send_message(sender, receiver, encrypted_message):
    nonce, tag, ciphertext, enc_aes_key = encrypted_message
    cursor.execute("""
        INSERT INTO messages (sender, receiver, encrypted_message, nonce, tag, enc_aes_key)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (sender, receiver, ciphertext, nonce, tag, enc_aes_key))
    conn.commit()

def get_messages(receiver):
    cursor.execute("""
        SELECT sender, encrypted_message, nonce, tag, enc_aes_key, timestamp
        FROM messages
        WHERE receiver = ?
        ORDER BY timestamp DESC
    """, (receiver,))
    return cursor.fetchall()

# Streamlit app setup
st.title("Secure Messaging App")

# Generate keys for demonstration purposes (in a real app, keys should be securely managed)
st.sidebar.header("Key Management")
if "keys" not in st.session_state:
    ecc_private_key, ecc_public_key = generate_ecc_key_pair()
    rsa_private_key, rsa_public_key = generate_rsa_key_pair()
    st.session_state["keys"] = {
        "ecc_private_key": ecc_private_key,
        "ecc_public_key": ecc_public_key,
        "rsa_private_key": rsa_private_key,
        "rsa_public_key": rsa_public_key
    }
keys = st.session_state["keys"]
st.sidebar.write("ECC Public Key:", keys["ecc_public_key"])
st.sidebar.write("RSA Public Key:", keys["rsa_public_key"].decode()[:50] + "...")

mode = st.radio("Select Mode", ("Sender", "Receiver"))

if mode == "Sender":
    st.header("Send a Secure Message")
    sender = st.text_input("Your Name")
    receiver = st.text_input("Receiver's Name")
    message = st.text_area("Message")

    if st.button("Send Message"):
        if sender and receiver and message:
            encrypted_msg = encrypt_message(
                message, 
                st.session_state.keys["ecc_public_key"], 
                st.session_state.keys["rsa_public_key"]
            )
            send_message(sender, receiver, encrypted_msg)
            st.success("Message sent successfully!")
        else:
            st.error("Please fill in all fields.")

elif mode == "Receiver":
    st.header("View Your Messages")
    receiver = st.text_input("Your Name")

    if st.button("Refresh Messages"):
        if receiver:
            messages = get_messages(receiver)
            if messages:
                for msg in messages:
                    sender, ciphertext, nonce, tag, enc_aes_key, timestamp = msg
                    encrypted_msg = (nonce, tag, ciphertext, enc_aes_key)
                    try:
                        plaintext = decrypt_message(
                            encrypted_msg, 
                            st.session_state.keys["ecc_private_key"], 
                            st.session_state.keys["rsa_private_key"]
                        )
                        st.markdown(f"**From:** {sender}")
                        st.markdown(f"**Message:** {plaintext}")
                        st.markdown(f"_Received at: {timestamp}_")
                        st.markdown("---")
                    except Exception as e:
                        st.error(f"Failed to decrypt a message: {e}")
            else:
                st.info("No messages found.")
        else:
            st.error("Please enter your name.")

# Ensure database connection closes properly
st.session_state.db_connection = conn
