import streamlit as st
import sqlite3
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from tinyec import registry
import hashlib
import secrets
import base64

# Database setup
def init_db():
    conn = sqlite3.connect("messages.db")
    cursor = conn.cursor()
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS messages (
        id INTEGER PRIMARY KEY,
        sender TEXT,
        receiver TEXT,
        nonce BLOB,
        tag BLOB,
        ciphertext BLOB,
        enc_aes_key BLOB
    )
    """)
    conn.commit()
    conn.close()

init_db()

# ECC and RSA key generation
def generate_ecc_key_pair():
    curve = registry.get_curve('brainpoolP256r1')
    private_key = secrets.randbelow(curve.field.n)
    public_key = private_key * curve.g
    return private_key, public_key

def generate_rsa_key_pair():
    key = RSA.generate(2048)
    return key.export_key(), key.publickey().export_key()

def ecc_point_to_256_bit_key(point):
    sha = hashlib.sha256(int.to_bytes(point.x, 32, 'big'))
    sha.update(int.to_bytes(point.y, 32, 'big'))
    return sha.digest()

# Encryption
def encrypt_message(msg, ecc_public_key, rsa_public_key):
    curve = registry.get_curve('brainpoolP256r1')
    ecc_private_key = secrets.randbelow(curve.field.n)
    shared_ecc_key = ecc_private_key * ecc_public_key
    secret_key = ecc_point_to_256_bit_key(shared_ecc_key)

    cipher_aes = AES.new(secret_key, AES.MODE_GCM)
    ciphertext, tag = cipher_aes.encrypt_and_digest(msg.encode('utf-8'))

    cipher_rsa = PKCS1_OAEP.new(RSA.import_key(rsa_public_key))
    enc_aes_key = cipher_rsa.encrypt(secret_key)

    return cipher_aes.nonce, tag, ciphertext, enc_aes_key

# Decryption
def decrypt_message(enc_msg, ecc_private_key, rsa_private_key):
    nonce, tag, ciphertext, enc_aes_key = enc_msg

    cipher_rsa = PKCS1_OAEP.new(RSA.import_key(rsa_private_key))
    aes_key = cipher_rsa.decrypt(enc_aes_key)

    cipher_aes = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
    plaintext = cipher_aes.decrypt_and_verify(ciphertext, tag)

    return plaintext.decode('utf-8')

# Streamlit app
st.title("Secure Messaging App")
role = st.radio("Select your role:", ("Sender", "Receiver"))

if "keys" not in st.session_state:
    ecc_private_key, ecc_public_key = generate_ecc_key_pair()
    rsa_private_key, rsa_public_key = generate_rsa_key_pair()
    st.session_state.keys = {
        "ecc_private": ecc_private_key,
        "ecc_public": ecc_public_key,
        "rsa_private": rsa_private_key,
        "rsa_public": rsa_public_key
    }

def store_message(sender, receiver, nonce, tag, ciphertext, enc_aes_key):
    conn = sqlite3.connect("messages.db")
    cursor = conn.cursor()
    cursor.execute("INSERT INTO messages (sender, receiver, nonce, tag, ciphertext, enc_aes_key) VALUES (?, ?, ?, ?, ?, ?)",
                   (sender, receiver, nonce, tag, ciphertext, enc_aes_key))
    conn.commit()
    conn.close()

def fetch_messages(receiver):
    conn = sqlite3.connect("messages.db")
    cursor = conn.cursor()
    cursor.execute("SELECT sender, nonce, tag, ciphertext, enc_aes_key FROM messages WHERE receiver = ?", (receiver,))
    messages = cursor.fetchall()
    conn.close()
    return messages

if role == "Sender":
    receiver = st.text_input("Enter receiver's username:")
    message = st.text_area("Enter your message:")

    if st.button("Send Message"):
        ecc_public_key = st.session_state.keys["ecc_public"]
        rsa_public_key = st.session_state.keys["rsa_public"]

        nonce, tag, ciphertext, enc_aes_key = encrypt_message(message, ecc_public_key, rsa_public_key)
        store_message("Sender", receiver, nonce, tag, ciphertext, enc_aes_key)

        st.success("Message sent successfully!")

elif role == "Receiver":
    username = st.text_input("Enter your username:")

    if st.button("Fetch Messages"):
        messages = fetch_messages(username)

        if messages:
            for sender, nonce, tag, ciphertext, enc_aes_key in messages:
                enc_msg = (nonce, tag, ciphertext, enc_aes_key)
                ecc_private_key = st.session_state.keys["ecc_private"]
                rsa_private_key = st.session_state.keys["rsa_private"]

                try:
                    plaintext = decrypt_message(enc_msg, ecc_private_key, rsa_private_key)
                    st.write(f"Message from {sender}: {plaintext}")
                except Exception as e:
                    st.error("Failed to decrypt a message.")
        else:
            st.info("No messages found.")
