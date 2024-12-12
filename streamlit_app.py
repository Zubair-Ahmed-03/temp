import streamlit as st
import sqlite3
import time

# Initialize SQLite database
conn = sqlite3.connect('messages.db', check_same_thread=False)
cursor = conn.cursor()

# Create a table for messages
cursor.execute('''
CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sender TEXT,
    receiver TEXT,
    message TEXT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
)
''')
conn.commit()

# Helper function to send a message
def send_message(sender, receiver, message):
    cursor.execute("INSERT INTO messages (sender, receiver, message) VALUES (?, ?, ?)", (sender, receiver, message))
    conn.commit()

# Helper function to fetch messages for the receiver
def get_messages(receiver):
    cursor.execute("SELECT sender, message, timestamp FROM messages WHERE receiver = ? ORDER BY timestamp DESC", (receiver,))
    return cursor.fetchall()

# Streamlit app
st.title("Message Sender/Receiver App")

# Select mode: Sender or Receiver
mode = st.radio("Select Mode", ("Sender", "Receiver"))

if mode == "Sender":
    st.header("Send a Message")
    sender = st.text_input("Your Name")
    receiver = st.text_input("Receiver's Name")
    message = st.text_area("Message")

    if st.button("Send Message"):
        if sender and receiver and message:
            send_message(sender, receiver, message)
            st.success("Message sent successfully!")
        else:
            st.error("Please fill in all fields.")

elif mode == "Receiver":
    st.header("View Messages")
    receiver = st.text_input("Your Name")

    if st.button("Refresh Messages"):
        if receiver:
            messages = get_messages(receiver)
            if messages:
                for msg in messages:
                    st.markdown(f"**From:** {msg[0]}  ")
                    st.markdown(f"**Message:** {msg[1]}  ")
                    st.markdown(f"_Received at: {msg[2]}_  ")
                    st.markdown("---")
            else:
                st.info("No messages found.")
        else:
            st.error("Please enter your name.")

# Close the database connection on app exit
st.on_event("shutdown", lambda: conn.close())
