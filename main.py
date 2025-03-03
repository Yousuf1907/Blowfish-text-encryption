import streamlit as st
from Crypto.Cipher import Blowfish
from Crypto.Util.Padding import pad, unpad
import binascii
import secrets
import time
import random
import string
import matplotlib.pyplot as plt
import math
from collections import Counter

if 'key' not in st.session_state:
    st.session_state['key'] = secrets.token_bytes(16)

key = st.session_state['key']  
BLOCK_SIZE = Blowfish.block_size  

def blowfish_encrypt(plaintext, key):
    cipher = Blowfish.new(key, Blowfish.MODE_CBC)
    iv = cipher.iv
    ciphertext = cipher.encrypt(pad(plaintext.encode('utf-8'), BLOCK_SIZE))
    return binascii.hexlify(iv + ciphertext).decode('utf-8')

def blowfish_decrypt(ciphertext, key):
    try:
        ciphertext = binascii.unhexlify(ciphertext.encode('utf-8'))
        iv, encrypted_data = ciphertext[:BLOCK_SIZE], ciphertext[BLOCK_SIZE:]
        cipher = Blowfish.new(key, Blowfish.MODE_CBC, iv)
        decrypted = unpad(cipher.decrypt(encrypted_data), BLOCK_SIZE)
        return decrypted.decode('utf-8')
    except (ValueError, binascii.Error):
        return "Error: Invalid ciphertext or incorrect padding."

def measure_time(plaintext, key):
    start_enc = time.perf_counter()
    encrypted_text = blowfish_encrypt(plaintext, key)
    end_enc = time.perf_counter()

    start_dec = time.perf_counter()
    decrypted_text = blowfish_decrypt(encrypted_text, key)
    end_dec = time.perf_counter()

    return end_enc - start_enc, end_dec - start_dec, encrypted_text

# Calculate entropy of text
def calculate_entropy(data):
    frequency = Counter(data)
    length = len(data)
    entropy = -sum((count / length) * math.log2(count / length) for count in frequency.values())
    return entropy

st.title("Blowfish Encryption and Decryption App")

# Text Encryption
user_text = st.text_area("Enter text to encrypt:")
if st.button("Encrypt Text"):
    if user_text.strip():
        encrypted_text = blowfish_encrypt(user_text, key)
        st.session_state['encrypted_text'] = encrypted_text
        st.success("Text encrypted successfully!")
        st.code(encrypted_text, language='text')
    else:
        st.warning("Please enter text to encrypt.")

# Text Decryption
if "encrypted_text" in st.session_state:
    if st.button("Decrypt Text"):
        decrypted_text = blowfish_decrypt(st.session_state['encrypted_text'], key)
        if "Error:" in decrypted_text:
            st.error(decrypted_text)
        else:
            st.success("Text decrypted successfully!")
            st.code(decrypted_text, language='text')

# File Encryption
uploaded_file = st.file_uploader("Upload a file to encrypt", type=["txt"])
if uploaded_file is not None:
    file_contents = uploaded_file.read().decode("utf-8")
    encrypted_file_text = blowfish_encrypt(file_contents, key)
    st.session_state['encrypted_file_text'] = encrypted_file_text
    st.success("File encrypted successfully!")
    st.code(encrypted_file_text, language='text')

if "encrypted_file_text" in st.session_state:
    if st.button("Decrypt File"):
        decrypted_file_text = blowfish_decrypt(st.session_state['encrypted_file_text'], key)
        if "Error:" in decrypted_file_text:
            st.error(decrypted_file_text)
        else:
            st.success("File decrypted successfully!")
            st.text_area("Decrypted File Content:", decrypted_file_text, height=200)

# Performance Visualization
def visualize_performance():
    text_sizes = [10, 50, 100, 500, 1000, 5000, 10000]
    enc_times, dec_times, entropies = [], [], []
    
    for size in text_sizes:
        plaintext = ''.join(random.choices(string.ascii_letters + string.digits, k=size))
        enc_time, dec_time, encrypted_text = measure_time(plaintext, key)
        enc_times.append(enc_time)
        dec_times.append(dec_time)
        entropies.append(calculate_entropy(encrypted_text))

    fig, ax = plt.subplots()
    ax.plot(text_sizes, enc_times, label='Encryption Time', marker='o')
    ax.plot(text_sizes, dec_times, label='Decryption Time', marker='s')
    ax.set_xlabel('Text Size (characters)')
    ax.set_ylabel('Time (seconds)')
    ax.set_title('Encryption & Decryption Performance')
    ax.legend()
    st.pyplot(fig)

if st.button("Show Performance Visualization"):
    visualize_performance()
