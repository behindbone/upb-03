from Crypto.Protocol.KDF import PBKDF2
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
import sys

filename = sys.argv[1]

public_ = RSA.generate(3072)
private_ = public_.publickey()
pubKeyPEM = private_.exportKey()
privKeyPEM = public_.exportKey()

with open ("RSA_private_key.pem", "wb") as prv_file:
    prv_file.write(privKeyPEM)
with open ("RSA_public_key.pem", "wb") as pub_file:
    pub_file.write(pubKeyPEM)

# Key generation
salt = get_random_bytes(16)
private_key = privKeyPEM.decode('ascii')
key = PBKDF2(private_key, salt)
public_key = pubKeyPEM.decode('ascii')

# Data to encrypt
with open(filename, 'rb') as f:
        input_data = f.read()

# Encrypt using AES GCM
cipher = AES.new(key, AES.MODE_GCM)
cipher.update(public_key.encode("utf8"))
ciphertext, tag = cipher.encrypt_and_digest(input_data)

_message = public_key, ciphertext, tag, cipher.nonce, salt
with open("encrypted.aes", 'wb') as f:
    for var in _message:
        if isinstance(var, str):
            f.write(bytearray(bytes(var, encoding='utf-8')))
        else:
            f.write(bytearray(bytes(var)))


# Open encrypted file
with open("encrypted.aes", 'rb') as f:
    received_msg = f.read()

# Parse encrypted file 
received_pubKey = received_msg[:624]
received_ciphertext = received_msg[624:len(received_msg)-3*16]
received_tag = received_msg[len(received_msg)-3*16:len(received_msg)-2*16]
received_nonce = received_msg[len(received_msg)-2*16:len(received_msg)-1*16]
received_kdf_salt = received_msg[len(received_msg)-1*16:len(received_msg)]

# Decrypt
with open("RSA_private_key.pem", 'r') as f:
        RSA_private_key_file =  f.read()
decryption_key = PBKDF2(RSA_private_key_file, received_kdf_salt)
cipher = AES.new(decryption_key, AES.MODE_GCM, received_nonce)
cipher.update(received_pubKey)

# Validate
try:
    decrypted_data = cipher.decrypt_and_verify(received_ciphertext, received_tag)
    print ("\nZachovanie integrity. MAC validácia úspešná.")
    with open('decrypted_' + filename, 'wb') as f:
        data = f.write(decrypted_data)
    print ("Dešifrovaný súbor uložený ako {}.".format('decrypted_' + filename))
except ValueError as mac_mismatch:
    print ("\nPorušenie integrity. MAC validácia neúspešná pri dešifrovaní.")
    