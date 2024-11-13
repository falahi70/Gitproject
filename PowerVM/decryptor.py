from cryptography.fernet import Fernet



key = "XuJdbHbZy5Tr66D5y4EwR-jXt8iXFmiQTBAe7CVaojc=".encode("utf-8")
cipher_suite = Fernet(key)

def decrypt(password):
    password = password.encode("utf-8")
    decoded_text = cipher_suite.decrypt(password)
    return decoded_text.decode("utf-8")

def encrypt(password):
    password = password.encode("utf-8")
    encoded_text = cipher_suite.encrypt(password)
    return encoded_text.decode("utf-8")

def enc_pass(credentialUsernme, credentialPassword):
    credential_string = f"{credentialUsernme} || {credentialPassword}"
    credential_string = encrypt(credential_string)
    return credential_string