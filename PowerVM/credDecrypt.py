from cryptography.fernet import Fernet



key = "XuJdbHbZy5Tr66D5y4EwR-jXt8iXFmiQTBAe7CVaojc=".encode("utf-8")
cipher_suite = Fernet(key)

def decrypt(password):
    password = password.encode("utf-8")
    decoded_text = cipher_suite.decrypt(password)
    return decoded_text.decode("utf-8")

print(decrypt("gAAAAABiKLe_gg8aA4lt1eXLjrNpwTaPKZLmwOUQv1WQXrfZ3caYrtuAKukeVqMZt_eg5cP-2fwUUPwVlOdfrWy0Qgb6DEuseWWRIHihvgU1YoqIbqRmOt-M1_y-2TEDCOTiOiVmCjkH"))
