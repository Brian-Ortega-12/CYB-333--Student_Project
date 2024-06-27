import secrets
import string

def generate_password(password_length):

    characters = string.ascii_letters + string.digits

    secure_password = "".join(secrets.choice(characters) for i in range(password_length))

    return secure_password

def main():

    user_password_length = int(input("Inout number of digits for password generation: "))

    print("Password Generated: ", generate_password(user_password_length))

main()
