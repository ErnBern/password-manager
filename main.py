import string, random, os
from cryptography.fernet import Fernet

clear = ''

#Creating/opening the master password file
try: master_pw_file = open("masterpw.txt", 'r+')
except: master_pw_file = open("masterpw.txt", 'x+')
master_string = master_pw_file.readlines()


#Setting the clear command
if os.name == 'nt':
    clear = 'CLS'
else:
    clear = 'clear'

type = ''

reset_password = False

def startup():
    global reset_password
    os.system(clear)
    with open('masterpw.txt', 'w+') as master_pw_file:
        password = input("Please create your master password:\n")
        master_key = Fernet.generate_key()
        fernet = Fernet(master_key)
        encrypted_password = fernet.encrypt(password.encode()).decode('utf-8')
        master_pw_file.write(f"{encrypted_password}\n")
        master_pw_file.write(master_key.decode('utf8'))
        reset_password = True
        os.system(clear)
    return

def generate(length, security_type):
    if not length.isdigit() and not security_type.isdigit():
        print("Invalid Length and Security Type")
        return
    if not length.isdigit(): 
        print("Invalid Length")
        return
    if not security_type.isdigit():
        print("Invalid Security Type")
        return
    length = int(length)
    security_type = int(security_type)
    if security_type > 3 or security_type < 0:
        print("Invalid security type")
        return
    if security_type == 1:
        letters = string.ascii_letters
        return ''.join(random.choice(letters) for i in range(length))
    if security_type == 2:
        letters = string.ascii_letters + string.digits
        return ''.join(random.choice(letters) for i in range(length))
    if security_type == 3:
        letters = string.ascii_letters + string.digits + string.punctuation
        return ''.join(random.choice(letters) for i in range(length))

def encrypt(message, key):
        return Fernet(key).encrypt(message).decode('utf-8')


def decrypt(message, token):
    return Fernet(token).decrypt(message).decode('utf-8')

def checker(type):
    lowercase = type.lower()
    if lowercase == 'a':
        app = input("Website/App:\n")
        username = input(f"Username:\n")
        confirm = input("Generate Password? (y/n):\n")
        if confirm.lower() == 'y':
            security = input("Please Select the security type\n1. Uppercase And Lowercase Letters\n2. Option 1 but With Numbers\n3. Option 2 but With Special Characters\n")
            length = input("Password Length:\n")
            password = generate(length, security)
            print(password)
            if not password: return mainpage()
            with open('passwords.txt', 'rb') as file:
                passwords_array = file.readlines()
                place = len(passwords_array)
                key = passwords_array[0]
            with open('passwords.txt', 'a') as file:
                entry = encrypt(f"{place}. Website/App: {username} App: {app} Password: {password}".encode(), key)
                file.write(f'\n{entry}')
            return
        if confirm.lower() == 'n':
            password = input("Password:\n")
            if not password: return mainpage()
            with open('passwords.txt', 'rb') as file:
                passwords_array = file.readlines()
                place = len(passwords_array)
                key = passwords_array[0]
            with open('passwords.txt', 'a') as file:
                entry = encrypt(f"{place}. Website/App: {username} App: {app} Password: {password}".encode(), key)
                file.write(f'\n{entry}')
                file.close()
            return
    if lowercase == 'e': exit()

    if lowercase == 'd':
        order = input("Order: ")
        if not order.isdigit():return mainpage()
        order = int(order) - 1
        with open('passwords.txt', 'rb') as file:
            key = file.readlines()[0].decode("utf-8").strip().encode('utf-8')
        with open('passwords.txt', 'r') as file:
            encrypted_passwords = file.readlines()
            decrypted_passwords = []
            for password in encrypted_passwords:
                if password.strip().encode('utf-8') == key: continue
                decrypted_passwords.append(decrypt(password.strip().encode('utf-8'), key))
        password = decrypted_passwords[order]
        decrypted_passwords.remove(password)
        with open('passwords.txt', 'w+') as file:
            file.write(key.decode('utf-8'))
            repeats = 0
            for password in decrypted_passwords:
                if repeats == order + 1: break
                repeats += 1
                removed_placement = password.split(f'{repeats + 1}.')[1]
                encrypted_password = encrypt(f'{repeats}. {removed_placement}'.encode('utf-8'), key)
                file.write(f'\n{encrypted_password}')
        return
    if lowercase == 'da':
        with open('passwords.txt', 'w+') as file:
            key = Fernet.generate_key().decode('utf-8')
            file.write(key)
            file.close()
    if lowercase == 'r': startup()
            
                
def mainpage():
    with open('passwords.txt', 'r') as f:
        f.close()
    passwords_write = open('passwords.txt', 'a+')
    passwords_read = open('passwords.txt', 'r')
    passwords = passwords_read.readlines()
    try:
        key = passwords[0].strip().encode('utf-8')
    except:
        print('a')
        key = Fernet.generate_key().decode('utf-8')
        passwords_write.write(key)
        passwords_write.close()
        passwords_read.close()
        
    decrypted_passwords = []
    if len(passwords) <= 1: 
        global reset_password
        print("There are currently no stored passwords")
        user_input = input("To add a new password type a, r to reset your master password to exit type e:\n")
        checker(user_input)
        if user_input.lower() not in ['a', 'r' 'e'] and not reset_password:
            print('Invalid Option')
            mainpage()
            return
        if reset_password:
            reset_password = False
        return

    for password in passwords:
        if password.strip().encode('utf-8') == key: continue
        decrypted_password = decrypt(password.strip().encode(), key)
        decrypted_passwords.append(decrypted_password)
    print("Stored Info:")
    print('\n'.join(decrypted_passwords))
    user_input = input("To add a new password type a, to delete a password type d, to delete all paswords type da, to reset your master password type r, to exit type e:\n")
    checker(user_input)

i = 0


if not master_string:
    startup()
    try: master_pw_file = open("masterpw.txt", 'r+')
    except: master_pw_file = open("masterpw.txt", 'x+')
    master_string = master_pw_file.readlines()
    master_password = master_string[0].split('\n')[0].encode('utf-8')
    master_key = master_string[1].encode('utf-8')

master_password = master_string[0].split('\n')[0].encode('utf-8')
master_key = master_string[1].encode('utf-8')
decrypted_master_password = decrypt(master_password, master_key)

password_input = input('Password: ')

while password_input !=  decrypted_master_password:
    i += 1
    if i >= 10:
        os.system(clear)
        print("Too many invalid passwords!")
        master_pw_file.close()
        exit()
    os.system(clear)
    print("Invalid password!")
    password_input = input('Password: ')
    master_pw_file.close()

os.system(clear)

run = True
while run == True:
    mainpage()
