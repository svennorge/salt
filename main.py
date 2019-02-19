import hashlib
import json
import getpass


def read_policy():
    with open("pwconfig.ini", "r") as policy_file:
        policy = json.load(policy_file)
    # print(json.dumps(policy, indent=4))
    print(policy['password_Policy']['minlen'])
    return policy


def read_salt():
    # return salting
    pass


def shaCrypt(toCrypt):
    hash_object = hashlib.sha256(toCrypt.encode())
    hex_dig = hash_object.hexdigest()
    print(hex_dig)


def password_login(password):
    # if len(password) < min_len_pw:
    #   return false
    pass


def password_set(rules):
    password = input('Password')
    if len(password) < rules['password_Policy']['minlen']:
        print('Kennwort kurz')
        return False
    elif len(password) > rules['password_Policy']['maxlen']:
        print('ZU Lang')
        return False
    else:
        print('PW Korrekt')
        return True


def login():
    user = input('UserName :')
    password = input('Passsword :')
    # return loginname
    pass


# appUser =  login()
# print("Welcome %1 ".format(),appUser)
p = getpass.getpass('Input')
print(p)
rules = read_policy()
while not password_set(rules):
    print("valid")
