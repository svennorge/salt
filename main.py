import hashlib
import json
import re


def read_policy():
    with open("pwconfig.ini", "r") as policy_file:
        policy = json.load(policy_file)
    print(json.dumps(policy, indent=4))
    print(policy['password_Policy']['minlen'])
    return policy


def read_salt():
    # return salting strig
    pass


def shaCrypt(toCrypt):
    hash_object = hashlib.sha256(toCrypt.encode())
    hex_dig = hash_object.hexdigest()
    print(hex_dig)
    return hex_dig


def password_login(password):
    # if len(password) < min_len_pw:
    #   return false
    pass


def password_set(rules):
    while True:
        password = input('Password')
        if len(password) < rules['password_Policy']['minlen']:
            print('Kennwort kurz')
        elif len(password) > rules['password_Policy']['maxlen']:
            print('ZU Lang')
        elif re.search('[A-Z]', password) is None:
            print('Gross Kleinschreibung fehlt')
        elif re.search('[a-z]', password) is None:
            print('Kleinschreibung fehlt')
        elif re.search('[1-9]', password) is None:
            print('keine Zahl')
        else:
            return True
def login():
    user = input('UserName :')
    password = input('Passsword :')
    # return loginname
    pass


# appUser =  login()
# print("Welcome %1 ".format(),appUser)
rules = read_policy()
while not password_set(rules):
    print("valid")
