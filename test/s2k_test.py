# generate test cases from PGP python

import Crypto
import pgp

MD5 = 1
SHA1 = 2

DES3 = 2
AES128 = 7


def create_simple(password):
    stk = pgp.s2k.SimpleS2K(MD5, DES3)
    key = stk.to_key(password)
    return key

def create_salted(password, salt):
    stk = pgp.s2k.SaltedS2K(MD5, DES3, salt)
    key = stk.to_key(password)
    return key

def create_iter_salted(password, salt, count):
    stk = pgp.s2k.IteratedAndSaltedS2K(MD5, DES3, salt, count)
    key = stk.to_key(password)
    return key

def format_hex_key(key):
    string = ""
    for i in range(len(key)):
        string += format(key[i], '02X')
    return "16#"+string

def main():
    k = create_simple(b"Hello")
    print(format_hex_key(k))
    k = create_salted(b"Hello", b"12345678")
    print(format_hex_key(k))
    k = create_iter_salted(b"Hello", b"12345678", 9728)
    print(format_hex_key(k))
    
