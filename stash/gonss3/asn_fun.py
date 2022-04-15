#!/usr/bin/env python
from hashlib import sha1
from binascii import hexlify, unhexlify
import hmac

verbose = True


def decrypt3DES(globalSalt, masterPassword, entrySalt, encryptedData):
    # see http://www.drh-consultancy.demon.co.uk/key3.html
    hp = sha1(globalSalt + masterPassword).digest()
    pes = entrySalt + '\x00' * (20 - len(entrySalt))
    chp = sha1(hp + entrySalt).digest()
    k1 = hmac.new(chp, pes + entrySalt, sha1).digest()
    print(hexlify(k1))
    tk = hmac.new(chp, pes, sha1).digest()
    k2 = hmac.new(chp, tk + entrySalt, sha1).digest()
    k = k1 + k2
    iv = k[-8:]
    key = k[:24]
    if verbose:
        print 'key=' + hexlify(key), 'iv=' + hexlify(iv)


globalSalt = unhexlify(
    "0cf8cf1d97e4adb125b6f65fcaed9895ddc2eb46")
entrySalt = unhexlify(
    "6e6e3f5c8fa74b6b172f28c77d81be557cffa6fc")
ct = unhexlify("8500f522bc91de080bb64c2af8331eac")

data = decrypt3DES(globalSalt, "", entrySalt, ct)
