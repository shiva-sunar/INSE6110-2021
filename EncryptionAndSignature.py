#!/usr/bin/python3

def aPOWbMODm(a, b, m):
    assert a >= 0
    assert b >= 0
    assert m > 0
    if a == 0:
        return 0
    if b == 0:
        return 1
    a = a % m
    if b % 2 == 0:
        answer = aPOWbMODm(a, b/2, m)
        answer = (answer*answer) % m
    else:
        answer = (a*aPOWbMODm(a, b-1, m))
    return (answer+m) % m

# algorithm as per our lecture slide
def extendedEuclideanGCD(a, b):
    x = 1
    y = 0
    d = a
    r = 0
    s = 1
    t = b
    while(t > 0):
        q = d//t
        u = x-q*r
        v = y-q*s
        w = d-q*t
        x = r
        y = s
        d = t
        r = u
        s = v
        t = w
    return d, x, y


def stringToHex(string):
    converted = ""
    for c in string:
        converted += str(format(ord(c), "x"))
    return converted


def hexToString(string):
    x = bytearray.fromhex(string).decode()
    return x


def hexToDec(hexa):
    return int(hexa, 16)


def decToHex(dec):
    return str(hex(dec))[2:]


def encrypt(num, e, N):
    return aPOWbMODm(num, e, N)


def decrypt(num, d, N):
    return aPOWbMODm(num, d, N)


def encryptMessageToPartner():
    e = 27799  # partner's e
    N = 165862241  # partner's N
    message = "Hi-Riya-Hello-From-Shiva!!!"
    encrypted = []
    chunks = [message[i:i+3] for i in range(0, len(message), 3)]
    for c in chunks:
        hexb = stringToHex(c)
        dec = hexToDec(hexb)
        enc = encrypt(dec, e, N)
        encrypted.append(enc)
    print("The message to Partner:", message)
    print("Partners key:(e=", e, ", N=", N, ")")
    print("Message Chunks:", chunks)
    print("Encrypted Message:", encrypted)


def decryptMessageFromPartner():
    encrptedMessageFromPartner = [880248732, 2326532686, 538046734, 1891347078,
                                  2460709033, 1696673335, 271255283, 880248732, 2326532686, 2194216549]
    d = 807638153  # My d
    N = 2493396179  # My N
    decrypted = []
    for i in encrptedMessageFromPartner:
        plain = decrypt(i, d, N)
        # print("i->",i)
        # print("decrypt(i, d, N)->", plain)
        rehex = decToHex(plain)
        # print(rehex,end="")
        decString = hexToString(rehex)
        # # print(decString)
        decrypted.append(decString)
    print("Encrypted Message from Partner:", encrptedMessageFromPartner)
    print("Partners Message Chunk After Decrypt:", decrypted)
    print("Message Decrypted with My Private Key:", end="")
    for dm in decrypted:
        print(dm, end="")


def mySignature():
    d = 807638153  # My d
    N = 2493396179  # My N
    originalMessage = "Shiva-Sunar"
    messageSignature = []
    chunks = [originalMessage[i:i+3]
              for i in range(0, len(originalMessage), 3)]
    for c in chunks:
        hexb = stringToHex(c)
        dec = hexToDec(hexb)
        enc = encrypt(dec, d, N)
        messageSignature.append(enc)
    print("My Original Message:", originalMessage)
    print("Message Chunks to be Signed", chunks)
    print("My Message Signature:", messageSignature)


def verifyPartnersSignature():
    partnersSignedMessage = [127501024, 88939517, 45891312, 148387753]
    partnersOriginalMessage = "RIYA--POBARI"
    e = 27799  # partner's e
    N = 165862241  # partner's N
    decrypted = ""
    for i in partnersSignedMessage:
        plain = decrypt(i, e, N)
        rehex = decToHex(plain)
        decString = hexToString(rehex)
        decrypted += decString
    print("Message Signature from Partner:", partnersSignedMessage)
    print("Message Decrypted with Partner's Public Key:", decrypted)
    print("Does the Signature Matches???:",
          decrypted == partnersOriginalMessage)

#The Main Program Starts from here.
print("\n------------------------------\n")
encryptMessageToPartner()
print("\n------------------------------\n")
decryptMessageFromPartner()
print("\n------------------------------\n")
mySignature()
print("\n------------------------------\n")
verifyPartnersSignature()
print("\n------------------------------\n")
