import struct

from Crypto.Cipher import CAST, AES
from Crypto.Hash import SHA1
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad
from Crypto.Util.number import bytes_to_long, long_to_bytes






def generisanjePoruke(passphrase : str , IDA:str , IDB : str , message :str, fajl_poslata_poruka:str , privatniPrstenovi, javniPrstenovi, algoritam:str):
    h = SHA1.new()
    b = passphrase.encode()
    h.update(b)
    hash = h.hexdigest() # 40 byte
    prsten = None

    for i in range (len(privatniPrstenovi)):
        if(IDA == privatniPrstenovi[i].userID):
            prsten = privatniPrstenovi[i]
            break
    if prsten==None:
        print("GRESKA NE POSTOJI PRSTEN ZA "+ IDA)
        return

    keyCip = hash[0:len(hash) - 8]
    byte_array = bytes.fromhex(keyCip)
    old_iv = prsten.privateKey[:8]
    cipher = CAST.new(byte_array, CAST.MODE_CFB, old_iv)

    dekriptovanPrivatniKljuc = cipher.decrypt(prsten.privateKey[8:])
    h1 = SHA1.new()
    b1 = message.encode()
    h1.update(b1)
    hash1 = h1.hexdigest()

    p,q,d = deserialize_private_key(dekriptovanPrivatniKljuc)
    poruka = int.from_bytes(bytes.fromhex(hash1))

    potpis = pow(poruka, d, p*q)
    potpis = long_to_bytes(potpis)
    poruka = message.encode()
    poruka = prsten.keyID + len(poruka).to_bytes(4) +  poruka + potpis


    # Encrypt
    prsten = None
    for p in javniPrstenovi:
        if IDB == p.userID:
            prsten = p
            break
    e,n = deserialize_public_key(prsten.publicKey)

    if algoritam=='AES':
        sym_key = get_random_bytes(16)  # AES-128 key is 16 bytes long
        cipher = AES.new(sym_key, AES.MODE_CBC)
        iv = cipher.iv  # Initialization vector
        ciphertext = cipher.encrypt(pad(poruka, AES.block_size))
    elif algoritam=='CAST':
        sym_key = get_random_bytes(16)  # CAST key is 16 bytes long
        cipher = CAST.new(sym_key, CAST.MODE_CBC)
        iv = cipher.iv  # Initialization vector
        ciphertext = cipher.encrypt(pad(poruka, CAST.block_size))



    enkriptovan_sym_key = pow(int.from_bytes(sym_key), e, n)
    enkriptovan_sym_key = long_to_bytes(enkriptovan_sym_key)
    poruka = (b'A' if algoritam=='AES' else b'C') + len(iv).to_bytes(1) + iv + len(ciphertext).to_bytes(4)+ ciphertext+ prsten.keyID + enkriptovan_sym_key

    with open(fajl_poslata_poruka, 'w') as fajl:
        fajl.write(poruka.hex())
    return poruka


def deserialize_private_key(serialized_key):
    offset = 0
    p_len = int.from_bytes(serialized_key[offset:offset+2])
    offset+= 2
    p = bytes_to_long(serialized_key[offset:offset+p_len])
    offset += p_len

    q_len = int.from_bytes(serialized_key[offset:offset + 2])
    offset += 2
    q = bytes_to_long(serialized_key[offset:offset + q_len])
    offset += q_len

    d_len = int.from_bytes(serialized_key[offset:offset + 2])
    offset += 2
    d = bytes_to_long(serialized_key[offset:offset + d_len])
    offset += d_len



    return p, q, d




def deserialize_public_key(serialized_key):
    offset = 0

    # Unpack e
    e_length = struct.unpack('>I', serialized_key[offset:offset + 4])[0]
    offset += 4
    e_bytes = serialized_key[offset:offset + e_length]
    e = int.from_bytes(e_bytes, 'big')
    offset += e_length

    # Unpack n
    n_length = struct.unpack('>I', serialized_key[offset:offset + 4])[0]
    offset += 4
    n_bytes = serialized_key[offset:offset + n_length]
    n = int.from_bytes(n_bytes, 'big')

    return e, n



