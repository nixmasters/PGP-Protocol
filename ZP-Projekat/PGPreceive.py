from Crypto.Cipher import CAST, AES
from Crypto.Hash import SHA1
from Crypto.Util.Padding import unpad
from Crypto.Util.number import bytes_to_long, long_to_bytes

import JavniPrsten

from PGPsend import deserialize_private_key, deserialize_public_key, generisanjePoruke
import PrivatniPrsten


def prijemPoruke(passphrase : str, fajl_dolazna_poruka:str , privatniPrstenovi , javniPrstenovi):
    p = ''
    with open(fajl_dolazna_poruka, 'r') as fajl:
        p=fajl.read()
    p = bytes.fromhex(p)
    offset = 0
    algoritam = p[offset:offset + 1]
    offset+=1
    iv_len = int.from_bytes(p[offset:offset + 1])
    offset += 1
    iv = p[offset:offset + iv_len]
    offset += iv_len
    cip_len = int.from_bytes(p[offset:offset + 4])
    offset += 4
    encryptedMessage = p[offset:offset + cip_len]
    offset += cip_len
    keyID = p[offset:offset + 8]
    offset += 8
    encryptedSessionKey = p[offset:]


    enkriptovanPrivatniKljuc = None
    for i in range(len(privatniPrstenovi)):
        if(keyID == privatniPrstenovi[i].keyID):
            enkriptovanPrivatniKljuc = privatniPrstenovi[i].privateKey
            break
    if enkriptovanPrivatniKljuc == None:
        return 'GRESKA: Nije ucitan privatni prsted recievera'

    h = SHA1.new()
    b = passphrase.encode()
    h.update(b)
    hash = h.hexdigest()  # 40 byte

    keyCip = hash[0:len(hash) - 8]
    byte_array = bytes.fromhex(keyCip)
    old_iv = enkriptovanPrivatniKljuc[:8]
    enkriptovanPrivatniKljuc = enkriptovanPrivatniKljuc[8:]
    cipherPrivKey = CAST.new(byte_array, CAST.MODE_CFB, old_iv)
    privatniKljuc = cipherPrivKey.decrypt(enkriptovanPrivatniKljuc)

    p, q, d = deserialize_private_key(privatniKljuc)
    enkriptovanSesijskiKljuc = int.from_bytes(encryptedSessionKey)
    try :
        sesijskiKljuc = pow(enkriptovanSesijskiKljuc, d, p * q)
    except :
        return 'Pogresna lozinka'
    sesijskiKljuc = long_to_bytes(sesijskiKljuc)
    #poruka = prsten.keyID + len(poruka).to_bytes(4) +  poruka + potpis

    if algoritam==b'A':
        cipher = AES.new(sesijskiKljuc, AES.MODE_CBC, iv)
        decrypted_padded = cipher.decrypt(encryptedMessage)
        poruka = unpad(decrypted_padded, AES.block_size)
    elif algoritam==b'C':
        cipher = CAST.new(sesijskiKljuc, CAST.MODE_CBC, iv)
        decrypted_padded = cipher.decrypt(encryptedMessage)
        poruka = unpad(decrypted_padded, CAST.block_size)


    offset = 0
    key_ID = poruka[offset:offset + 8]
    offset +=8
    poruka_len = int.from_bytes(poruka[offset:offset + 4])
    offset+=4
    message = poruka[offset:offset + poruka_len]
    offset+= poruka_len
    stariPotpis = poruka[offset:]

    h = SHA1.new()
    h.update(message)
    Mess = h.hexdigest()  # 40 byte
    Mess = bytes.fromhex(Mess)

    javniKljuc = None
    for i in range(len(javniPrstenovi)):
        if(key_ID == javniPrstenovi[i].keyID):
            javniKljuc = javniPrstenovi[i].publicKey
            break
    if javniKljuc==None:
        return 'NIJE UCITAN JAVNI PRSTEN SENDERA'

    e, n = deserialize_public_key(javniKljuc)

    potpis = pow(int.from_bytes(stariPotpis), e, n)
    potpis = long_to_bytes(potpis)

    if(potpis == Mess) :
        print('BEZBEDNA KOMUNIKACIJA')

    else :
        print('Jebote ko smisli ZP GRESKA ')
    return message

