import base64
import struct
from datetime import datetime

from Crypto.Cipher import CAST
from Crypto.Hash import SHA1
from Crypto.PublicKey.RSA import RsaKey
from Crypto.Util.number import bytes_to_long, long_to_bytes

from JavniPrsten import generisanjeRSAparaKljuceva


class PrivatniPrsten:
    def __init__(self, timestamp: int, keyID: bytes, publicKey: bytes, privateKey: bytes, userID: str, user: str):
        self.timestamp = timestamp
        self.keyID = keyID
        self.publicKey = publicKey
        self.privateKey = privateKey
        self.userID = userID
        self.user = user

    def serialize_to_bytes(self) -> bytes:
        timestamp_bytes = struct.pack('>Q', self.timestamp)  # Unsigned 64-bit integer
        keyID_bytes = self.keyID
        publicKey_bytes = self.publicKey
        privateKey_bytes = self.privateKey
        userID_bytes = self.userID.encode('utf-8')  # Encode string as bytes
        user_bytes = self.user.encode('utf-8')  # Encode string as bytes

        keyID_length = len(keyID_bytes)
        publicKey_length = len(publicKey_bytes)
        privateKey_length = len(privateKey_bytes)
        userID_length = len(userID_bytes)
        user_length = len(user_bytes)

        keyID_length_bytes = struct.pack('>I', keyID_length)
        publicKey_length_bytes = struct.pack('>I', publicKey_length)
        privateKey_length_bytes = struct.pack('>I', privateKey_length)
        userID_length_bytes = struct.pack('>I', userID_length)
        user_length_bytes = struct.pack('>I', user_length)

        serialized_bytes = (
                timestamp_bytes +
                keyID_length_bytes + keyID_bytes +
                publicKey_length_bytes + publicKey_bytes +
                privateKey_length_bytes + privateKey_bytes +
                userID_length_bytes + userID_bytes +
                user_length_bytes + user_bytes
        )

        return serialized_bytes

    def upisiUPem(self, fajl: str):
        serialized_data = self.serialize_to_bytes()

        # Convert to PEM format
        pem_header = '-----BEGIN PRIVATNI PRSTEN DATA-----\n'
        pem_footer = '-----END PRIVATNI PRSTEN DATA-----\n'

        # Base64 encode the serialized data
        encoded_data = base64.encodebytes(serialized_data)

        # Format Base64 encoded data with line breaks (64 characters per line)
        formatted_data = b'\n'.join([encoded_data[i:i + 64] for i in range(0, len(encoded_data), 64)])

        # Combine header, formatted data, and footer
        pem_data = pem_header.encode('ascii') + formatted_data + pem_footer.encode('ascii')

        # Write to file
        with open(fajl, 'wb') as pemFajl:
            pemFajl.write(pem_data)


def citajIzPema(fajl: str):
    with open(fajl, 'rb') as pem_file:
        pem_data = pem_file.read()

        # Strip off the PEM headers and footers
    pem_header = b'-----BEGIN PRIVATNI PRSTEN DATA-----\n'
    pem_footer = b'-----END PRIVATNI PRSTEN DATA-----\n'

    # Extract the Base64 encoded data
    start = pem_data.find(pem_header) + len(pem_header)
    end = pem_data.find(pem_footer)
    base64_data = pem_data[start:end].replace(b'\n', b'')

    # Decode the Base64 data
    try:
        serialized_data = base64.b64decode(base64_data)
    except:
        return None

    # Deserialize from bytes
    return deserialize_from_bytes(serialized_data)


@staticmethod
def deserialize_from_bytes(data: bytes):
    # Unpack the timestamp
    timestamp = struct.unpack('>Q', data[:8])[0]
    offset = 8

    # Unpack lengths
    keyID_length = struct.unpack('>I', data[offset:offset + 4])[0]
    offset += 4
    keyID = data[offset:offset + keyID_length]
    offset += keyID_length

    publicKey_length = struct.unpack('>I', data[offset:offset + 4])[0]
    offset += 4
    publicKey = data[offset:offset + publicKey_length]
    offset += publicKey_length

    privateKey_length = struct.unpack('>I', data[offset:offset + 4])[0]
    offset += 4
    privateKey = data[offset:offset + privateKey_length]
    offset += privateKey_length

    userID_length = struct.unpack('>I', data[offset:offset + 4])[0]
    offset += 4
    userID = data[offset:offset + userID_length].decode('utf-8')
    offset += userID_length

    user_length = struct.unpack('>I', data[offset:offset + 4])[0]
    offset += 4
    user = data[offset:offset + user_length].decode('utf-8')

    return PrivatniPrsten(timestamp, keyID, publicKey, privateKey, userID, user)


def generisanjePrivatnogKljucaPrstena(key: RsaKey, userID, passphrase, user):

    p_bytes = long_to_bytes(key.p)
    q_bytes = long_to_bytes(key.q)
    d_bytes = long_to_bytes(key.d)
    serialized_privateKey = len(p_bytes).to_bytes(2) + p_bytes + len(q_bytes).to_bytes(2)+q_bytes+len(d_bytes).to_bytes(2)+d_bytes

    h = SHA1.new()
    b = passphrase.encode()
    h.update(b)
    hash = h.hexdigest()

    keyCip = hash[0:len(hash) - 8]
    byte_array = bytes.fromhex(keyCip)
    cipher = CAST.new(byte_array, CAST.MODE_CFB)
    enkriptovanPrivatniKljuc = cipher.encrypt(serialized_privateKey)
    enkriptovanPrivatniKljuc = cipher.iv + enkriptovanPrivatniKljuc
    #print(enkriptovanPrivatniKljuc)
    e_bytes = key.e.to_bytes((key.e.bit_length() + 7) // 8, 'big')
    n_bytes = key.n.to_bytes((key.n.bit_length() + 7) // 8, 'big')

    serialized_publicKey = struct.pack('>I', len(e_bytes)) + e_bytes + struct.pack('>I', len(n_bytes)) + n_bytes
    keyID = serialized_publicKey[len(serialized_publicKey) - 8:len(serialized_publicKey)]
    return PrivatniPrsten(int(datetime.now().timestamp() * 1000), keyID, serialized_publicKey, enkriptovanPrivatniKljuc,
                          userID, user)

#prsten = generisanjePrivatnogKljucaPrstena(generisanjeRSAparaKljuceva(2048) , 'petar@etf.rs' , 'test' , 'Petar')

# prsten.upisiUPem('mojPrivPrsten.pem')

