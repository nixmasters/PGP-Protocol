import base64
import struct
from datetime import datetime

from Crypto.PublicKey import RSA



class   JavniPrsten :
    def __init__(self, timestamp :int , keyID : bytes, publicKey : bytes , userID :str, user :str) :
        self.timestamp = timestamp
        self.keyID = keyID
        self.publicKey = publicKey
        self.userID = userID
        self.user = user
    def serialize_to_bytes(self) -> bytes:

        timestamp_bytes = struct.pack('>Q', self.timestamp)  # Unsigned 64-bit integer
        keyID_bytes = self.keyID
        publicKey_bytes = self.publicKey
        userID_bytes = self.userID.encode('utf-8')  # Encode string as bytes
        user_bytes = self.user.encode('utf-8')  # Encode string as bytes


        keyID_length = len(keyID_bytes)
        publicKey_length = len(publicKey_bytes)
        userID_length = len(userID_bytes)
        user_length = len(user_bytes)


        keyID_length_bytes = struct.pack('>I', keyID_length)
        publicKey_length_bytes = struct.pack('>I', publicKey_length)
        userID_length_bytes = struct.pack('>I', userID_length)
        user_length_bytes = struct.pack('>I', user_length)


        serialized_bytes = (
                timestamp_bytes +
                keyID_length_bytes + keyID_bytes +
                publicKey_length_bytes + publicKey_bytes +
                userID_length_bytes + userID_bytes +
                user_length_bytes + user_bytes
        )

        return serialized_bytes
    def upisiUPem(self,fajl:str):
        serialized_data = self.serialize_to_bytes()


        pem_header = '-----BEGIN JAVNI PRSTEN DATA-----\n'
        pem_footer = '-----END JAVNI PRSTEN DATA-----\n'


        encoded_data = base64.encodebytes(serialized_data)


        formatted_data = b'\n'.join([encoded_data[i:i + 64] for i in range(0, len(encoded_data), 64)])


        pem_data = pem_header.encode('ascii') + formatted_data + pem_footer.encode('ascii')


        with open(fajl, 'wb') as pemFajl:
            pemFajl.write(pem_data)


def citajIzPema(fajl:str):
    with open(fajl, 'rb') as pem_file:
        pem_data = pem_file.read()

        # Strip off the PEM headers and footers
    pem_header = b'-----BEGIN JAVNI PRSTEN DATA-----\n'
    pem_footer = b'-----END JAVNI PRSTEN DATA-----\n'

    # Extract the Base64 encoded data
    start = pem_data.find(pem_header) + len(pem_header)
    end = pem_data.find(pem_footer)
    base64_data = pem_data[start:end].replace(b'\n', b'')
    serialized_data = None

    try:
        # Decode the Base64 data
        serialized_data = base64.b64decode(base64_data)
    except:
        return None


    # Deserialize from bytes
    return deserialize_from_bytes(serialized_data)

@staticmethod
def deserialize_from_bytes(data: bytes):

    # Unpack the timestamp
   try:
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

       userID_length = struct.unpack('>I', data[offset:offset + 4])[0]
       offset += 4
       userID = data[offset:offset + userID_length].decode('utf-8')
       offset += userID_length

       user_length = struct.unpack('>I', data[offset:offset + 4])[0]
       offset += 4
       user = data[offset:offset + user_length].decode('utf-8')
   except:
       return None

   return JavniPrsten(timestamp, keyID, publicKey, userID, user)

def generisanjeRSAparaKljuceva(keySize) :
    key = RSA.generate(keySize)
    return key


def generisanjeJavnogKljucaPrstena(key,userID,user):



    e_bytes = key.e.to_bytes((key.e.bit_length() + 7) // 8, 'big')
    n_bytes = key.n.to_bytes((key.n.bit_length() + 7) // 8, 'big')


    serialized_publicKey = struct.pack('>I', len(e_bytes)) + e_bytes + struct.pack('>I', len(n_bytes)) + n_bytes

    keyID = serialized_publicKey[len(serialized_publicKey)-8:len(serialized_publicKey)]

    return JavniPrsten(int(datetime.now().timestamp()*1000),keyID,serialized_publicKey,userID ,user)





#prsten = generisanjeJavnogKljucaPrstena(generisanjeRSAparaKljuceva(2048),'petar@etf.rs' , 'Petar')

#prsten.upisiUPem('mojJavniPrsten.pem')
#prsten = prsten.citajIzPema('mojJavniPrsten.pem')



