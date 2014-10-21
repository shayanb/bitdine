



from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

import keyUtils






def generate_RSA(bits=1024): #4096 <- change it
    '''
    Generate an RSA keypair with an exponent of 65537 in PEM format
    param: bits The key length in bits
    Return private key and public key
    https://gist.github.com/lkdocs/6519378
    '''
    from Crypto.PublicKey import RSA
    new_key = RSA.generate(bits, e=65537)
    public_key = new_key.publickey().exportKey("PEM")
    private_key = new_key.exportKey("PEM")
    print private_key
    print public_key
    return private_key, public_key



def encrypt_RSA(public_key, message):
    '''
    param: public_key_loc Path to public key
    param: message String to be encrypted
    return base64 encoded encrypted string
    '''

    key = public_key
    rsakey = RSA.importKey(key)
    rsakey = PKCS1_OAEP.new(rsakey)
    encrypted = rsakey.encrypt(message)
    return encrypted.encode('base64')



def decrypt_RSA(private_key, package):
    '''
    param: public_key_loc Path to your private key
    param: package String to be decrypted
    return decrypted string
    '''
    from base64 import b64decode
    key = private_key
    rsakey = RSA.importKey(key)
    rsakey = PKCS1_OAEP.new(rsakey)
    decrypted = rsakey.decrypt(b64decode(package))
    return decrypted

btcAddress, btcPrivKey = None,None

def set_bitcoin_address():
    '''
    returns bitcoin public key and private key
    sets the global variables btcAddress & btcPrivKey
    :return:
    Bitcoin public key, private key = set_bitcoin_address()
    '''
    global btcAddress,btcPrivKey
    addresses = keyUtils.returnaddresses()
    btcAddress = addresses[0]
    btcPrivKey = addresses[1]
    print
    return btcAddress, btcPrivKey



def base58_to_int(btcaddress):
    '''
    Converts Bitcoin address (public key) to int (Long)
    :param btcaddress:
    :return:
    '''
    import base58, binascii
   # btcaddress = "1111111111111111111111111111111112"
    decoded_string = base58.b58decode(btcaddress)
    print decoded_string
    hex_string = binascii.hexlify(bytearray(decoded_string))
    print hex_string
    int_string = int(hex_string, 16)
    print int_string # log
    return int_string



def int_to_base58(int_string):
    '''
    Converts (long) int to bitcoin address (public key)
    :param int_string:
    :return:
    '''
    import base58
    hex_string = hex(int_string).rstrip("L").replace("x", "0")
    print hex_string
    unencoded_string = str(bytearray.fromhex(hex_string))
    print unencoded_string
    encoded_string= base58.b58encode(unencoded_string)
    print(encoded_string)
    return encoded_string






def split_range(rrange,lrange):
    return lrange, rrange/2




if __name__ == "__main__" :

    # private_key, public_key = generate_RSA()
    #
    # message = "THIS IS THE message!"
    #
    # newpubkey = public_key.replace("-----BEGIN PUBLIC KEY-----","").replace("-----END PUBLIC KEY-----","").strip()
    # print newpubkey
    # makhfi =  encrypt_RSA(newpubkey, message)
    # print "=========================================encrypted============================"
    # print makhfi
    # print "=========================================decrypted============================"
    #
    # vazeh = decrypt_RSA(private_key, makhfi)
    # print vazeh
    set_bitcoin_address()
    print btcAddress + " private " + btcPrivKey
    integ = base58_to_int(btcAddress)
    pubaddress = int_to_base58(integ)
    print integ
    print pubaddress



