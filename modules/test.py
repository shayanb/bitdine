



from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP








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


if __name__ == "__main__" :

    private_key, public_key = generate_RSA()

    message = "THIS IS THE message!"

    newpubkey = public_key.replace("-----BEGIN PUBLIC KEY-----","").replace("-----END PUBLIC KEY-----","").strip()
    print newpubkey
    makhfi =  encrypt_RSA(newpubkey, message)
    print "=========================================encrypted============================"
    print makhfi
    print "=========================================decrypted============================"

    vazeh = decrypt_RSA(private_key, makhfi)
    print vazeh
