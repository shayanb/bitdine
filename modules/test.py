

import keyUtils



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
    hex_string = binascii.hexlify(bytearray(decoded_string))
    int_string = int(hex_string, 16)
    return int_string



def int_to_base58(int_string):
    '''
    Converts (long) int to bitcoin address (public key)
    :param int_string:
    :return:
    '''
    import base58
    hex_string = hex(int_string).rstrip("L").replace("x", "0")
    unencoded_string = str(bytearray.fromhex(hex_string))
    encoded_string= base58.b58encode(unencoded_string)
    return encoded_string


def hextobin(hexval):
        '''
        Takes a string representation of hex data with
        arbitrary length and converts to string representation
        of binary.  Includes padding 0s
        '''
        thelen = len(hexval)*4
        binval = bin(int(hexval, 16))[2:]
        while ((len(binval)) < thelen):
            binval = '0' + binval
        return binval


def base58_to_binary(btcaddress):
    '''
    Converts Bitcoin address (public key) to binary
    :param btcaddress:
    :return:
    '''
    import base58, binascii
    decoded_string = base58.b58decode(btcaddress)
    hex_string = binascii.hexlify(bytearray(decoded_string))
    binary_string = hextobin(hex_string)
    return binary_string



def binary_to_base58(binary_string):
    '''
    Converts (long) binary to bitcoin address (public key)
    :param binary_string:
    :return:
    '''
    import base58
    hex_string = hex(int(binary_string, 2)).rstrip("L").replace("x", "0")
    unencoded_string = str(bytearray.fromhex(hex_string))
    encoded_string= base58.b58encode(unencoded_string)
    return encoded_string




#def split_range(rrange,lrange):
#    return lrange, rrange/2




def order_binary(testgroup, n):
    '''
    in this test case testgroup is list of binarykeys
    n is integer
    '''
    temp_count = 0
    for key in testgroup:
        while temp_count < 2:
            if key[n] == 0:
                temp_count += 1
        print "going for n=" + str(n+1)
        order_binary(testgroup, n+1)
    if temp_count == 1:
        print "ONE on bit " + str(n)
        return 1
    if temp_count == 0:
        print "NONE"
        return


def btc_divideandconquer(prefix, btcAddress_tuple, lock):
    """
    btcAddress_tuple --> [user] = [btcaddress]
    prefix starts with 000000001

    :param prefix:
    :param btcAddress_tuple:
    :return:
    """
    matched_item = None
    matched_keys = 0
    print "Prefix:" + prefix
    with lock:
        for item in btcAddress_tuple:
            if item[1].startswith(prefix):
           # print "HERE " + item[0]
                matched_item = item[0]
                matched_keys+=1
        print "# Matched Keys:"+str(matched_keys)
        print ''


        if matched_keys == 0:
            print "None on Prefix " + prefix
            print ''
            return 0

        if matched_keys == 1:
            #get value in DC
            print "#                       1 match on prefix: "+ prefix + " = " + matched_item
            print '#                       '+ str(base58_to_int(matched_item))
            print base58_to_binary(matched_item)
            return matched_item

        if matched_keys > 1:
            #print str(matched_keys) + "Now going to " + prefix+"0,1"
            btc_divideandconquer(prefix+"0", btcAddress_tuple, lock)
            btc_divideandconquer(prefix+"1", btcAddress_tuple, lock)









if __name__ == "__main__" :
    """
    DOCS:
List_joingroup  -> [USERX] = [BTCAddress]
Testgroup_binary -> [BTCAddress] = [BTCAddress_Binary]





"""


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
    flag = True
    import time

    testgroup = {}
    testgroup_binary = {}
    test_joingroup = {}

    for i in range(0,100):
        bit_address, bit_priv = set_bitcoin_address()
        testgroup[bit_address] = bit_priv
        testgroup_binary[bit_address] = base58_to_binary(bit_address)
        test_joingroup["USER"+str(i)] = bit_address


    setkeys_binary = testgroup_binary.items()
    list_joingroup = test_joingroup.items()



 #   print "Here are the keys:"
 #   binary_list = []
 #   for setkey in setkeys_binary:
  #      print "Pub address: " + setkey[0]
   #     print "binary: " + setkey[1]
    #    print ""
     #    binary_list.append(setkey[1])

    print "and here are the users: "
    for user in list_joingroup:
        print user[0] + " with this address " + user[1]
        print base58_to_int(user[1])
  #  order_binary(binary_list, 0)

    import threading
    lock = threading.RLock()
    import thread
    lock2 = thread.allocate_lock()
    time.sleep(1)
    btc_divideandconquer("00000000", setkeys_binary, lock)

  #  print base58_to_binary("1z")

 #   print binary_to_base58("00000000101110010000110101011100010001101101001000111101000110001110011010001111111111110100000010001111011000101001000000101001101111101011001111110000010110110011101100001111100100111011010110100010")



    # print btcAddress + " private " + btcPrivKey
    # integ = base58_to_int(btcAddress)
    # pubaddress = int_to_base58(integ)
    # print integ
    # print pubaddress
    #
    # print "binary starts...."
    # binary_1 = base58_to_binary(btcAddress)
    # pubaddress_1 = binary_to_base58(binary_1)
    # print "binary " + binary_1
    # print "pubaddress " + pubaddress_1






