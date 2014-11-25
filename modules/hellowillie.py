
"""
hellowillie.py - Hello world for coinjoin
Shayan Eskandari
"""



"""
ORDER of manual commands:

.leader


dnc = divide and conquer

Note: Leader should be initiated first, or there would be random incorrect Decryption errors from some of the bots
"""



#TODO:
"""
[setup]
- set LEADERNICK
- set nick
- set IRC server and channel


[runtime]
- leader : check timestamp, wait for the new one to get from NIST beacon

- replace sleep(5) to call the cycle
- flag to know if the cycle is close or not
- check flags to know if a event has been executed or not


MESSAGE TYPES:
    11  :   initiate Sending encrypted random number (by leader)
    12  :   receive the encrypted random number

    21  :   first round of dining, M = None, just checks if the sum of all the diffs is 0

    31  :   leader announces that the circle messaging (DCnet) works fine
    32  :   left neighbour of the leader initiates leader's output ordering procedure

    34  :   divide and conquer LEADER sends query
    35  :   LEADER reads the responses


[error handling]
Error Types:
        .error
                01, Failed to read the command message



TO DO ON THE SECOND ROUND OF DEVELOPMENT:

- implement lastcall for leader to start the ordering
    - closes the circle and no one can call .join event (if lastcall)
    -






FACT: All version 1 bitcoin addresses in binary format starts with minimum of 8 zeros!

"""




from willie import module
from Crypto import Hash
import re
import requests
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import time

import random
try:
    import xml.etree.cElementTree as ET
except ImportError:
    import xml.etree.ElementTree as ET


#generate bitcoin addresses
import keyUtils


######################################
#           Global Variables         #
######################################
#Hardcoded leader nickname
LEADERNICK = "LeaderBot"


nisturl = "https://beacon.nist.gov/rest/record/last"


#rsa keys for encryption/decryption
privkey, pubkey = None,None

#bitcoin output addresses
btcAddress, btcPrivKey = None, None
#int and binary value of bitcoin public address
int_btc = None
bin_btc = None

#runtime global variables
leader = None
leftNeighbour = None
rightNeighbour = None
tempRand = None
leftRand = None

# joingroup is a dictionary for members in the channel
# 'nickname' is the key and values are the pubkey
joingroup = {}

#ordergroup is the ordered group of members after the shuffle by the leader
orderGroup = {}
numberOfGroup = 0


#output ordering range
lrange = 0
rrange = 2 ** 194 # 2 ** 256 is too big for the range, the highest bitcoin address (not assuming the checksums) would be 1zzzzzzzzzzzzzzzzzzzzzzzzzzzzzz that the integer value would be less than 2 ** 194



#temporary Global Variables
tempsum = None


#last call to join the circle flag, NOT YET USED
lastcall = None







######################################
#           Helper functions         #
######################################

def xmlnist(url=nisturl):
    """
    utility function, does the actually https call and parse the results
    original by hmason https://github.com/hmason/randomness_beacon
    modified for this purpose by Shayan
    """
    result = requests.get(nisturl).text

    data = {}
    record = ET.fromstring(result)
    for child in record:
        data[child.tag] = child.text

    if not data.get('timeStamp', None):
        print "No data returned. Perhaps the government is down."

    print data["seedValue"]
    print data["timeStamp"]
    return data



def parse_pubkey_respond(pubkey_respond):
    '''
    Regex for .pubkey respond from the bots
    RSA in PEM format
    returns nickname and pubkey
    '''
    match = re.search('#nick=(?P<nick>.*)#pubkey=(?P<pubkey>-----BEGIN PUBLIC KEY-----.*-----END PUBLIC KEY-----)', str(pubkey_respond))
    if match.group('pubkey'):
        print match.group('nick'), match.group('pubkey') #4debug
        return match.group('nick'), match.group('pubkey')
    else:
        print "Wrong pubkey announcement format"#LOG
        return None, None



def str2list(str2):
    '''
    Converts a string to a list
    (removes unicode u)
    :param str2:
    :return:
    '''
    lst = re.sub("[()]", '', str2).replace("'", "").strip("[]").split(', ')
    lststr = [str(x) for x in lst]
    return lststr


def commandsplit(rawcommand, botnick):
    '''
    reads the rawcommand (trigger.group[2]) and splits the command
    example of the string:
                            04,nick1,nick2,message can be anything,EOM
    (EOM = End of Message)
    checks if:
                msgType is an integer between 00 and 99
                fromNick is actually the sender's bot nick
    :return:
    return  msgType,
            Nick of the sender,
            Nick of the receiver,
            message
    '''
    command = re.search('(?P<msgType>\d{2}),(?P<fromNick>\w*),(?P<toNick>\w*),(?P<msg>.*),EOM', rawcommand)
    if command:
        if command.group('fromNick') == botnick:
            return command.group('msgType'), command.group('fromNick'), command.group('toNick'), command.group('msg')
        else:
            print "WARNING: " + botnick + " and " + command.group('fromNick') + "are not the same - Illegal request"#4debug
    else:
        print "Wrong command format" #LOG
    return None



def fix_pubkey(pubkey):
    '''
    fixes the public key format (PEM) retrieved from the IRC chat string
    (RSA)
    '''
    pubkey = str(pubkey).replace("'", "").strip("[]")
    firstline = pubkey[:26]
    pem = pubkey.replace(pubkey[-24:], '').replace(pubkey[:26], '')
    lastline = pubkey[-24:]
    final = firstline + "\n" + pem + "\n" + lastline
    print "fixed pubkey = " + final #debug
    return str(final)



######################################
#           Main Functions           #
######################################

#=========================
#  Shuffle and Ordering  #
#=========================

def shuffle(ary, seed):
    random.seed(seed)
    randary = random.shuffle(ary)
    return randary




def readOrder(bot,orderGroup):
    '''
    sets the global rightneighbour and the leftneighbour from the shuffled order group
    '''
    global leftNeighbour, rightNeighbour
    for index,value in enumerate(orderGroup):
        if orderGroup[index] == bot.nick and index != 0 and index!= (len(orderGroup)-1):
            leftNeighbour = str(orderGroup[index-1])
            rightNeighbour = str(orderGroup[index+1])
        elif index == 0 and orderGroup[index] == bot.nick:
            leftNeighbour = str(orderGroup[len(orderGroup)-1])
            rightNeighbour = str(orderGroup[index+1])
        elif index == (len(orderGroup)-1) and orderGroup[index] == bot.nick:
            leftNeighbour = str(orderGroup[index-1])
            rightNeighbour = str(orderGroup[0])
    return leftNeighbour, rightNeighbour


#=========================
#  RSA Crypto Functions  #
#=========================

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
    encrypted = rsakey.encrypt(str(message))
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


#=========================
#       Misc Functions   #
#=========================

def rnd_gen():
    '''
    generates a random number between 0 and (2 ^ 64) - 1
    for DCnet communication
    '''
    rnd = random.randint(0,(2**64)-1)
    return rnd



#=================================
#    Bitcoin Address Functions   #
#=================================

def set_bitcoin_address():
    '''
    #IMP Generates new set of key on every run
    returns bitcoin public key and private key
    sets the global variables btcAddress & btcPrivKey
    :return:
    Bitcoin public key, private key = set_bitcoin_address()
    '''
    global btcAddress,btcPrivKey
    addresses = keyUtils.returnaddresses()
    btcAddress = addresses[0]
    btcPrivKey = addresses[1]
    print btcAddress #log
    print btcPrivKey #4debug TO BE REMOVED LATER
    return btcAddress, btcPrivKey



def base58_to_int(btcaddress):
    '''
    Converts Bitcoin address (public key) to int (Long)
    :param btcaddress:
    :return:
    '''
    import base58, binascii

    decoded_string = base58.b58decode(btcaddress)
    hex_string = binascii.hexlify(bytearray(decoded_string))
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
    unencoded_string = str(bytearray.fromhex(hex_string))
    encoded_string= base58.b58encode(unencoded_string)
    print(encoded_string)
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


#=============================
#  split range and Ordering  #
#=============================


def split_range(lrange,rrange):
    return lrange, rrange/2


def check_in_range(selfint, lrange, rrange):
    if lrange < selfint < rrange:
        return 1
    else:
        return 0




######################################
#           Bot Modules              #
######################################

#=========================
#    Initial Handshake   #
#=========================

# On JOIN event
@module.event('join')
@module.rule('.*')
def joinshout(bot, trigger):
    '''
    generates the private and public key
    broadcasts the public key to the channel (.pubkey) (repeats for every JOIN event)
      e.g      .pubkey #nick=Willie2 #pubkey=-----BEGIN PUBLIC KEY-----MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDzpi9fjjVuH4+hWRnMxaGTgg51jLsfj/KrU9EbRuMtCcn/pHL7F+mHGV0TfWPGfR2LjuwJJV3Bj41ypIKsD8MGZSUGCZE+30zur042idkaE3PvSRteMoOg7lhr8R3tfrqcRPxrvylhu99FFvD8XMPXG/tuA1I2WC93GzLE0qGWBQIDAQAB-----END PUBLIC KEY-----
    broadcasts the local timestamp (.timestamp)
      e.g      .timestamp #nick=Willie2#timestamp=1400639033
    saves the local bots nick and public in joingroup
    '''
    global  privkey, pubkey, joingroup, int_btc
    if not privkey:
        privkey, pubkey = generate_RSA()
        joingroup[bot.nick] = pubkey
    bot.say(".pubkey #nick=" + bot.nick + "#pubkey=" + pubkey)
    #bot.say(".timestamp #nick=" + bot.nick + "#timestamp="+ str(int(time())))
    if not btcAddress:
        set_bitcoin_address()
        int_btc = base58_to_int(btcAddress)
        bin_btc = base58_to_binary(btcAddress)
        print "bitcoin addresses generated" #log



@module.commands('pubkey')
def pm(bot,trigger):
    """
    MIX BOT COMMAND
    Read other public keys and stores them in joingroup() dict [nick,pubkey]
    """
    global joingroup
    nick, pubkey = parse_pubkey_respond(trigger.group(2)) #anything after .pubkey wil be in passed to parse_pub_key
    if pubkey and not (nick in joingroup): #checks to have a valid public key and also if the nickname already exists in the list of joingroup
        joingroup[nick] = fix_pubkey([pubkey])
        bot.say("%s received" %nick) #4DEBUG



#=========================
# Leader initial leading #
#=========================


@module.commands('leader')
def leadannouncement(bot,trigger):
    """
    Announces the leaders nick and pubkey
    only the leader would respond
    """
    global orderGroup,numberOfGroup
    if bot.nick == LEADERNICK:
        global pubkey,joingroup
        bot.say(".lead #nick=" + bot.nick + " #pubkey" + pubkey)
        bot.say("Leader is shuffling...")
        NistSeed = xmlnist()["seedValue"]
    #shuffle should be done with pubkeys instead of nicks in the final version
        nicklist = joingroup.keys()
        shuffle(nicklist, NistSeed)
        bot.say(".order " + str(nicklist))
        orderGroup = str2list(str(nicklist).replace("Nick(", "")) #THIS IS REALLY DIRTY CODE!!!!!!
        numberOfGroup = len(orderGroup)
        bot.say(".numberofgroup " + str(numberOfGroup)) #announce the number of users in the circle
        readOrder(bot,orderGroup)
        print "Order list = " + str(orderGroup)#LOG
        time.sleep(5) # delays for 5 seconds <-- should be replaced with another other way
        bot.say(".commandme 11,"+LEADERNICK+","+leftNeighbour+",TEMP,EOM")



@module.commands("numberofgroup")
def number_of_group(bot,trigger):
    """
    sets the numberofgroup variable to know how many are in the circle
    """
    global numberOfGroup
    numberOfGroup = int(trigger.group(2))
    print "Number of group="+ str(numberOfGroup) #4debug


@module.commands("lead")
def setleader(bot,trigger):
    """
    LEADER COMMAND - Not to be used as input command
    sets the leader for all the bots
    """
    global leader
    if not leader and trigger.group(2):
        leader = trigger.nick
    elif bot.nick == LEADERNICK and trigger.group(2): #removes the leader error
        leader = bot.nick
    bot.say("the leader is " + leader) #4debug
    print "LEADER = " + leader #LOG



@module.commands('order')
def readorder(bot,trigger):
    """
    LEADER COMMAND - Not to be used as input command
    read the shuffled order from the leader
    """
    global orderGroup, leftNeighbour, rightNeighbour
    orderGroup = str2list(trigger.group(2).replace("Nick(", ""))
    bot.say(str(orderGroup)) #4debug
    readOrder(bot, orderGroup)
    bot.say("left neighbour is : " + leftNeighbour) #4debug





#=========================
#    Divide and conquer  #
#           dnc          #
#=========================


def dnc_prefix_send(bot, prefix):
    '''
    LEADER broadcast the prefix of the output address to the channel
    '''
    bot.say(".commandme 34,"+LEADERNICK+","+"ALL"+","+str(prefix)+",EOM")



def dnc_prefix_respond(bot,prefix):
    '''
    EVERYONE read the prefix from dns_prefix_send (LEADER) and checks their value and respond 0 or 1

    ::returns:
    0 if the prefix does not match his address
    1 if the prefix matches
    '''
    if bin_btc.startswith(prefix):
        return 1
    else:
        return 0


#def dnc_read_responces(bot, responces):



def send_dcnet_encrypted(pubkey,msg=0,init=None):
    '''
    init = True is only for the first round
        in this case message should be the newly generated random number
        and returns the encrypted message and the random number , #hacky solution
    :param pubkey:
    :param msg:
    :param init:
    :return:
    '''
    if init is None:
        tempRand = msg
    else:
        tempRand = rnd_gen()
        msg += tempRand
    enc_message = encrypt_RSA(pubkey,msg)
    if init is None:
        return enc_message, tempRand
    else:
        return enc_message

#=========================
#    Main Command Module #
#=========================

@module.commands('commandme')
def readcommand(bot,trigger):
    """
    reads the command and runs the appropriate function
    CSV
    .commandme COMMAND_CODE,SENDERS_NICK,RECEIVERS_NICK,MESSAGE,EOM
    """
    global tempRand, leftRand
    if commandsplit(trigger.group(2), trigger.nick):
        msgType, fromNick, toNick, msg = commandsplit(trigger.group(2), trigger.nick)

 # here should be the command list with msgTypes

        # 11 - initiate the round sequence by leader
        if msgType == "11" and fromNick == LEADERNICK and toNick == bot.nick:
                leftneighbour_pubkey = joingroup[leftNeighbour]
                initmsg = send_dcnet_encrypted(leftneighbour_pubkey)
                query = ".commandme 12,"+bot.nick+","+leftNeighbour+","+initmsg+",EOM"
                bot.say(query)
                #print tempRand #4debug

        # 12 - get the encrypted random number from the rightneighbour (leader) and decrypt | also send the encrypted number to the leftneighbour and so on
        if msgType == "12":
            if bot.nick == toNick and fromNick == rightNeighbour:
                if not tempRand:
                    leftneighbour_pubkey = joingroup[leftNeighbour]
                    tempRand = rnd_gen()
                    initmsg, tempRand = send_dcnet_encrypted(leftneighbour_pubkey, tempRand, 1)
                    query = ".commandme 12,"+bot.nick+","+leftNeighbour+","+initmsg+",EOM"
                    bot.say(query)
                leftRand = decrypt_RSA(privkey, msg)
                print leftRand #4debug
                temp_sum = tempRand - int(leftRand)
               # bot.say(".randdiff "+ str(temp_sum))
               # time.sleep(tempRand % 5) #random sleep to prevent overlap of function runs (huh?)
                bot.say(".commandme 21,"+bot.nick+","+LEADERNICK+","+str(temp_sum)+",EOM")

        # 21 - first round of dining, M = None, just checks if the sum of all the diffs is 0
        if msgType == "21" and toNick == LEADERNICK and bot.nick == LEADERNICK:
            global tempsum
            time.sleep(5) #sleep till leader gets leftRand #dirtysolution
            if tempsum == None:
                tempsum = tempRand - int(leftRand)
                tempsum += int(msg)
            elif not (tempsum == 0):
                tempsum += int(msg)
            if tempsum == 0:
                bot.say(".commandme 31,"+bot.nick+","+leftNeighbour+","+"let's Dine"+",EOM") #trick to initiate the leader's output ordering

        # because each bot would not listen to their own commands here is a trick to start range dividing by leader
        if msgType == "31" and toNick == bot.nick and fromNick == LEADERNICK:
            bot.say(".commandme 32,"+bot.nick+","+ LEADERNICK +","+"You go first"+",EOM")


        if msgType == "32" and toNick == LEADERNICK and bot.nick == LEADERNICK:
            #start the output ordering range
            bot.say("Raise your hand if you have a public key in these ranges")
            inner_lrange, inner_rrange = split_range(lrange, rrange) #splits the range
            print "who has pubkey between" + str(inner_lrange) + " and " + str(inner_rrange)
            bot.say(".commandme 33,"+bot.nick+","+"ALL"+","+str(inner_lrange)+","+str(inner_rrange)+",EOM")


       #TODO: REMOVE 33 FROM HERE! -> divide and conquer function uses 34 msg type


        if msgType == "33" and fromNick == LEADERNICK:
            # main message type to check if anyone is in range temp_lrange, temp_rrange
            temp_lrange, temp_rrange = msg.split(',')
            print btcAddress #4debug
            print int_btc #4debug remove later

            if check_in_range(int_btc, int(temp_lrange), int(temp_rrange)/4):
                bot.say("ME")





    else:
        #if the message could not be interpreted
        bot.say(".error 01, Failed to read the command message" + trigger.group(2)) #4debug - ERROR handling
        print ("ERROR 01, Failed to read the command message" + trigger.group(2)) #LOG







@module.commands('randdiff')      # COMMENTED OUT ! SHOULD COMPUTE THE SUM OF ALL THE DIFF RANDS
def randdiff(bot,trigger):
    global tempsum, tempRand, leftRand
    if bot.nick == LEADERNICK and leftRand:
        bot.say("calculating diff")

        if tempsum == None:
            tempsum = int(tempRand) - int(leftRand)
            tempsum = tempsum + int(trigger.group(2))
            bot.say("its none" + str(tempsum))
        elif tempsum:
            tempsum = tempsum + int(trigger.group(2))
            bot.say("not none "+ str(tempsum))

        if tempsum == 0:
            bot.say("Let's dine")





