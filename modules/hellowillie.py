
"""
hellowillie.py - Hello world for coinjoin
Shayan Eskandari
"""



"""
ORDER of manual commands:

.leader

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

MESSAGE TYPES:
    11  :   initiate Sending encrypted random number
    12  :   receive the encrypted random number


[error handling]
Error Types:
        .error
                01, Failed to read the command message

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




######################################
#           Global Variables         #
######################################
privkey, pubkey = None,None
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

#Hardcoded leader nickname
LEADERNICK = "LeaderBot"


nisturl = "https://beacon.nist.gov/rest/record/last"



#temporary Global Variables
tempsum = 0


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
    '''
    rnd = random.randint(0,(2**64)-1)
    return rnd




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
    global  privkey, pubkey, joingroup
    if not privkey:
        privkey, pubkey = generate_RSA()
        joingroup[bot.nick] = pubkey
    bot.say(".pubkey #nick=" + bot.nick + "#pubkey=" + pubkey)
    #bot.say(".timestamp #nick=" + bot.nick + "#timestamp="+ str(int(time())))



@module.commands('pubkey')
def pm(bot,trigger):
    """
    MIX BOT COMMAND
    Read other public keys and stores them in joingroup() dict [nick,pubkey]
    """
    global joingroup
    #bot.say(trigger.group(2))
    nick, pubkey = parse_pubkey_respond(trigger.group(2)) #anything after .pubkey wil be in passed to parse_pub_key
    if pubkey and not (nick in joingroup): #checks to have a valid public key and also if the nickname already exists in the list of joingroup
        joingroup[nick] = [pubkey]
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
    global orderGroup
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
        readOrder(bot,orderGroup)
        print "Order list = " + str(orderGroup)#LOG
        time.sleep(5) # delays for 5 seconds <-- should be replaced with some other way
        bot.say(".commandme 11,"+LEADERNICK+","+leftNeighbour+",TEMP,EOM")




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
                tempRand = rnd_gen()
                leftneighbour_pubkey = fix_pubkey(joingroup[leftNeighbour])
                tempMsg = encrypt_RSA(leftneighbour_pubkey, tempRand)
                query = ".commandme 12,"+bot.nick+","+leftNeighbour+","+tempMsg+",EOM"
                bot.say(query)
                print tempRand #4debug

        # 12 - get the encrypted random number from the rightneighbour (leader) and decrypt | also send the encrypted number to the leftneighbour and so on
        if msgType == "12":
            if bot.nick == toNick and fromNick == rightNeighbour:
                if not tempRand:
                    tempRand = rnd_gen()
                    leftneighbour_pubkey = fix_pubkey(joingroup[leftNeighbour])
                    tempMsg = encrypt_RSA(leftneighbour_pubkey, tempRand)
                    query = ".commandme 12,"+bot.nick+","+leftNeighbour+","+tempMsg+",EOM"
                    bot.say(query)
                leftRand = decrypt_RSA(privkey, msg)
                print leftRand #4debug
                tempSum = tempRand - int(leftRand)
                bot.say(".randdiff "+ str(tempSum))






    else:
        #if the message could not be interpreted
        bot.say(".error 01, Failed to read the command message") #4debug - ERROR handling
        print ("ERROR 01, Failed to read the command message") #LOG




# @module.commands('randdiff')       COMMENTED OUT ! SHOULD COMPUTE THE SUM OF ALL THE DIFF RANDS
def randdiff(bot,trigger):
    global tempsum
    if bot.nick == LEADERNICK:
        if tempsum == 0:
            tempsum = int(tempRand)
        tempsum = tempsum + int(trigger.group(2))
        bot.say(str(tempsum))





