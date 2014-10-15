__author__ = 'sbeta'


from willie import module
from Crypto import Hash
from Crypto import Random
import random
import requests





def prng(seed):
    random.seed(seed)
    rand = random.getrandbits(128)
    print dec2bin(rand)
    return rand


def dec2bin(x):
    return int(bin(x)[2:])



# """
# def shuffle(ary):
#     """
#   #  Fisher Yates Shuffle
#     """
#     a = len(ary)
#     b = a-1
#     for d in range(b, 0, -1):
#         e = random.randint(0, d)
#         if e == d:
#             continue
#         ary[d], ary[e] = ary[e], ary[d]
#     return ary
# """








if __name__ == "__main__" :
    nistdata = xmlnist(nisturl)
    #generate_RSA()
    prng(nistdata["seedValue"])


