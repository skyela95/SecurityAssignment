from Crypto.Hash import SHA256
from Crypto.Random import random

from lib.helpers import read_hex
#from time import time

# Project TODO: Is this the best choice of prime? Why? Why not? Feel free to REPLACE!

# 4096 bit safe prime for Diffie-Hellman key exchange
# obtained from RFC 3526
raw_prime = """FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1
      29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD
      EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245
      E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED
      EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE45B3D
      C2007CB8 A163BF05 98DA4836 1C55D39A 69163FA8 FD24CF5F
      83655D23 DCA3AD96 1C62F356 208552BB 9ED52907 7096966D
      670C354E 4ABC9804 F1746C08 CA18217C 32905E46 2E36CE3B
      E39E772C 180E8603 9B2783A2 EC07A28F B5C55DF0 6F4C52C9
      DE2BCBF6 95581718 3995497C EA956AE5 15D22618 98FA0510
      15728E5A 8AAAC42D AD33170D 04507A33 A85521AB DF1CBA64
      ECFB8504 58DBEF0A 8AEA7157 5D060C7D B3970F85 A6E1E4C7
      ABF5AE8C DB0933D7 1E8C94E0 4A25619D CEE3D226 1AD2EE6B
      F12FFA06 D98A0864 D8760273 3EC86A64 521F2B18 177B200C
      BBE11757 7A615D6C 770988C0 BAD946E2 08E24FA0 74E5AB31
      43DB5BFC E0FD108E 4B82D120 A9210801 1A723C12 A787E6D7
      88719A10 BDBA5B26 99C32718 6AF4E23C 1A946834 B6150BDA
      2583E9CA 2AD44CE8 DBBBC2DB 04DE8EF9 2E8EFC14 1FBECAA6
      287C5947 4E6BC05D 99B2964F A090C3A2 233BA186 515BE7ED
      1F612970 CEE2D7AF B81BDD76 2170481C D0069127 D5B05AA9
      93B4EA98 8D8FDDC1 86FFB7DC 90A6C08F 4DF435C9 34063199
      FFFFFFFF FFFFFFFF"""
# Convert from the value supplied in the RFC to an integer
prime = read_hex(raw_prime)
g = 2


# Project TODO: write the appropriate code to perform DH key exchange

def create_dh_key(): #g, prime
    # Creates a Diffie-Hellman key
    # Returns (public, private)
    my_private_key = (random.randint(0, prime)) #maybe?Another source of rand?              Uses prime?
    my_public_key = pow(g, my_private_key, prime)

    #my_private_key = (the ** a) % prime
    #a = random.randint(0, int(2**8))
    #print(my_private_key, my_private_key)
    return (my_public_key, my_private_key)

def calculate_dh_secret(their_public_key, my_private_key):
    # Calculate the shared secret
    #shared_secret = their_public * my_private
    shared_secret = pow(their_public_key, my_private_key, prime)
    # Hash the value so that:
    # (a) There's no bias in the bits of the output
    #     (there may be bias if the shared secret is used raw)
    # (b) We can convert to raw bytes easily
    # (c) We could add additional information if we wanted
    # Feel free to change SHA256 to a different value if more appropriate
    ##sticking with 256 as others seem to be more easily broken
    shared_hash = SHA256.new(bytes(str(shared_secret), "ascii")).hexdigest()
    #[:shortened_to]
    return shared_hash



#2042 bit min rec 4096
