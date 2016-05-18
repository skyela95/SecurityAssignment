import struct

import datetime

import time

from Crypto.Cipher import XOR

from Crypto.Cipher import AES

from Crypto.Hash import HMAC

from Crypto.Hash import SHA256

import random

from dh import create_dh_key, calculate_dh_secret


class StealthConn(object):
    def __init__(self, conn, client=False, server=False, verbose=False):
        self.conn = conn
        self.cipher = None
        self.client = client
        self.server = server
        self.verbose = verbose
        self.shared_hash = None
        self.shared_secret = None
        self.iv = None
        self.mac = None
        self.key = None
        self.timest = None
        self.recvtimest = None
        self.initiate_session()

		
    def initiate_session(self):
        # Perform the initial connection handshake for agreeing on a shared secret

        ### TODO: Your code here!
        # This can be broken into code run just on the server or just on the client
        if self.server or self.client:
            my_public_key, my_private_key = create_dh_key()
            # Send them our public key
            self.send(bytes(str(my_public_key), "ascii"))
            # Receive their public key
            their_public_key = int(self.recv())
            # Obtain our shared secret
            self.shared_secret = calculate_dh_secret(their_public_key, my_private_key)
            self.shared_hash = SHA256.new(bytes(str(self.shared_secret), "ascii")).hexdigest()[:16]
            print("Shared hash: {}".format(self.shared_hash))
            self.key = self.shared_hash
			
        #creating iv
        randSeed = random.seed(self.shared_hash)
        self.iv = str(random.getrandbits(128))[:16]
        print("IV is: {}".format(self.iv))
		
		#creating cipher
        self.cipher = AES.new(self.shared_hash, AES.MODE_CBC, self.iv)

    def send(self, data):
        if self.cipher:
            #creating time stamp to prevent replay
            self.timest = time.asctime()
			#adding to data
            dataToSend = data + self.timest.encode("ascii")
			#encryting data
            encrypted_data = self.encrypt(dataToSend, self.key)

			#creating hmac with shared hash as key and encrypted data as msg
            self.mac = HMAC.new(bytes.fromhex(self.shared_hash))
            self.mac.update(encrypted_data)
            sMac = self.mac.hexdigest()

			#creating packet to send
            packet_data = self.iv.encode("ascii") + sMac.encode("ascii") + encrypted_data
            
            if self.verbose:  
                print("MAC is: {}".format(sMac))
                print("Time: {}".format(self.timest))
                print("Original data: {}".format(data))
                print("Encrypted data: {}".format(repr(encrypted_data)))
                print("Packet data: {}".format(repr(packet_data)))
                print("Sending packet of length {}".format(len(packet_data)))
        else:
            packet_data = data

        # Encode the data's length into an unsigned two byte int ('H')
        pkt_len = struct.pack('H', len(packet_data))
        #send packet
        self.conn.sendall(pkt_len)
        self.conn.sendall(packet_data)
        return
        
    def recv(self):
        # Decode the data's length from an unsigned two byte int ('H')
        pkt_len_packed = self.conn.recv(struct.calcsize('H'))
        unpacked_contents = struct.unpack('H', pkt_len_packed)
        pkt_len = unpacked_contents[0]

        encrypted_data = self.conn.recv(pkt_len)

        if self.cipher:
		    #recieved IV first 16 bytes
            riv = encrypted_data[:16]
			#recieved hmac 
            rmac = encrypted_data[16:48]
			#encrypted data
            encrypted_data = encrypted_data[48:]

			#decrypting data using recv IV
            data = self.decrypt(encrypted_data, self.key, riv)
            
			#recv time stamp is last 24 bytes
            recvtimest = data[-24:]
			#actual data is data minus timestamp
            data = data[:-24]
			#reformat and read time stamp
            recvtimest = time.mktime(time.strptime(recvtimest.decode("ascii"), "%a %b %d %H:%M:%S %Y"))
            rTime = datetime.datetime.fromtimestamp(recvtimest)            
            
			#was message sent within the last 2 seconds
            excTime = datetime.datetime.now() - datetime.timedelta(seconds=2)
			#if not - return false
            if rTime < excTime:
                return False      

            if self.verbose:
                print("Receiving packet of length {}".format(pkt_len))
                print("Encrypted data: {}".format(repr(encrypted_data)))
                print("Original data: {}".format(data))
        else:
            data = encrypted_data  
                            
        return data

    def close(self):
        self.conn.close()
        return
		
    #encrypt function with padding for AES - length 16
    def encrypt(self, m, key):
        mp = ANSI_X923_pad(m, 16)
        cipher = AES.new(key, AES.MODE_CBC, self.iv)
        return cipher.encrypt(mp)

    #decrypt function with unpadding for AES - length 16
    def decrypt(self, m, key, iv):
        cipher = AES.new(key, AES.MODE_CBC, iv)
        return ANSI_X923_unpad(cipher.decrypt(m), 16)

#pad and unpad copied from week 02 Lab
def ANSI_X923_pad(m, pad_length):
    # Work out how many bytes need to be added
    required_padding = pad_length - (len(m) % pad_length)
    # Use a bytearray so we can add to the end of m
    b = bytearray(m)
    # Then k-1 zero bytes, where k is the required padding
    b.extend(bytes("\x00" * (required_padding-1), "ascii"))
    # And finally adding the number of padding bytes added
    b.append(required_padding)
    return bytes(b)

def ANSI_X923_unpad(m, pad_length):
    # The last byte should represent the number of padding bytes added
    required_padding = m[-1]
    # Ensure that there are required_padding - 1 zero bytes
    if m.count(bytes([0]), -required_padding, -1) == required_padding - 1:
        return m[:-required_padding]
    else:
        # Raise an exception in the case of an invalid padding
        raise AssertionError("Padding was invalid")
    return