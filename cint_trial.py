import sys
import socket
import secrets
import struct
import math
 
def send_and_receive_tcp(address, port, message):
    print("You gave arguments: {} {} {}".format(address, port, message))
     # create TCP socket
    tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
     # connect socket to given address and port
    tcp_socket.connect((address, port))

     # create encryption keys
    keys = generate_keys(20)
    if "ENC" in message:
         # append keys to message with newlines in between
        message += "\r\n" + "\r\n".join(keys) + "\r\n.\r\n"
    else:
         # append a newline to message
        message += "\r\n"
    print(f"Sent message:\n{message}")

      # send given message to socket
    tcp_socket.sendall(message.encode())
     # receive data from socket
    reply_data = tcp_socket.recv(1024)
     # data you received is in bytes format. turn it to string with .decode() command
    data = reply_data.decode()
    # print received data
    print(f"Data received by server from TCP:\n{data}")

    # close the socket
    tcp_socket.close()

     # Get your CID and UDP port from the message
    if "ENC" in message:
         # split the data(decoded data) by newline characters and first line of data by spaces
        data_split = data.split("\r\n")
        cid_port = data_split[0].split(" ")
         # extract cid and udp port from split data
        cid = cid_port[1]
        udp_port = cid_port[2]
         #extract the received keys from split data
        keys_recv = data_split[1:-2]
    else:
        data_split = data.split(" ")
        cid = data_split[1]
        udp_port = data_split[2]
        #if no encryption, use generated keys so function works later
        keys_recv = keys

    # Continue to UDP messaging. You might want to give the function some other parameters like the above mentioned cid and port.
    send_and_receive_udp(address, udp_port, cid, message, keys, keys_recv)

    return
 
 
def send_and_receive_udp(address, port, cid, message, keys, keys_recv):

     # server address and port
    serverAddrPort = (address, int(port))
     # creating a UDP socket
    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    if "ENC" in message:
        enc_key = keys.pop(0)

     # form the initial message to send
    mssg = f"Hello from {cid}\n"
    old_mssg = mssg
    if "ENC" in message:
        mssg = encrypt_message(mssg, enc_key)
    len_mssg = len(mssg)
    if "PAR" in message:
         #initialize an empty string for the parity message
        par_mssg = ""
         #for each character in the message
        for i in range(len(mssg)):
             #add parity bit to the character & append it to parity mssg
            par_mssg += add_parity(mssg[i])
         #update message with parity mssg
        mssg = par_mssg
    mssg_bytes = mssg.encode()

    # UDP messaging variables
    cid_bytes = cid.encode()
    ack_bool = True
    eom_bool = False
    data_rem = 0

     # packing the message
    Data = struct.pack('!8s??HH128s', cid_bytes, ack_bool, eom_bool, data_rem, len_mssg, mssg_bytes)

     # send the first message of the UDP interaction
    udp_socket.sendto(Data, serverAddrPort)
    if "PAR" in message:
        mssg = remove_parity(mssg) #remove parity from mssg
    print(f"Message\n {old_mssg} sent to {address}:{port}\n")

    # start the messaging
    while (True):
         #receive and unpack message
        Data_recv = udp_socket.recvfrom(1024)
        cid, ack_bool, eom_bool, data_rem, recv_len, recv_bytes = struct.unpack('!8s??HH128s', Data_recv[0])

         # check EOM bit
        if eom_bool is True:
            break
         # if there is remaining data to be sent
        if "MUL" in message and data_rem != 0:
             # decodes the received bytes up to received length
            tot_mssg = recv_bytes[:recv_len].decode()
            total_len = recv_len
            while data_rem != 0:
                 # while there is remaining data to be received, receive data from udp socket
                Data_recv = udp_socket.recvfrom(1024)
                cid, ack_bool, eom_bool, data_rem, recv_len, recv_bytes = struct.unpack('!8s??HH128s', Data_recv[0])
                 #add decoded received bytes to tot_msg
                tot_mssg += recv_bytes[:recv_len].decode()
                total_len += recv_len #adds received length
            recv_bytes = tot_mssg.encode()
            recv_len = total_len

         # decode and reverse the word list, check parity and decrypt message
        mssg_recv = recv_bytes.decode()
        if "PAR" in message:
            for character in mssg_recv:
                parity_ok = check_parity(character)
                if parity_ok is False:
                    ack_bool = False
            #remove parity from the message 
            mssg_recv = remove_parity(mssg_recv)

        #if not ack, resend package
        if ack_bool is False and data_rem == 0:
             #discard the used decryption keys
            keys_recv = keys_recv[math.ceil(recv_len/64):]
            error_msg = "Send again"
            error_len = len(error_msg)
             # if mssg has ENC, and keys are left, encrypts error mssg
            if "ENC" in message and len(keys) != 0:
                try:
                    encrypt_key = keys.pop(0)
                    error_msg = encrypt_message(error_msg, encrypt_key)
                except IndexError:
                    print("All encryption keys used")
            error_mssg = error_mssg.encode()
            error_data = struct.pack('!8s??HH128s', cid_bytes, ack_bool, eom_bool, data_rem, error_len, error_msg)
            udp_socket.sendto(error_data, serverAddrPort)
            print(f"Parity check failed, sent message: Send again to {address}:{port}\n")
            continue
        mssg_recv = mssg_recv[0:recv_len] #shorten mssg received to length of received data

        if "ENC" in message and len(keys_recv) != 0:
            if "MUL" in message:
                  # empty string to store decrypted pieces
                tmp_string = ""
                enc_pieces = split_message(mssg_recv)
                for piece in enc_pieces:
                    try:
                        decrypt_key = keys_recv.pop(0) #gets decryption keys from received keys
                        tmp_string += encrypt_message(piece, decrypt_key)
                    except IndexError:
                        tmp_string += piece 
                mssg_recv = tmp_string
            else:
                decrypt_key = keys_recv.pop(0)
                mssg_recv = encrypt_message(mssg_recv, decrypt_key)
        print(f"Received message:\n{mssg_recv}")
        mssg_send = reverse_words(mssg_recv)
        print(f"Reversed mssg:\n{mssg_send}")

         # prepare message for sending
        if "MUL" in message:
            pieces = split_message(mssg_send)
        else:
            pieces = mssg_send
         # calculates the remaining data length
        data_rem = len(mssg_send)

        for piece in pieces: #checks each piece in the message
              # sets current message to be sent as a piece
            mssg_send = piece
            cont_len = len(mssg_send)
            data_rem -= cont_len  #updates the remaining data length 

            if "ENC" in message and len(keys) != 0:   #if keys are still available
                try:
                    encrypt_key = keys.pop(0)
                      #encrypt the current message with popped key
                    mssg_send = encrypt_message(mssg_send, encrypt_key)
                except IndexError:
                    print("All encryption keys have been used")
            
            if "PAR" in message:
                mssg_send_par = ""  #initializes empty string for parity added message
                for i in range(0,len(mssg_send)):
                     # Add parity to each character and append it to the parity-added message
                    mssg_send_par += add_parity(mssg_send[i])
                mssg_send = mssg_send_par #sets current mssg to be the parity added mssg

            mssg_bytes = mssg_send.encode()
            Data = struct.pack('!8s??HH128s', cid_bytes, ack_bool, eom_bool, data_rem, cont_len, mssg_bytes)
            udp_socket.sendto(Data, serverAddrPort)
            
        print(f"Message sent to {address}:{port}\n\n_______________")
             
    # program jumps here after EOM bit = 1
    last_msg = recv_bytes.decode()
    print(f"Received message:{last_msg}")
    udp_socket.close()
    return

def reverse_words(string):
     # splits the input string into a list of words,
     # reverse the list, and join it back into a string
    return " ".join(string.split()[::-1])
 
def generate_keys(quantity):
    keys_list = []
    for i in range (0, quantity):
         #generate a secure random key in hexadecimal format
        random_key = secrets.token_hex(32)
        keys_list.append(random_key)
    return keys_list

def encrypt_message(message, key):
      #initialize an empty string for encrypted mssg
    encrypted = str("")
    for i in range(0,len(message)):
         # For each character, performs a bitwise XOR operation (^) on the ASCII values of 
         # the message character and the corresponding key character
         #Then, converts the result back to a character using chr() and append it to the encrypted string
        encrypted = encrypted + (chr(ord(message[i]) ^ ord(key[i])))
    return encrypted

def get_parity(n):
     # returns even parity bit of the given number
    while n > 1:
         # Right shifts n by 1 bit and XOR it with n AND 1
        n = (n >> 1) ^ (n & 1)
    return n 

def add_parity(a):
     # converts character a to its ASCII value
    a = ord(a)
    a <<= 1
     # adds the parity of a to a
    a += get_parity(a)
     # converts a back to character
    a = chr(a)
    return a

def check_parity(c):
    c = ord(c)
     # gets the parity bit of c
    parity_bit = c & 1
    c >>= 1
     # gets the parity of a (parity test)
    test_parity = get_parity(c)
    if parity_bit == test_parity:
        return True  # parity check passed
    else:
        return False # parity check failed
    
def remove_parity(string):
     # removes parity bit from each character and returns the resulting string
    rm_string = " "
    for c in string:
        a = ord(c)
        a >>= 1
        a = chr(a)
         # appends the character to the result string
        rm_string = rm_string + a
    return rm_string 
     
def split_message(message):
     # It splits a given message into chunks of 64 characters each
     # initialize an empty list
    chunks = []
    chunk_size = 64
    for i in range(0, len(message), chunk_size):
         # append each chunk to the list 
        chunks.append(message[i:i+chunk_size])
    return chunks

def main():
    USAGE = 'usage: %s <server address> <server port> <message>' % sys.argv[0]
    if len(sys.argv) !=4:
        print(USAGE)
        return
 
    try:
        # Get the server address, port and message from command line arguments
        server_address = str(sys.argv[1])
        server_tcpport = int(sys.argv[2])
        message = str(sys.argv[3])
    except IndexError:
        print("Index Error")
    except ValueError:
        print("Value Error")
    # Print usage instructions and exit if we didn't get proper arguments
        sys.exit(USAGE)
 
    send_and_receive_tcp(server_address, server_tcpport, message)
  
if __name__ == '__main__':
    # Call the main function when this script is executed
    main()
