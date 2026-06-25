from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os

covert_data = b""
covert_data_index = 0
recvd_covert_data = b""
recvd_covert_data_index = 0 

start_ct_len = 32

# 'N' in my writeup.
transmission_replacement_rate = 2

def set_covert_data(data, key, transmission_rate):
    
    global covert_data, transmission_replacement_rate
    transmission_replacement_rate = transmission_rate
    
    f = AESGCM(key)
    nonce = os.urandom(12)
    
    header = len(data).to_bytes(4, 'big')
    start_ct = nonce + f.encrypt(nonce, header, None)
    second_nonce = os.urandom(12)
    data_ct = second_nonce + f.encrypt(second_nonce, data, None)
    covert_data = start_ct + data_ct
    covert_data = os.urandom(50) + covert_data 
    assert len(start_ct) == start_ct_len

def set_transmission_rate(transmission_rate):
    global transmission_replacement_rate
    transmission_replacement_rate = transmission_rate

def get_recvd_covert_data(key):
    global recvd_covert_data
    #look for the header
    for i in range(len(recvd_covert_data) - start_ct_len):
        test_start_ct = recvd_covert_data[i:i+start_ct_len]
        start_nonce = test_start_ct[:12]
        start_ct = test_start_ct[12:]
        try:
            f = AESGCM(key)
            header = f.decrypt(start_nonce, start_ct, None)
            data_len = int.from_bytes(header[:4], 'big')
            print("Found covert data header at index", i, "with length", data_len)
            #now we have the second part too
            test_data_ct = recvd_covert_data[i + start_ct_len:i + start_ct_len + 12 + data_len + 16]
            data_nonce = test_data_ct[:12]
            data_ct = test_data_ct[12:]
            data = f.decrypt(data_nonce, data_ct, None)
            return data

        except:
            continue
    print("No covert data found")
    return None
 
 
def encode_covert_data(incoming_data):
    global covert_data, covert_data_index
    incoming_data = bytearray(incoming_data)  # Convert to mutable bytearray
    
    if transmission_replacement_rate == 0:
        return incoming_data

    for i in range(len(incoming_data)):
        if i % transmission_replacement_rate == transmission_replacement_rate - 1:
            if covert_data_index < len(covert_data):
                incoming_data[i] = covert_data[covert_data_index]
                covert_data_index += 1
    
    return incoming_data

def decode_covert_data(incoming_data):
    global recvd_covert_data, recvd_covert_data_index
    incoming_data = bytearray(incoming_data)  # Convert to mutable bytearray
    
    if transmission_replacement_rate == 0:
        return incoming_data

    for i in range(len(incoming_data)):
        if i % transmission_replacement_rate == transmission_replacement_rate - 1:
            recvd_covert_data += bytes([incoming_data[i]])
            recvd_covert_data_index += 1
            incoming_data[i] = incoming_data[i-1] 
    return incoming_data
        