import pefile
import struct
import binascii
import socket

def decrypter(data,key,length):
    decode=[]
    for i in range(length):
        decode.append(data[i] ^ key[i % len(key)])
    return decode

def Get_PE_Data(filename):
    pe=pefile.PE(filename)
    print(hex(pe.OPTIONAL_HEADER.ImageBase))
    for section in pe.sections:
        if b'.data' in section.Name:
            return section.get_data(section.VirtualAddress,section.SizeOfRawData)


def data_decrypter():
    filename = 'C:\\Users\\Hack\\Desktop\\samples___\\Emotet'
    extracted_data = Get_PE_Data(filename)
    data_end = extracted_data.index(b'\x00\x00')
    encrypted_config = extracted_data[:data_end]
    xor_key = encrypted_config[:4]
    xor_key_unpacked = struct.unpack('<I',xor_key)[0]
    xor_length_unpacked = struct.unpack('<I',encrypted_config[4:8])[0]
    string_length = xor_key_unpacked ^ xor_length_unpacked 
    print(string_length)
    encrypted_data = encrypted_config[8:]
    
    decrypted_data = decrypter(encrypted_data,xor_key,string_length)
    decrypted_data = bytes(decrypted_data)
    len_of_decrypted = len(decrypted_data)
    print(len_of_decrypted)
    print(decrypted_data)
    i = 0
    counter =0
    for i in range(len_of_decrypted):
        ip = decrypted_data[counter : counter + 4]
        port = decrypted_data[counter + 4 : counter + 6]
        ip_address = socket.inet_ntoa(ip)
        port_num = int(binascii.hexlify(port),16)
        print(ip_address,':',port_num)
        counter+=8
        if counter >= len_of_decrypted:
            print("we will have a break bro -_- ")
            break 
data_decrypter()
