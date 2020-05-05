import os
import sys
import subprocess

def get_changed_bits(module_addr, bits_changed_orig, addrs):
    res = list()

    for addr in addrs:
        changed_bits = module_addr ^ addr
        x = 0       
        while changed_bits:
            if (changed_bits & 1):
                if x not in bits_changed_orig and x not in res:
                    res.append(x)

            x += 1
            changed_bits = changed_bits >> 1
    return res

content = open("C:\\Users\\researcher\\Desktop\\aslr_check", 'r').readlines()

module_addr = 0
module_name = ""
bits_changed = dict()
module_addrs = dict()
is_64 = 0
count = 1
for line in content:
    if "64-bit run" in line:
        is_64 = 1
    elif "New Run" in line:
        #print(count)
        is_64 = 0
        count += 1

    if "Module" in line:
        line = line.split(" ")
        module_addr = int(line[5], 16)
        module_name = line[1]
        if is_64 == True:
            module_name += "_64"
        if module_name in bits_changed:
            bits_changed_list = get_changed_bits(module_addr, bits_changed[module_name], module_addrs[module_name])
            for bit_changed in bits_changed_list:
                bits_changed[module_name].append(bit_changed)
        else:
            bits_changed[module_name] = get_changed_bits(module_addr, None, list())
            module_addrs[module_name] = list()
        module_addrs[module_name].append(module_addr)

for name in bits_changed:
    bits_changed[name].sort()
    print(name, bits_changed[name], len(bits_changed[name]))