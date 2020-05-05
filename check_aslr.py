import os
import sys
import subprocess

def execute_test_aslr():
    path = "C:\\Users\\researcher\\source\\repos\\TestASLR\\Release\\TestASLR.exe"
    path64 = "C:\\Users\\researcher\\source\\repos\\TestASLR\\x64\\Release\\TestASLR.exe"
    out_32 = subprocess.run([path], stdout=subprocess.PIPE) # run 32-bit binary
    out_64 = subprocess.run([path64], stdout=subprocess.PIPE) # run 64-bit as well
    return out_32.stdout, out_64.stdout

count = int(open("C:\\Users\\researcher\\Desktop\\count.txt", 'r').readlines()[0])
file_to_write = open("C:\\Users\\researcher\\Desktop\\count.txt", 'w')
print(count)
count = int(count)
if count < 1000: # run it 1000 times
    count += 1
    file_to_write.write(str(count))
    file_to_write.close()
else:
    sys.exit(0)

file_to_save = open("C:\\Users\\researcher\\Desktop\\aslr_check", 'a')
aslr_data, aslr64_data = execute_test_aslr()
print(aslr_data, aslr64_data)
file_to_save.write("\nNew Run \n")
file_to_save.write(aslr_data.decode("utf-8"))
file_to_save.write("64-bit run\n")
file_to_save.write(aslr64_data.decode("utf-8"))
os.system("shutdown /r /t 0") # restart system to refresh ASLR