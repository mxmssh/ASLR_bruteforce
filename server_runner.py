import os
import sys
import subprocess
import time

start = time.time()
while True:
    print("Starting\n")
    if "64" in sys.argv[1]:
        path = "C:\\Users\\researcher\\source\\repos\\TestASLR\\x64\\Release\\TestASLR.exe"
    else:
        path = "C:\\Users\\researcher\\source\\repos\\TestASLR\\Release\\TestASLR.exe"
    out = subprocess.run([path], stdout=subprocess.PIPE)
    print("Process stopped with return code %d" % out.returncode, out)
    if out.returncode == 2:
        print("Address was correctly predicted")
        break

done = time.time()
elapsed = done - start
print(elapsed)