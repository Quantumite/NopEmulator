"""Parse PCAP files and output to .bin to be processed by NopEmulator."""
import sys
import os
from scapy.all import *

def main():
    my_pcap = rdpcap(sys.argv[1])
    file_name = os.path.basename(sys.argv[1])
    print(file_name)
    for i,packet in enumerate(my_pcap):
        if packet.haslayer('TCP'):
            with open(f"{file_name.replace('.','_')}_{i}.bin", "wb") as f:
                f.write(bytes(packet['TCP'].payload))
        elif packet.haslayer('UDP'):
            with open(f"{file_name.replace('.','_')}_{i}.bin", "wb") as f:
                f.write(bytes(packet['UDP'].payload))
        else:
            pass

if __name__ == "__main__":
    main()