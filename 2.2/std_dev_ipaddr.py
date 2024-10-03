#!/usr/bin/env python3

#Assumes output from:
#tshark -r your_file.pcap -T fields -e ip.addr > ip_addresses.txt

from collections import Counter
import numpy as np

with open('ip_addresses.txt', 'r') as f:
    ip_addresses = [line.strip()
                    for line in f]  #account for win/linux new lines

counter = Counter(ip_addresses)

#need to use numpy array for calc
values = np.array(list(counter.values()))
mean = np.mean(values)
std = np.std(values)

#outlier definition more than 3 std away
outliers = {
    ip: count
    for ip, count in counter.items() if abs(count - mean) > 3 * std
}

#could print to json if you want
print("Outliers:")
for ip, count in outliers.items():
    print(f"{ip}: {count}")
