# Netflow2CSV 
Netflow2CSV is a python-based tool that uses Scapy to convert the netflow packets into a CSV format.
Currently it works with Netflow v9 packets.

# Installation
Netflow2CSV uses Scapy to read and decode the netflow flows. Since the support of Netflow V9 is not merged in the master-branch, so I have put the scapy package with this repo. 
``` 
git clone https://github.com/vasiqmz/netflow2csv
cd netflow2csv
execute netflow2csv.py
```

# Prerequisites
For now, the code is pretty straight forward and does not do lot of checks. So it assume the following conditions to run it successfully.
1. Need Python 3 to run the code.
2. The netflow pcap file should be named as 'netflow.pcap'

# Acknoledgement
* Thanks to [GPotter2] (https://github.com/gpotter2) for modifying the netflowv9 code.
