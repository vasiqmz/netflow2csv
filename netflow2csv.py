

from scapy.all import *

pcap_ref = rdpcap('netflow.pcap')
print('PCAP reading completed ... ')

print('Starting the defragmentation of netflow ...')

# A temporary fix for future Pull Request ... Issue # 1060, link for more info.
# https://github.com/secdev/scapy/issues/1060
decode_pcap = netflowv9_defragment(pcap_ref)
pkt_cnt = len(decode_pcap)
print('Received '+str(pkt_cnt)+' packets from the PCAP ...')

# Need to get the list of fields from the flows in packets
pcap_ref = rdpcap('netflow.pcap')
flow_fields = []
packet_list = pcap_ref.filter(lambda x: x.haslayer(NetflowFlowsetV9) or x.haslayer(NetflowOptionsFlowsetV9))
current = packet_list[0][NetflowFlowsetV9]
for ntv9 in current.templates:
	for template in ntv9.template_fields:
		flow_fields.append(NetflowV9TemplateFieldTypes[template.fieldType])
		
# print('Got the fields list ... '+str(flow_fields))

# Now open a new CSV file ...
netflow_csv_ref = open('netflow.csv', 'w')

# Create the header for the CSV 
header = ','.join(flow_fields)
netflow_csv_ref.write(header)
netflow_csv_ref.write('\n')

# we are starting from 0, so reduce the count by 1
pkt_cnt -= 1

print('Iterating the flows in each packet ...')
for pkt in range(0, pkt_cnt):

	# write down the packet # 
	netflow_csv_ref.write('Packet # '+str(pkt))
	netflow_csv_ref.write('\n')

	# Store the total flows count
	flows_cnt = (decode_pcap[pkt][NetflowHeader].count)+6
	tmp_pkt_flow = [] # store the flows temporarily in csv
	
	# print('In packet no .'+str(pkt)+' with flow count as '+str(flows_cnt))

	# print('Has '+str(flows_cnt)+' flows ...')

	# In pkt the data will be arrange as followed
	# [0] - from Ethernet Header onwards 
	# [1] - from IP header onwards
	# [2] - from UDP header onwards
	# [3] - Netflow Header onwards 
	# [4] - Netflow v9 Header onwards
	# [5] - Netflow DataFlowSet V9 onwards
	# [6] - will contain the FLOWS ... 
	# since we are only focusing on flows so 
	# we will start from 6 + flows_cnt to read all flows
	for flow in range (6, flows_cnt):

		# inside each flow ... go for attributes in it ...
		for field in flow_fields:
			try:				
				tmp = str(decode_pcap[pkt][flow].__getattr__(field))
				tmp_pkt_flow.append(tmp)
			except Exception as e:
				break #if no such attr. then break and go to next flow ...
		
		# time to convert data in list to CSV per-flow
		tmp_d = ','.join(tmp_pkt_flow)
		netflow_csv_ref.write(tmp_d)
		netflow_csv_ref.write('\n')
		tmp_pkt_flow = []	# reset the flow data for new flow 

	netflow_csv_ref.write('\n') # New line after every packet ...

print('Netflow pcap has been converted to CSV ...')
netflow_csv_ref.close() # closing the CSV file now ...



