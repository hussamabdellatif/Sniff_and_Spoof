# Sniff_and_Spoof
A C program that filters out packets, and spoofs all packets sent using ICMP protocol.

The sniff file (sniffex.c) is created by the Tcpdump Group which is a modification of Tim Carstens "sniffer.c" software.

The sniff file is then modified (by me) to activate the spoof function inside (spoof.c) once a packet has been captured if and only if that packet uses the ICMP protocol.

The spoof.c file then creates a packet from scratch and sends back an ICMP packet to which ever device intially sent out the packet. 


**********************************
Example of how the program works....

Node 1 on the network pings Node 3 ( however node 3 does not exist) <br>
Node 2 (the attacker) sniffs the packet (sniffex.c)<br>
Node 2 spoofs the packet and puts down Node3's address as the source address and Node1's address as the destination add.(spoof.c)<br>
Node 2 then sends out the packet to Node 1<br>
Node 1 then concludes that Node 3 is alive and exists on the network <br>
**********************************

Most of the code inside spoof.c was written by me with the exception of some helper functions written by the teaching assitants in my Computer Security course (CSE 365: University At Buffalo).

Feel free to alter the code to launch the same attack for different protocols. 
