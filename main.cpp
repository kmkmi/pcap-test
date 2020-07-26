#include <pcap.h>
#include <stdio.h>
#include <cstring>
#include <string>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>


void usage() {
    printf("syntax: pcap-test <interface> <count>\n");
    printf("sample: pcap-test wlan0 20(Maximum count : 20)\n");
}

char* ntoh_hex(u_int8_t *addr, char* buf, int size)
{

    for(int i=0;i<size;i++)
    {
        snprintf(buf+(3*i),size, "%02x",addr[i]);
        if(i!=size-1)
            snprintf(buf+2+(3*i),2,":");

    }

    return buf;

}


void callback(u_char *user ,const struct pcap_pkthdr* header, const u_char* pkt_data ){

    struct ether_header *eth_hdr;
    struct ip *ipv4_hdr;
    struct tcphdr *tcp_hdr;

    char result[256];
    char buf[20];
    int len;

    printf("\n\n%u bytes captured\n", header->caplen);

    eth_hdr = (struct ether_header*)pkt_data; //Ethernet header starting point.


    len = snprintf(result, 36, "source MAC: %s",
           ntoh_hex(eth_hdr->ether_shost,buf,6));
    len += snprintf(result+len, 50,  " | dest MAC: %s | ether type: %x ",
           ntoh_hex(eth_hdr->ether_dhost,buf,6), ntohs(eth_hdr->ether_type));


    if(ntohs(eth_hdr->ether_type) == ETHERTYPE_IP){
        pkt_data+= sizeof(ether_header);
        ipv4_hdr = (struct ip*)pkt_data;

        len += snprintf(result+len , 36, "\nsource IP: %s",
               inet_ntoa(ipv4_hdr->ip_src));
        len += snprintf(result+len , 50, " | dest IP: %s | protocoal :%x\n",
               inet_ntoa(ipv4_hdr->ip_dst), ipv4_hdr->ip_p);

        if(ipv4_hdr->ip_p == IPPROTO_TCP){

            printf("%s", result);

            pkt_data += ipv4_hdr->ip_hl * 4;
            tcp_hdr = (struct tcphdr*)pkt_data;

            printf("source Port: %d | dest Port: %d \n",
                   ntohs(tcp_hdr->source), ntohs(tcp_hdr->dest));


            int tcp_hdr_len = tcp_hdr->th_off*4;
            pkt_data += tcp_hdr_len;

            if(int size = header->caplen-tcp_hdr_len < 16){
                strncpy(buf, (char*)pkt_data, size);
                buf[size]= '\0';
                printf("data %dbytes: %s\n", size, buf);
            }
            else{
                strncpy(buf, (char*)pkt_data, 16);
                buf[16] = '\0';
                printf("data 16bytes: %s\n", buf);
            }





        }


    }


}




int main(int argc, char* argv[]) {
    if (argc != 3) {
        usage();
        return -1;
    }
    if(atoi(argv[2])>20){
        printf("Please choose the number not over 20.");
        return -1;
}

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t* alldevsp;
    pcap_if_t* dev;
    bpf_u_int32 netp;
    bpf_u_int32 maskp;
    struct bpf_program fp;



    if(pcap_findalldevs(&alldevsp, errbuf) == -1){
        fprintf(stderr, "pcap_findalldevs return nullptr - %s\n",errbuf);
        return -1;
    }

    for(dev = alldevsp; dev; dev=dev->next){
        printf("%s\n", dev->name);
        if(strncmp(dev->name, argv[1], strlen(dev->name))==0)
            break;
    }

    if(dev == nullptr){
        fprintf(stderr, "No matching network interface '%s'.\n", argv[1]);
        return -1;
    }

    if(pcap_lookupnet(dev->name, &netp, &maskp, errbuf) == -1){
        fprintf(stderr, "pcap_lookupnet(%s) return nullptr - %s\n", dev->name, errbuf);
        return -1;
    }


    pcap_t* handle = pcap_open_live(dev->name, BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "pcap_open_live(%s) return nullptr - %s\n", dev->name, errbuf);
        return -1;
    }

    if(pcap_compile(handle, &fp, "" , 0, netp)==-1){
        fprintf(stderr, "pcap_compile failed\n");
        return -1;
    }

    if(pcap_setfilter(handle, &fp) == -1){
        fprintf(stderr, "pcap_setfileter failed\n");
        return -1;
    }


    int ret = pcap_loop(handle, atoi(argv[2]), callback, nullptr );
    if (ret == -1 || ret == -2) {
        printf("pcap_next_ex return %d(%s)\n", ret, pcap_geterr(handle));
        pcap_close(handle);
        return -1;
    }
    pcap_close(handle);

    return 0;

}
