#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <unistd.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <pthread.h>
#include "m_pcap.h"

pid_t g_pid;
int   g_seq;
int   g_ack;
unsigned int g_dsthost;
unsigned short g_port=80;

void send_tcp_raw(unsigned int, unsigned int, unsigned short);
unsigned short in_cksum(unsigned short *, int);
unsigned int host2ip(char *);
unsigned char optval_linux[] = {0x02, 0x04, 0x05, 0xb4, 0x04, 0x02, 0x08, 0x0a, 0x00, 0x0f, 0x4f, 0xb0, 0x00, 0x00, 0x00, 0x00, 0x01, 0x03, 0x03, 0x00};

#define HTTP_HEAD      "GET / HTTP/1.1\r\n" \
                       "User-Agent: Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1)\r\n" \
                       "Host: %s\r\n" \
                       "Accept */*\r\n\r\n"

main(int argc, char **argv)
{
    unsigned int srchost;
    unsigned int dsthost;
    unsigned short port=80;
    unsigned int number=1000;
    if(argc < 2)
    {
        printf("%s dsthost port\n", argv[0]);
        exit(0);
    }
    g_dsthost = host2ip(argv[1]);
    srchost = inet_addr("192.168.16.131");
    if(argc >= 3) g_port = atoi(argv[2]);
    if(port == 0) g_port = 80;

    pthread_t id = 0;
    g_pid = getpid();
    g_seq = 0;
    g_ack = 0;
    if(0 != pthread_create(&id, NULL, pcap_entry, NULL))
        return printf("error@phread_create");
    
    /*wait for libcap 5 seconds*/
    sleep(5);
    printf("synflooding %s from %s port %u %u times\n", argv[2], argv[1], port, number);
    send_tcp_raw(srchost, g_dsthost, port);
    pthread_join(id,NULL);
}

void send_tcp_raw(unsigned int source_addr, unsigned int dest_addr, unsigned short dest_port)
{
    struct send_tcp
    {
        struct iphdr ip;
        struct tcphdr tcp;
        char   opt[256];
    } send_tcp;
    struct pseudo_header
    {
        unsigned int source_address;
        unsigned int dest_address;
        unsigned char placeholder;
        unsigned char protocol;
        unsigned short tcp_length;
        struct tcphdr tcp;
        char   opt[256];
    } pseudo_header;
    int i;
    int tcp_socket;
    struct sockaddr_in sin;
    int sinlen;

    memset(&send_tcp,0,sizeof(struct send_tcp)); 
    /* form ip packet */
    send_tcp.ip.ihl = 5;
    send_tcp.ip.version = 4;
    send_tcp.ip.tos = 2;
    send_tcp.ip.tot_len = htons(60);
    send_tcp.ip.id = htons(g_pid); 
    send_tcp.ip.frag_off = 0;
    send_tcp.ip.ttl = 255;
    send_tcp.ip.protocol = IPPROTO_TCP;
    send_tcp.ip.check = 0;
    send_tcp.ip.saddr = source_addr;
    send_tcp.ip.daddr = dest_addr;

    /* form tcp packet */
    send_tcp.tcp.source = htons(g_pid);
    send_tcp.tcp.dest = htons(dest_port);
    send_tcp.tcp.seq = htonl(g_pid);
    send_tcp.tcp.ack_seq = 0;
    send_tcp.tcp.res1 = 0;
    send_tcp.tcp.doff = 0x0a;
    send_tcp.tcp.fin = 0;
    send_tcp.tcp.syn = 1;
    send_tcp.tcp.rst = 0;
    send_tcp.tcp.psh = 0;
    send_tcp.tcp.ack = 0;
    send_tcp.tcp.urg = 0;
    send_tcp.tcp.window = htons(65535);
    send_tcp.tcp.check = 0;
    send_tcp.tcp.urg_ptr = 0;

    /* setup the option */
    unsigned char *optp = (unsigned char*)send_tcp.opt;
    memcpy(optp, optval_linux, 20);

    /* setup the sin struct */
    sin.sin_family = AF_INET;
    sin.sin_port = send_tcp.tcp.source;
    sin.sin_addr.s_addr = send_tcp.ip.daddr;

    /* (try to) open the socket */
    tcp_socket = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if(tcp_socket < 0)
    {
        perror("socket");
        exit(1);
    }

    /* calculate the ip checksum */
    send_tcp.ip.check = in_cksum((unsigned short *)&send_tcp.ip, 20);

    /* set the pseudo header fields */
    pseudo_header.source_address = send_tcp.ip.saddr;
    pseudo_header.dest_address = send_tcp.ip.daddr;
    pseudo_header.placeholder = 0;
    pseudo_header.protocol = IPPROTO_TCP;
    pseudo_header.tcp_length = htons(40);
    bcopy((char *)&send_tcp.tcp, (char *)&pseudo_header.tcp, 20);
    bcopy((char *)send_tcp.opt, (char *)pseudo_header.opt, 20);
    send_tcp.tcp.check = in_cksum((unsigned short *)&pseudo_header, 52);
    sinlen = sizeof(sin);
    sendto(tcp_socket, &send_tcp, 60, 0, (struct sockaddr *)&sin, sinlen);

    usleep(10000);
    /*send ack*/
    send_tcp.tcp.syn = 0;
    send_tcp.tcp.ack = 1;
    send_tcp.tcp.check = 0;
    send_tcp.tcp.seq = htonl(g_pid + 1);
    send_tcp.tcp.ack_seq = htonl(g_seq + 1);
    bcopy((char *)&send_tcp.tcp, (char *)&pseudo_header.tcp, 20);
    send_tcp.tcp.check = in_cksum((unsigned short *)&pseudo_header, 52);
    sendto(tcp_socket, &send_tcp, 60, 0, (struct sockaddr *)&sin, sinlen);

    /*send http*/
    char headbuf[1024];
    struct in_addr dest;
    dest.s_addr = dest_addr; 
    snprintf(headbuf,sizeof(headbuf),HTTP_HEAD,inet_ntoa(dest));
    printf("buf=%s %d\n",headbuf,strlen(headbuf));
    int payloadlen = strlen(headbuf);
    bcopy((char *)headbuf,(char *)send_tcp.opt,256);

    int frag = 1;
    if(frag == 0){
        send_tcp.ip.tot_len = htons(20+20+payloadlen);
        /* calculate the ip checksum */
        send_tcp.ip.check = 0;
        send_tcp.ip.check = in_cksum((unsigned short *)&send_tcp.ip, 20);

        send_tcp.tcp.syn = 0;
        send_tcp.tcp.ack = 1;
        send_tcp.tcp.psh = 1;
        send_tcp.tcp.check = 0;
        send_tcp.tcp.doff = 0x05;
        send_tcp.tcp.seq = htonl(g_pid + 1);
        send_tcp.tcp.ack_seq = htonl(g_seq + 1);
        pseudo_header.tcp_length = htons(20+payloadlen);
        bcopy((char *)&send_tcp.tcp, (char *)&pseudo_header.tcp, 20);
        bcopy((char *)send_tcp.opt, (char *)pseudo_header.opt, 256);

        send_tcp.tcp.check = in_cksum((unsigned short *)&pseudo_header, 12+20+payloadlen);
        sendto(tcp_socket, &send_tcp, 40+payloadlen, 0, (struct sockaddr *)&sin, sinlen);
    }else{
        send_tcp.ip.tot_len = htons(20+24);
        /* calculate the ip checksum */
        send_tcp.ip.check = 0;
        send_tcp.ip.frag_off = htons(0x2000);
        send_tcp.ip.check = in_cksum((unsigned short *)&send_tcp.ip, 20);

        send_tcp.tcp.syn = 0;
        send_tcp.tcp.ack = 1;
        send_tcp.tcp.psh = 1;
        send_tcp.tcp.check = 0;
        send_tcp.tcp.doff = 0x05;
        send_tcp.tcp.seq = htonl(g_pid + 1);
        send_tcp.tcp.ack_seq = htonl(g_seq + 1);
        pseudo_header.tcp_length = htons(20+payloadlen);
        bcopy((char *)&send_tcp.tcp, (char *)&pseudo_header.tcp, 20);
        bcopy((char *)send_tcp.opt, (char *)pseudo_header.opt, 256);

        send_tcp.tcp.check = in_cksum((unsigned short *)&pseudo_header, 12+20+payloadlen);
        sendto(tcp_socket, &send_tcp, 44, 0, (struct sockaddr *)&sin, sinlen);
        printf("frag 1---------------------------\n");


        send_tcp.ip.tot_len = htons(20+20+payloadlen-24);
        /* calculate the ip checksum */
        send_tcp.ip.check = 0;
        send_tcp.ip.frag_off = htons(0x0003);
        send_tcp.ip.check = in_cksum((unsigned short *)&send_tcp.ip, 20);

        memmove((char *)&send_tcp.tcp,(char *)&send_tcp.tcp + 24 ,payloadlen-4);
        sendto(tcp_socket, &send_tcp, 16+payloadlen, 0, (struct sockaddr *)&sin, sinlen);
        printf("frag 2---------------------------\n");
    }
    close(tcp_socket);
}

unsigned short in_cksum(unsigned short *ptr, int nbytes)
{
    register long sum; /* assumes long == 32 bits */
    u_short oddbyte;
    register u_short answer; /* assumes u_short == 16 bits */

    /*
     * Our algorithm is simple, using a 32-bit accumulator (sum),
     * we add sequential 16-bit words to it, and at the end, fold back
     * all the carry bits from the top 16 bits into the lower 16 bits.
     */

    sum = 0;
    while (nbytes > 1) {
        sum += *ptr++;
        nbytes -= 2;
    }

    /* mop up an odd byte, if necessary */
    if (nbytes == 1) {
        oddbyte = 0; /* make sure top half is zero */
        *((u_char *) &oddbyte) = *(u_char *)ptr; /* one byte only */
        sum += oddbyte;
    }

    /*
     * Add back carry outs from top 16 bits to low 16 bits.
     */

    sum = (sum >> 16) + (sum & 0xffff); /* add high-16 to low-16 */
    sum += (sum >> 16); /* add carry */
    answer = ~sum; /* ones-complement, then truncate to 16 bits */
    return(answer);
}

unsigned int host2ip(char *hostname)
{
    static struct in_addr i;
    struct hostent *h;
    i.s_addr = inet_addr(hostname);
    if(i.s_addr == -1)
    {
        h = gethostbyname(hostname);
        if(h == NULL)
        {
            fprintf(stderr, "cant find %s!\n", hostname);
            exit(0);
        }
        bcopy(h->h_addr, (char *)&i.s_addr, h->h_length);
    }
    return i.s_addr;
}
