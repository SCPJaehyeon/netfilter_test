#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>		/* for NF_ACCEPT */
#include <errno.h>
#include <string.h>
#include <libnetfilter_queue/libnetfilter_queue.h>

#include <pcap.h>

static char *host;
static int cmp;
int police(unsigned char *data){
    printf("IN police \n");
    if(data[9] == 0x06 && data[22] == 0x00 && data[23] == 0x50){ //Check TCP(6), HTTP(80)
        printf("ok1 \n");
        if((data[40] == 0x47 && data[41] == 0x45 && data[42] == 0x54) || //Check GET
                 (data[40] == 0x50 && data[41] == 0x4f && data[42] == 0x53 && data[43] == 0x54) || //Check POST
                 (data[40] == 0x48 && data[41] == 0x45 && data[42] == 0x41 && data[43] == 0x44) || //Check HEAD
                 (data[40] == 0x50 && data[41] == 0x55 && data[42] == 0x54) || //Check PUT
                 (data[40] == 0x44 && data[41] == 0x45 && data[42] == 0x4c && data[43] == 0x45 && data[44] == 0x54 && data[45] == 0x45) || //Check DELETE
                 (data[40] == 0x43 && data[41] == 0x4f && data[42] == 0x4e && data[43] == 0x4e && data[44] == 0x45 && data[45] == 0x43 && data[46] == 0x54) || //Check CONNECT
                 (data[40] == 0x4f && data[41] == 0x50 && data[42] == 0x54 && data[43] == 0x49 && data[44] == 0x4f && data[45] == 0x4e && data[46] == 0x53) || //Check OPTIONS
                 (data[40] == 0x54 && data[41] == 0x52 && data[42] == 0x41 && data[43] == 0x43 && data[44] == 0x45) || //Check TRACE
                 (data[40] == 0x50 && data[41] == 0x41 && data[42] == 0x54 && data[43] == 0x43 && data[44] == 0x48)){ //Check PATCH
            printf("ok2 \n");
            int i;
            for (i=43;i<55;i++){ //Find ':'
                if(data[i] == 0x0d && data[i+1] == 0x0a){ //Check Host':'
                    printf("find %d \n",i);
                    int cmp = memcmp(host, &data[i+8],sizeof(host)); //Check argv[1] and Request HOST
                    return cmp;
                }
            }
        }
        else{
            return 2;
        }
    }
    else{
        return 1;
    }
}

void dump(unsigned char* buf, int size) {
    int i;
    for (i = 0; i < size; i++) {
        if (i % 16 == 0)
            printf("\n");
        printf("%02x ", buf[i]);
    }
}

/* returns packet id */
static u_int32_t print_pkt (struct nfq_data *tb)
{
    int id = 0;
    struct nfqnl_msg_packet_hdr *ph;
    struct nfqnl_msg_packet_hw *hwph;
    u_int32_t mark,ifi;
    int ret;
    unsigned char *data;

    ph = nfq_get_msg_packet_hdr(tb);
    if (ph) {
        id = ntohl(ph->packet_id);
        printf("hw_protocol=0x%04x hook=%u id=%u ",
            ntohs(ph->hw_protocol), ph->hook, id);
    }

    hwph = nfq_get_packet_hw(tb);
    if (hwph) {
        int i, hlen = ntohs(hwph->hw_addrlen);

        printf("hw_src_addr=");
        for (i = 0; i < hlen-1; i++)
            printf("%02x:", hwph->hw_addr[i]);
        printf("%02x ", hwph->hw_addr[hlen-1]);
    }

    mark = nfq_get_nfmark(tb);
    if (mark)
        printf("mark=%u ", mark);

    ifi = nfq_get_indev(tb);
    if (ifi)
        printf("indev=%u ", ifi);

    ifi = nfq_get_outdev(tb);
    if (ifi)
        printf("outdev=%u ", ifi);
    ifi = nfq_get_physindev(tb);
    if (ifi)
        printf("physindev=%u ", ifi);

    ifi = nfq_get_physoutdev(tb);
    if (ifi)
        printf("physoutdev=%u ", ifi);

    ret = nfq_get_payload(tb, &data);
    cmp = police(data);
    dump(data, ret);
    printf("\n cmp : %d \n",cmp);
    if (ret >= 0)
        printf("payload_len=%d ", ret);

    fputc('\n', stdout);

    return id;
    //return cmp;
}


static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
          struct nfq_data *nfa, void *data)
{
    u_int32_t id = print_pkt(nfa);
    printf("id = %d \n",id);
    printf("entering callback\n");
        if(cmp==0){return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);}
        else {return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);}
}

int main(int argc, char **argv)
{
    struct nfq_handle *h;
    struct nfq_q_handle *qh;
    struct nfnl_handle *nh;
    int fd;
    int rv;
    char buf[4096] __attribute__ ((aligned));
    host = argv[1];
    printf("opening library handle\n");
    h = nfq_open();
    if (!h) {
        fprintf(stderr, "error during nfq_open()\n");
        exit(1);
    }

    printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
    if (nfq_unbind_pf(h, AF_INET) < 0) {
        fprintf(stderr, "error during nfq_unbind_pf()\n");
        exit(1);
    }

    printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
    if (nfq_bind_pf(h, AF_INET) < 0) {
        fprintf(stderr, "error during nfq_bind_pf()\n");
        exit(1);
    }

    printf("binding this socket to queue '0'\n");
    qh = nfq_create_queue(h,  0, &cb, NULL);
    if (!qh) {
        fprintf(stderr, "error during nfq_create_queue()\n");
        exit(1);
    }

    printf("setting copy_packet mode\n");
    if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
        fprintf(stderr, "can't set packet_copy mode\n");
        exit(1);
    }

    fd = nfq_fd(h);

    for (;;) {
        if ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
            printf("pkt received\n");
            nfq_handle_packet(h, buf, rv);
            continue;
        }
        /* if your application is too slow to digest the packets that
         * are sent from kernel-space, the socket buffer that we use
         * to enqueue packets may fill up returning ENOBUFS. Depending
         * on your application, this error may be ignored. nfq_nlmsg_verdict_putPlease, see
         * the doxygen documentation of this library on how to improve
         * this situation.
         */
        if (rv < 0 && errno == ENOBUFS) {
            printf("losing packets!\n");
            continue;
        }
        perror("recv failed");
        break;
    }

    printf("unbinding from queue 0\n");
    nfq_destroy_queue(qh);

#ifdef INSANE
    /* normally, applications SHOULD NOT issue this command, since
     * it detaches other programs/sockets from AF_INET, too ! */
    printf("unbinding from AF_INET\n");
    nfq_unbind_pf(h, AF_INET);
#endif

    printf("closing library handle\n");
    nfq_close(h);

    exit(0);
}

