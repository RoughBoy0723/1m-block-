#include <iostream>
#include <set>
#include <string>
#include <fstream>
#include <cstdlib>
#include <cstring>
#include <cerrno>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/netfilter.h>
#include <linux/types.h>
#include <unistd.h>

#include <libnetfilter_queue/libnetfilter_queue.h>

#include <cstdio>     // C++ 스타일의 표준 입출력
#include <libnet.h>   // 네트워크 패킷 조작 라이브러리
using namespace std;


static bool url_block(struct nfq_data *nfa, set<string>* URL) {
    unsigned char *data;

    nfq_get_payload(nfa, &data);

    struct libnet_ipv4_hdr* ip_hdr = (struct libnet_ipv4_hdr *)data;
    struct libnet_tcp_hdr* tcp_hdr = (struct libnet_tcp_hdr *)(data + (ip_hdr->ip_hl * 4));
    unsigned char *chttp = data + (ip_hdr->ip_hl * 4) + (tcp_hdr->th_off * 4);
    string http((char*)chttp);
    printf("--------------\n");
    printf("0x%x\n", ip_hdr->ip_p);
    if ((ip_hdr->ip_p == 0x06)) {
        printf("0x%x\n", ntohs(tcp_hdr->th_dport));
        if (ntohs(tcp_hdr->th_dport) == 80) {
            size_t start = http.find("www.") + 4;
            if (start == string::npos) {
                return true;
            }

            size_t end = http.find("\r\n", start);
            if (end == string::npos) {
                return true;
            }

            if (end <= start) {
                return true;
            }

            string extracted = http.substr(start, end - start);
            cout << "Host: "<< extracted <<endl<<endl;
            if (URL->count(extracted)) {
                cout << "The " << extracted << " was blocked\n";
                printf("--------------\n\n");
                return false;
            }
        }
    }
    printf("--------------\n\n");
    return true;
}

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
              struct nfq_data *nfa, void *URL)
{
    uint32_t id;
    set<string>* urlSet = static_cast<set<string>*>(URL);

    struct nfqnl_msg_packet_hdr *ph = nfq_get_msg_packet_hdr(nfa);
    if (ph) {
        id = ntohl(ph->packet_id);
        printf("hw_protocol=0x%04x hook=%u id=%u ",ntohs(ph->hw_protocol), ph->hook, id);
    }
    printf("entering callback\n");

    if(url_block(nfa, urlSet)){
        return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);

    }else{
        return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
    }
}


int main(int argc, char *argv[])
{
    struct nfq_handle *h;
    struct nfq_q_handle *qh;
    struct nfnl_handle *nh;
    int fd;
    int rv;
    char buf[4096] __attribute__ ((aligned));

    if(argc != 2){
        cout << "./1m-block <usage>\n";
    }

    set<string> URL;

    ifstream inputFile(argv[1]);
    string line;

    if (!inputFile.is_open()) {
        cerr << "파일을 열 수 없습니다.\n";
        return 1;
    }

    while (getline(inputFile, line)) {
        size_t commaPos = line.find(',');
        if (commaPos != string::npos) {
            //cout << line.substr(commaPos + 1) << endl;
            URL.insert(line.substr(commaPos + 1));
        }
    }
    cout << "File memory upload finish\n";

    inputFile.close();

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
    qh = nfq_create_queue(h,  0, &cb, &URL);
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
