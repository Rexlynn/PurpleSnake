#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>  // <errno.h> for reading the errors

#ifdef _WIN32
    #include <winsock2.h>
    #include <windows.h>
    #include <ws2tcpip.h>
    #include <iphlpapi.h>
    #pragma comment(lib, "iphlpapi.lib") // This one for adding libs to Windows

    // Note: When compiling, -lws2_32 and -liphlpapi should be added with gcc

#else
    #include <sys/types.h>
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <netinet/ip.h>
    #include <netinet/tcp.h>
    #include <arpa/inet.h>
    #include <unistd.h>
    #include <sys/time.h> // for the struct timeval
    #include <linux/if_packet.h>
    #include <linux/if_ether.h>
    #include <net/ethernet.h>
    #include <netinet/udp.h>
#endif






// These are prototypes.
const char* get_service_name(int port);
void run_port_scanner();
void run_xor_tool();
void run_packet_sniffer(); // Windows -> Monitor, Linux -> Raw Capture

// Main skeleton of menu

int main(){

    int choice;

    while(1) {
        printf("\n=== Multi-Platform Security Toolkit ===\n");
        printf("1) Port Scanner\n");
        printf("2) XOR Encrypt / Decrypt\n");
        printf("3) Packet Sniffer / Network Monitor\n");
        printf("0) Exit\n");
        printf("Your Choice: ");

        if (scanf("%d", &choice) !=1) {
            // If the user writes nonsense, clear the input
            printf("Invalid input, Exiting.\n");
            break;
        }

       // To clear the \n remaining in the buffer after scanf
       int c;
       while ((c = getchar()) != '\n' && c != EOF);

       switch (choice) {
        case 1:
            run_port_scanner();
            break;
        case 2:
            run_xor_tool();
            break;
        case 3:
            run_packet_sniffer();
            break;
        case 0:
            printf("Exiting...\n");
            return 0;
        default:
            printf("Invalid choice, try again.\n");

       }       

    }

    return 0;

}

// Function for the service names
const char* get_service_name(int port) {
    switch(port) {
        case 20: return "FTP Data";
        case 21: return "FTP";
        case 22: return "SSH";
        case 23: return "Telnet";
        case 25: return "SMTP";
        case 53: return "DNS";
        case 67: return "DHCP";
        case 69: return "TFTP";
        case 80: return "HTTP";
        case 110: return "POP3";
        case 143: return "IMAP";
        case 443: return "HTTPS";
        case 445: return "SMB";
        case 3306: return "MySQL DB";
        case 3389: return "RDP";
        default: return "Unknown/Custom Service";
    }
}

void run_xor_tool() {
    char input_path[256];
    char output_path[256];
    char key[256];

    printf("\n=== XOR Encrypt/Decrypt Tool ===\n");

    printf("Enter input file path: ");
    fgets(input_path, sizeof(input_path), stdin);
    input_path[strcspn(input_path, "\n")] = '\0';

    printf("Enter output file path: ");
    fgets(output_path, sizeof(output_path), stdin);
    output_path[strcspn(output_path, "\n")] = '\0';

    printf("Enter key (string): ");
    fgets(key, sizeof(key), stdin);
    key[strcspn(key, "\n")] = '\0';


    if (strlen(key) == 0) {
        printf("Key cannot be empty!\n");
        return;
    }

    FILE *fin = fopen(input_path, "rb");
    if (!fin) {
        printf("Could not open input file.\n");
        return;
    }

    FILE *fout = fopen(output_path, "wb");
    if (!fout) {
        printf("Could not create output file.\n");
        fclose(fin);
        return;
    }

    size_t key_len = strlen(key);
    int ch;
    size_t i = 0;

    while ((ch = fgetc(fin)) != EOF) {
        unsigned char enc = ((unsigned char)ch) ^ ((unsigned char)key[i % key_len]);
        fputc(enc, fout);
        i++;
    }

    fclose(fin);
    fclose(fout);

    printf("Done! Output saved to %s\n", output_path);

}

void run_port_scanner() {
    char target_ip[100];
    int start_port, end_port;

    printf("\n=== Port Scanner ===\n");

    // Take the IP 
    printf("Enter target IP: ");
    fgets(target_ip, sizeof(target_ip), stdin);
    target_ip[strcspn(target_ip, "\n")] = '\0'; // Remove newline


    //  Starting port
    printf("Enter starting port: ");
    scanf("%d", &start_port);

    // Ending port
    printf("Enter ending port: ");
    scanf("%d", &end_port);

    // Clear the buffer after scanf
    int c;
    while ((c = getchar()) != '\n' && c != EOF);

    // Simple validation
    if (start_port < 1 || end_port > 65535 || start_port > end_port) {
        printf("Invalid port range, ports must be between 1 and 65535 and start <= end.\n");
        return;
    }

#ifdef _WIN32
    // Start winsock for Windows OS
    WSADATA wsa;
    if (WSAStartup(MAKEWORD(2, 2), &wsa) !=0) {
        printf("WSAStartup failed.\n");
        return;
    }
#endif

    // Target address structure (the IP part is set here, we will change the port within the loop)
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;


    // Convert IP string to binary format (inet_pton)
    if (inet_pton(AF_INET, target_ip, &addr.sin_addr) <= 0) {
        printf("Invalid IP address format.\n");
#ifdef _WIN32
        WSACleanup();
#endif
        return;
    }

    printf("\nScanning %s from port %d to %d...\n", target_ip, start_port, end_port);

    // PORT SCANNER LOOP
    for (int port = start_port; port <= end_port; port++) {

#ifdef _WIN32
        SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (sock == INVALID_SOCKET) {
            printf("Failed to create socket.\n");
            break;
        }

        // Timeout duration (ms)
        DWORD timeout = 1000; // 1 second
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout));
        setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (const char*)&timeout, sizeof(timeout));

#else
        int sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock < 0) {
            perror("Socket");
            break;
        }


        struct timeval tv;
        tv.tv_sec = 1; // 1 second 
        tv.tv_usec = 0;
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

#endif

        // Set the port number on each port
        addr.sin_port = htons(port);

        // Try to connect
        int result = connect(
            sock,
            (struct sockaddr *)&addr,
            sizeof(addr)
        );

#ifdef _WIN32
        if (result == 0) {
            printf("Port %5d OPEN (%s)\n", port, get_service_name(port));
        } else {
            int err = WSAGetLastError();
            if (err == WSAETIMEDOUT) {
                printf("Port %5d FILTERED (no response)\n", port);
            } else if (err == WSAECONNREFUSED) {
                printf("Port %5d CLOSED.\n", port);
            } else {
                printf("Port %5d FILTERED/ERROR (code %d)\n", port, err);
            }
        }
        closesocket(sock);

#else
        if (result == 0) {
            printf("Port %5d OPEN (%s)\n", port, get_service_name(port));
        } else {
            if (errno == ETIMEDOUT) {
                printf("Port %5d FILTERED (no response)\n", port);
            } else if (errno == ECONNREFUSED) {
                printf("Port %5d CLOSED.\n", port);
            } else {
                printf("Port %5d FILTERED/ERROR (errno %d)\n", port, errno);
            }
        }
        close(sock);
#endif
    }

#ifdef _WIN32
    WSACleanup();
#endif

    printf("Scan Complete.\n");

}

void run_packet_sniffer() {

#ifdef _WIN32
    printf("\n=== Windows Network Monitor ===\n");
    

    PMIB_TCPTABLE_OWNER_PID tcpTable;
    DWORD size = 0;
    DWORD result = GetExtendedTcpTable(NULL, &size, TRUE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);


    tcpTable = (PMIB_TCPTABLE_OWNER_PID)malloc(size);
    result = GetExtendedTcpTable(tcpTable, &size, TRUE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);

    if (result != NO_ERROR) {
        printf("Failed to retrieve TCP table.\n");
        return;
    }

    printf("Active TCP Connections: %lu\n", tcpTable->dwNumEntries);
    printf("------------------------------------------------------------\n");
    printf("PID        | Local Address        | Remote Address       | State\n");
    printf("------------------------------------------------------------\n");

    for (DWORD i = 0; i < tcpTable->dwNumEntries; i++) {
        MIB_TCPROW_OWNER_PID row = tcpTable->table[i];

        struct in_addr localAddr;
        struct in_addr remoteAddr;
        localAddr.S_un.S_addr = row.dwLocalAddr;
        remoteAddr.S_un.S_addr = row.dwRemoteAddr;

        // Connection states
        const char* state;
        switch (row.dwState) {
            case MIB_TCP_STATE_LISTEN: state = "LISTENING"; break;
            case MIB_TCP_STATE_ESTAB: state = "ESTABLISHED"; break;
            case MIB_TCP_STATE_SYN_SENT: state = "SYN-SENT"; break;
            case MIB_TCP_STATE_SYN_RCVD: state = "SYN-RECEIVED"; break;
            case MIB_TCP_STATE_CLOSE_WAIT: state = "CLOSE-WAIT"; break;
            case MIB_TCP_STATE_CLOSED: state = "CLOSED"; break;
            default: state = "OTHER"; break;
        }

        printf("PID: %-5lu | %-15s:%d | %-15s:%d | %s\n",
           row.dwOwningPid,
           inet_ntoa(localAddr), ntohs((u_short)row.dwLocalPort),
           inet_ntoa(remoteAddr), ntohs((u_short)row.dwRemotePort),
           state
        );
    }

    free(tcpTable);

    

#else

if (geteuid() != 0) {
    printf("This tool must be run as root.\n");
    return;
}

    printf("\n=== Linux Raw Packet Sniffer ===\n");

    int sock_raw = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock_raw < 0) {
        perror("Socket Error");
        return;
    }

    unsigned char buffer[65536];
    struct sockaddr saddr;
    int saddr_len = sizeof(saddr);

    while(1) {

    static int packet_count = 0;

    int data_size = recvfrom(sock_raw, buffer, sizeof(buffer), 0,
                             &saddr, (socklen_t*)&saddr_len);

    if (data_size < 0) {
        perror("recvfrom error");
        break;
    }

    struct ethhdr *eth = (struct ethhdr *)buffer;

    // ARP
    if (ntohs(eth->h_proto) == 0x0806) {
        printf("[ARP] Address Resolution Protocol\n");
        continue;
    }

    // Only IPv4 (skip others)
    if (ntohs(eth->h_proto) != 0x0800) {
        continue;
    }

    // IPv4 header
    struct iphdr *ip = (struct iphdr *)(buffer + sizeof(struct ethhdr));

    struct in_addr src, dst;
    src.s_addr = ip->saddr;
    dst.s_addr = ip->daddr;

    char src_ip[INET_ADDRSTRLEN];
    char dst_ip[INET_ADDRSTRLEN];

    inet_ntop(AF_INET, &src, src_ip, sizeof(src_ip));
    inet_ntop(AF_INET, &dst, dst_ip,sizeof(dst_ip));

    // ICMP
    if (ip->protocol == 1) {
        printf("[ICMP] %s -> %s\n", src_ip, dst_ip);
        packet_count++;
    }

    // TCP
    else if (ip->protocol == 6) {
        struct tcphdr *tcp = (struct tcphdr *)(buffer + sizeof(struct ethhdr) + ip->ihl * 4);

        printf("[TCP] %s:%u -> %s:%u\n",
               src_ip, ntohs(tcp->source),
               dst_ip, ntohs(tcp->dest));

        printf(" Flags: %s%s%s\n",
            tcp->syn ? "SYN " : "",
            tcp->ack ? "ACK " : "",
            tcp->fin ? "FIN " : "");
            packet_count++;
    }

    // UDP
    else if (ip->protocol == 17) {
        struct udphdr *udp = (struct udphdr *)(buffer + sizeof(struct ethhdr) + ip->ihl * 4);

        unsigned short src_port = ntohs(udp->source);
        unsigned short dst_port = ntohs(udp->dest);

        printf("[UDP] %s:%u -> %s:%u\n",
               src_ip, src_port,
               dst_ip, dst_port);

        if (src_port == 53 || dst_port == 53) {
            printf("[DNS] Domain Name Lookup Detected\n");
       
        }

        packet_count++;

    }

    if (packet_count >= 20) {
        printf("\n[INFO] 20 packets captured. Exiting...\n");
        break;
        
    }
}

    close(sock_raw);

#endif
}