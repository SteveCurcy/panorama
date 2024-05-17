#define SSL_MAX_LEN 16384
#define SSL_LEN_MASK 16383

struct ssl_pr_inet
{
    __u16 family;
    __u16 port;
    __u32 ip;
    char pad[8];
};

struct ssl_socket
{
    __u32 local_ip;
    __u32 remote_ip;
    __u16 local_port;
    __u16 remote_port;
};

struct ssl_event
{
    struct ssl_socket sock;
    char content[SSL_MAX_LEN];
    int from;
    int size;
};