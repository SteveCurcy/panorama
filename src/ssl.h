#define SSL_MAX_LEN     16384
#define SSL_LEN_MASK    16383

struct ssl_socket {
    __u32 from_ip;
    __u32 to_ip;
    __u16 from_port;
    __u16 to_port;
};

struct ssl_event {
    struct ssl_socket sock;
    char content[SSL_MAX_LEN];
    int from;
    int size;
};