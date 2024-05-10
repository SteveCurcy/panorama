#define SSL_MAX_LEN     16384
#define SSL_LEN_MASK    16383

struct ssl_event {
    char content[SSL_MAX_LEN];
    int from;
    int size;
};