#include <stdio.h>
#include <unistd.h>
#include <string.h>

int main() {
    getchar();
    char *argv[ ]={"ls", "-al", "/etc/passwd", NULL};
    char *envp[ ]={"PATH=/bin", NULL};
    execve("/usr/bin/ls", argv, envp);
    return 0;
}