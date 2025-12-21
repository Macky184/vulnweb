#include <stdio.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <stdint.h>

int main(void);
static void canary(char *out, int *off, size_t outsz);

static int g_global = 1234;
extern uintptr_t __stack_chk_guard;

static void send_text(int client, const char *body){
    char header[256];
    size_t len = strlen(body);
    int n = snprintf(header,
        sizeof(header),
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: text/plain; charset=utf-8\r\n"
        "Content-length: %zu\r\n"
        "Connection: close\r\n"
        "\r\n",
        len);
    write(client, header, (size_t)n);
    write(client, body, len);
}

static void debug_dump(int client){
    char out[8192];
    int off = 0;

    // stack / heap / function addresses
    int stack_local = 1;
    void *heap = malloc(16);

    off += snprintf(out + off,
        sizeof(out) - off,
        "[address]\n"
        " main              : %p\n"
        " debug_dump        : %p\n"
        " g_global (addr)   : %p\n"
        " g_global (value)  : %d\n"
        " stack_local       : %p\n"
        " heap(malloc(16))  : %p\n",
        (void*)&main, (void*)&debug_dump, (void*)&g_global, g_global, (void*)&stack_local, heap
    );

    // /proc/self/maps excerpt
    off += snprintf(out + off, sizeof(out) - off, "\n[maps]\n");
    {
        FILE *fp = fopen("/proc/self/maps", "r");
        if (fp){
            char line[256];
            int lines = 0;
            while (fgets(line, sizeof(line), fp) && lines < 40){
                off += snprintf(out + off, sizeof(out) - off, "%s", line);
                lines++;
                if (off > (int)sizeof(out) - 512) break;
            }
            fclose(fp);
        } else {
            off += snprintf(out + off, sizeof(out) - off, " cannot read /proc/self/maps\n");
        }
    }
    free(heap);
    send_text(client, out);
}

__attribute__((noinline))
static void smash(int len) {
    volatile char buf[64];

    memset((void*)buf, 'A', (size_t)len);
}

static void canary_dump(int client){
    char out[8182];
    int off = 0;

    off += snprintf(out + off, sizeof(out) - off, "try: compare master canary and stack canary copy\n\n");
    canary(out, &off, sizeof(out));
    send_text(client, out);
}

__attribute__((noinline))
static void canary(char *out, int *off, size_t outsz){
    volatile char buf[64];
    memset((void*)buf, 'B', sizeof(buf));

    uintptr_t guard = __stack_chk_guard;

    *off += snprintf(out + *off, outsz - *off,
        "[canary]\n"
        "__stack_chk_guard (master) : 0x%016lx\n"
        " buf addr                 : %p\n",
        (unsigned long)guard, (void*)buf);

    uintptr_t *p = (uintptr_t *)((uintptr_t)buf + sizeof(buf));

    *off += snprintf(out + *off, outsz - *off,
        "\n[stack dump after buf]\n"
        " (dumping 8 words from buf+64)\n");
    for (int i = 0; i < 8; i++){
        uintptr_t v = p[i];
        *off += snprintf(out + *off, outsz - *off,
            "  *(buf+64+%2d*8) @ %p : 0x%016lx%s\n",
        i, (void*)&p[i], (unsigned long)v, (v == guard) ? " <=MATCH" : "");
        if(*off > (int)outsz - 256) break;
    }
}

int main(void){
    int ret;
    int sock = socket(AF_INET, SOCK_STREAM, 0);

    if (sock < 0){
        perror("scoket");
        exit(1);
    }
    int yes = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));

    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(8080);
    addr.sin_addr.s_addr = INADDR_ANY;

    ret = bind(sock, (struct sockaddr*)&addr, sizeof(addr));
    if (ret < 0){
        perror("bind");
        exit(1);
    }
    listen(sock, 5);
    printf("Listening on :8080\n");

    while (1) {
        int client = accept(sock, NULL, NULL);
        if (client < 0) continue;

        char req[1024];
        int n = read(client, req, sizeof(req) - 1);
        if (n <= 0){
            close(client);
            continue;
        }
        req[n] = '\0';

        if (!strncmp(req, "GET /debug", 10)) {
            debug_dump(client);
        }else if(!strncmp(req, "GET /smash", 10)){
            int len = 80; // default.BoF will cause
            char *p = strstr(req, "len=");
            if (p){
                len = atoi(p + 4);
            }
            smash(len);
            send_text(client, "smash done\n");
        }else if(!strncmp(req, "GET /canary", 11)){
            canary_dump(client);
        }else {
            send_text(client, "vuln server alive\ntry: GET /debug or /smash\n");
        }
        close(client);
    }
}