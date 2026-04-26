#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

static uint32_t rotl32(uint32_t x, unsigned int r) {
    return (x << r) | (x >> (32 - r));
}

static uint32_t mix_name(const char *s) {
    uint32_t h = 0x9E3779B9u;
    int i = 0;
    while (s[i] != '\0') {
        uint8_t c = (uint8_t)s[i];
        h ^= (uint32_t)(c + (i * 17));
        h = rotl32(h, 5);
        h += 0x6D2B79F5u ^ (uint32_t)(i * 0x45D9F3Bu);
        i++;
    }
    return h ^ (h >> 16);
}

static uint32_t fold_serial(const char *serial) {
    uint32_t acc = 0x13572468u;
    for (int i = 0; serial[i] != '\0'; i++) {
        char ch = serial[i];
        if (ch == '-') continue;
        if (ch >= '0' && ch <= '9') {
            acc = rotl32(acc ^ (uint32_t)(ch - '0'), 3) + 0x11111111u;
        } else if (ch >= 'A' && ch <= 'F') {
            acc = rotl32(acc + (uint32_t)(10 + ch - 'A'), 7) ^ 0xA5A5A5A5u;
        } else {
            return 0xFFFFFFFFu;
        }
    }
    return acc;
}

static int parse_parts(const char *serial, uint32_t out[4]) {
    if (strlen(serial) != 19) return 0;
    if (serial[4] != '-' || serial[9] != '-' || serial[14] != '-') return 0;
    for (int p = 0; p < 4; p++) {
        char tmp[5];
        memcpy(tmp, serial + p * 5, 4);
        tmp[4] = '\0';
        char *end = NULL;
        unsigned long v = strtoul(tmp, &end, 16);
        if (end == NULL || *end != '\0' || v > 0xFFFFul) return 0;
        out[p] = (uint32_t)v;
    }
    return 1;
}

static int check_serial(const char *name, const char *serial) {
    uint32_t parts[4] = {0,0,0,0};
    if (strlen(name) < 4) return 0;
    if (!parse_parts(serial, parts)) return 0;

    uint32_t h = mix_name(name);
    uint32_t f = fold_serial(serial);

    uint32_t c0 = ((h >>  0) ^ 0x4A31u) & 0xFFFFu;
    uint32_t c1 = ((h >>  8) + 0x1337u) & 0xFFFFu;
    uint32_t c2 = (((h >> 16) ^ (parts[0] << 1)) + 0x2222u) & 0xFFFFu;
    uint32_t c3 = ((parts[0] + parts[1] + c2) ^ 0xBEEFu) & 0xFFFFu;

    if (parts[0] != c0) return 0;
    if (parts[1] != c1) return 0;
    if (parts[2] != c2) return 0;
    if (parts[3] != c3) return 0;
    if (((f ^ h) & 0xFFu) != 0x5Au) return 0;
    return 1;
}

int main(int argc, char **argv) {
    if (argc != 3) {
        puts("usage: lab3 <name> <serial>");
        return 2;
    }
    if (check_serial(argv[1], argv[2])) {
        puts("ACCESS GRANTED");
        return 0;
    }
    puts("ACCESS DENIED");
    return 1;
}
