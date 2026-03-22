/* Provides randombytes_internal_void_voidstar_longlong required by libmceliece.
 * Uses getrandom(2) (Linux ≥ 3.17) for cryptographic randomness.
 */
#include <sys/random.h>
#include <errno.h>

void randombytes_internal_void_voidstar_longlong(void *buf, long long len) {
    unsigned char *p = (unsigned char *)buf;
    long long remaining = len;
    while (remaining > 0) {
        ssize_t got = getrandom(p, (size_t)remaining, 0);
        if (got < 0) {
            if (errno == EINTR) continue;
            /* unrecoverable error — abort */
            __builtin_trap();
        }
        p += got;
        remaining -= got;
    }
}
