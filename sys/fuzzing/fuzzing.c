/*
 * SPDX-FileCopyrightText: 2019 Sören Tempel <tempel@uni-bremen.de>
 * SPDX-FileCopyrightText: 2022 Bennet Blischke <bennet.blischke@haw-hamburg.de>
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>

#include "assert.h"
#include "fuzzing.h"

#include "net/ipv6/addr.h"
#include "net/gnrc/netif.h"
#include "net/gnrc/pktbuf.h"
#include "net/gnrc/pkt.h"

extern int fuzzing_netdev(gnrc_netif_t *);
extern void fuzzing_netdev_wait(void);

/* buffer sizes for reading from an fd */
#define FUZZING_BSIZE 1024
#define FUZZING_BSTEP 128

/* used by gnrc_pktbuf_malloc to exit on free */
gnrc_pktsnip_t *gnrc_pktbuf_fuzzptr = NULL;

int
fuzzing_init(ipv6_addr_t *addr, unsigned pfx_len)
{
    static gnrc_netif_t netif;

    if (fuzzing_netdev(&netif)) {
        return -ENXIO;
    }

    fuzzing_netdev_wait();
    if (addr != NULL) {
        if (gnrc_netif_ipv6_addr_add(&netif, addr, pfx_len, 0) != sizeof(ipv6_addr_t)) {
            return -EINVAL;
        }
    }

    return 0;
}

int
fuzzing_read_packet(int fd, gnrc_pktsnip_t *pkt)
{
    size_t rsiz;

    /* can only be called once currently */
    assert(gnrc_pktbuf_fuzzptr == NULL);

    uint8_t *input = fuzzing_read_bytes(fd, &rsiz);
    if (input == NULL) {
        return -errno;
    }

    if (gnrc_pktbuf_realloc_data(pkt, rsiz)) {
        free(input);
        return -ENOMEM;
    }

    memcpy(pkt->data, input, rsiz);
    free(input);

    gnrc_pktbuf_fuzzptr = pkt;
    return 0;
}

uint8_t *
fuzzing_read_bytes(int fd, size_t *size)
{
    uint8_t *buffer = NULL;
    uint8_t *tmp;
    ssize_t r;
    size_t csiz, rsiz;

    csiz = 0;
    rsiz = FUZZING_BSIZE;
    if ((buffer = realloc(buffer, rsiz)) == NULL) {
        return NULL;
    }

    while ((r = read(fd, &(buffer[csiz]), rsiz)) > 0) {
        assert((size_t)r <= rsiz);

        csiz += r;
        rsiz -= r;

        if (rsiz == 0) {
            tmp = realloc(buffer, csiz + FUZZING_BSTEP);
            if (tmp == NULL) {
                int err = errno;
                free(buffer);
                errno = err;
                return NULL;
            }
            buffer = tmp;
            rsiz += FUZZING_BSTEP;
        }
    }
    if (r == -1) {
        int err = errno;
        free(buffer);
        errno = err;
        return NULL;
    }

    /* shrink buffer to actual size */
    if (csiz > 0) {
        tmp = realloc(buffer, csiz);
        if (tmp == NULL) {
            int err = errno;
            free(buffer);
            errno = err;
            return NULL;
        }
        buffer = tmp;
    }

    *size = csiz;
    return buffer;
}
