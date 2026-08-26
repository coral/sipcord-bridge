/*
 * Compile-time capacity settings for pjproject.
 *
 * Change SIPCORD_MAX_CLIENTS to move the whole capacity tier. It must remain
 * a power of two so the derived transport-manager hash size is 2^n - 1.
 */
#ifndef SIPCORD_PJPROJECT_CONFIG_H
#define SIPCORD_PJPROJECT_CONFIG_H

#ifndef SIPCORD_MAX_CLIENTS
#define SIPCORD_MAX_CLIENTS 1024
#endif

#if SIPCORD_MAX_CLIENTS < 8
#error "SIPCORD_MAX_CLIENTS must be at least 8"
#endif

#if (SIPCORD_MAX_CLIENTS & (SIPCORD_MAX_CLIENTS - 1)) != 0
#error "SIPCORD_MAX_CLIENTS must be a power of two"
#endif

/* One call slot per eight registered clients: 1024 clients => 128 calls. */
#define PJSUA_MAX_CALLS (SIPCORD_MAX_CLIENTS / 8)

/* One transport/ioqueue tier, with the hash size required to be 2^n - 1. */
#define PJ_IOQUEUE_MAX_HANDLES SIPCORD_MAX_CLIENTS
#define PJSIP_MAX_TRANSPORTS SIPCORD_MAX_CLIENTS
#define PJSIP_TPMGR_HTABLE_SIZE (SIPCORD_MAX_CLIENTS - 1)

/* Allow a burst of one quarter of the configured client tier. */
#define PJSIP_TCP_TRANSPORT_BACKLOG (SIPCORD_MAX_CLIENTS / 4)
#define PJSIP_TLS_TRANSPORT_BACKLOG (SIPCORD_MAX_CLIENTS / 4)

#endif /* SIPCORD_PJPROJECT_CONFIG_H */
