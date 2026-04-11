/* wolfP11
 * Copyright (C) 2026 wolfSSL Inc.
 *
 * This file is part of wolfP11.
 *
 * wolfP11 is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * wolfP11 is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 *
 * For a commercial license, contact wolfSSL Inc. at licensing@wolfssl.com.
 */

/* wp11_ccid.c -- wolfP11 CCID transport over libusb bulk transfers
 *
 * Frames ISO 7816 APDUs in CCID PC_to_RDR_XfrBlock messages and parses
 * the RDR_to_PC_DataBlock responses.  An injectable mock transport allows
 * unit tests to run without hardware.
 */

#include "wolfp11/wp11_ccid.h"

#include <stdlib.h>
#include <string.h>

#ifdef WOLFP11_CFG_USB_BACKEND
#include <libusb-1.0/libusb.h>
#endif

/* USB class code for CCID/smartcard readers (USB spec, bInterfaceClass) */
#define WP11_USB_CLASS_CCID    0x0Bu
/* USB endpoint address bit 7: 1 = IN (device->host), 0 = OUT (host->device) */
#define WP11_USB_EP_DIR_IN     0x80u

/* -------------------------------------------------------------------------
 * CCID message type bytes
 * ---------------------------------------------------------------------- */

#define CCID_MSG_PC_TO_RDR_XFRBLOCK  0x6Fu
#define CCID_MSG_RDR_TO_PC_DATABLOCK 0x80u

/* CCID message header length (bytes before abData) */
#define CCID_HEADER_LEN 10

/* -------------------------------------------------------------------------
 * Context definition (opaque to callers)
 * ---------------------------------------------------------------------- */

struct wp11_ccid_ctx {
    int     is_mock;    /* 1 = mock transport, 0 = real USB */
    uint8_t seq;        /* incrementing sequence number      */
    int     desync;     /* 1 = CCID conversation desynchronized; must reconnect */

    /* real USB fields */
#ifdef WOLFP11_CFG_USB_BACKEND
    libusb_context       *usb_ctx;
    libusb_device_handle *usb_dev;
    unsigned char         ep_out;
    unsigned char         ep_in;
    int                   timeout_ms;
    int                   claimed_iface; /* interface index claimed; -1 if none */
#endif

    /* mock fields */
    wp11_ccid_transport_fn mock_fn;
    void                  *mock_userdata;
};

/* -------------------------------------------------------------------------
 * Internal helpers
 * ---------------------------------------------------------------------- */

/* Write a uint32 in little-endian order into dst[0..3]. */
static void put_u32le(uint8_t *dst, uint32_t v)
{
    dst[0] = (uint8_t)(v        & 0xFFu);
    dst[1] = (uint8_t)((v >>  8) & 0xFFu);
    dst[2] = (uint8_t)((v >> 16) & 0xFFu);
    dst[3] = (uint8_t)((v >> 24) & 0xFFu);
}

/* Read a uint32 from little-endian bytes src[0..3]. */
static uint32_t get_u32le(const uint8_t *src)
{
    return ((uint32_t)src[0])
         | ((uint32_t)src[1] <<  8)
         | ((uint32_t)src[2] << 16)
         | ((uint32_t)src[3] << 24);
}

/* -------------------------------------------------------------------------
 * wp11_ccid_open
 * ---------------------------------------------------------------------- */

int wp11_ccid_open(uint16_t vid, uint16_t pid, wp11_ccid_ctx_t **ctx_out)
{
    if (ctx_out == NULL) {
        return WP11_CCID_ERR_PARAM;
    }

#ifdef WOLFP11_CFG_USB_BACKEND
    {
        wp11_ccid_ctx_t      *ctx = NULL;
        libusb_context       *usb_ctx = NULL;
        libusb_device_handle *usb_dev = NULL;
        libusb_device        *dev = NULL;
        libusb_device       **list = NULL;
        struct libusb_device_descriptor    dev_desc;
        struct libusb_config_descriptor   *cfg = NULL;
        const struct libusb_interface     *iface = NULL;
        const struct libusb_interface_descriptor *altsetting = NULL;
        const struct libusb_endpoint_descriptor  *ep = NULL;
        ssize_t  ndev, i;
        int      iface_num = -1;
        int      ret;
        unsigned char ep_in = 0, ep_out = 0;
        int      j, k;

        ret = libusb_init(&usb_ctx);
        if (ret != 0) {
            return WP11_CCID_ERR_USB;
        }

        ndev = libusb_get_device_list(usb_ctx, &list);
        if (ndev < 0) {
            libusb_exit(usb_ctx);
            return WP11_CCID_ERR_USB;
        }

        for (i = 0; i < ndev && dev == NULL; i++) {
            if (libusb_get_device_descriptor(list[i], &dev_desc) != 0) {
                continue;
            }
            if (dev_desc.idVendor == vid && dev_desc.idProduct == pid) {
                dev = list[i];
            }
        }

        if (dev == NULL) {
            libusb_free_device_list(list, 1);
            libusb_exit(usb_ctx);
            return WP11_CCID_ERR_NOTFOUND;
        }

        ret = libusb_open(dev, &usb_dev);
        libusb_free_device_list(list, 1);
        if (ret != 0) {
            libusb_exit(usb_ctx);
            return WP11_CCID_ERR_USB;
        }

        /* Find CCID class interface (bInterfaceClass == 0x0B) */
        if (libusb_get_active_config_descriptor(dev, &cfg) != 0) {
            libusb_close(usb_dev);
            libusb_exit(usb_ctx);
            return WP11_CCID_ERR_USB;
        }

        for (j = 0; j < (int)cfg->bNumInterfaces && iface_num < 0; j++) {
            iface = &cfg->interface[j];
            for (k = 0; k < iface->num_altsetting && iface_num < 0; k++) {
                altsetting = &iface->altsetting[k];
                if (altsetting->bInterfaceClass == WP11_USB_CLASS_CCID) {
                    int e;
                    iface_num = altsetting->bInterfaceNumber;
                    for (e = 0; e < (int)altsetting->bNumEndpoints; e++) {
                        ep = &altsetting->endpoint[e];
                        if ((ep->bEndpointAddress & WP11_USB_EP_DIR_IN) != 0u) {
                            ep_in  = ep->bEndpointAddress;
                        } else {
                            ep_out = ep->bEndpointAddress;
                        }
                    }
                }
            }
        }

        libusb_free_config_descriptor(cfg);

        /* USB bulk endpoints have non-zero addresses (0 is the control endpoint,
         * reserved by USB spec). Using 0 as "not found" sentinel is safe here. */
        if (iface_num < 0 || ep_in == 0 || ep_out == 0) {
            libusb_close(usb_dev);
            libusb_exit(usb_ctx);
            return WP11_CCID_ERR_NOTFOUND;
        }

        ret = libusb_claim_interface(usb_dev, iface_num);
        if (ret != 0) {
            libusb_close(usb_dev);
            libusb_exit(usb_ctx);
            return WP11_CCID_ERR_USB;
        }

        ctx = (wp11_ccid_ctx_t *)malloc(sizeof(*ctx));
        if (ctx == NULL) {
            libusb_release_interface(usb_dev, iface_num);
            libusb_close(usb_dev);
            libusb_exit(usb_ctx);
            return WP11_CCID_ERR_NOMEM;
        }

        memset(ctx, 0, sizeof(*ctx));
        ctx->is_mock       = 0;
        ctx->seq           = 0;
        ctx->usb_ctx       = usb_ctx;
        ctx->usb_dev       = usb_dev;
        ctx->ep_out        = ep_out;
        ctx->ep_in         = ep_in;
        ctx->timeout_ms    = 5000;
        ctx->claimed_iface = iface_num;

        *ctx_out = ctx;
        return WP11_CCID_OK;
    }
#else
    (void)vid;
    (void)pid;
    return WP11_CCID_ERR_NOTFOUND;
#endif /* WOLFP11_CFG_USB_BACKEND */
}

/* -------------------------------------------------------------------------
 * wp11_ccid_open_mock
 * ---------------------------------------------------------------------- */

int wp11_ccid_open_mock(wp11_ccid_transport_fn transport,
                        void                   *userdata,
                        wp11_ccid_ctx_t       **ctx_out)
{
    wp11_ccid_ctx_t *ctx;

    if (transport == NULL || ctx_out == NULL) {
        return WP11_CCID_ERR_PARAM;
    }

    ctx = (wp11_ccid_ctx_t *)malloc(sizeof(*ctx));
    if (ctx == NULL) {
        return WP11_CCID_ERR_NOMEM;
    }

    memset(ctx, 0, sizeof(*ctx));
    ctx->is_mock       = 1;
    ctx->seq           = 0;
    ctx->mock_fn       = transport;
    ctx->mock_userdata = userdata;
#ifdef WOLFP11_CFG_USB_BACKEND
    ctx->claimed_iface = -1; /* no USB interface claimed for mock transport */
#endif

    *ctx_out = ctx;
    return WP11_CCID_OK;
}

/* -------------------------------------------------------------------------
 * wp11_ccid_apdu
 * ---------------------------------------------------------------------- */

int wp11_ccid_apdu(wp11_ccid_ctx_t *ctx,
                   const uint8_t   *cmd,  size_t  cmdlen,
                   uint8_t         *resp, size_t *resplen)
{
    /* Working buffers: CCID header (10) + up to 512 bytes APDU payload.
     *
     * 522 bytes is sufficient because wolfP11 uses ISO 7816-4 short APDUs
     * with GET RESPONSE chaining (SW1=0x61) for responses longer than 256
     * bytes.  Extended-length APDUs (ISO 7816-4 section 5.1) are not issued;
     * each individual CCID frame therefore fits comfortably in 522 bytes.
     *
     * If extended APDUs are ever added, both buffers and the cmdlen guard
     * must be enlarged to match the new maximum frame size, or silent
     * truncation will occur: libusb clips the read at sizeof(frame_in), the
     * CCID header (first 10 bytes including seq) still validates, and the
     * caller receives a silently truncated APDU response. */
    uint8_t  frame_out[CCID_HEADER_LEN + 512];
    uint8_t  frame_in[CCID_HEADER_LEN + 512];
    size_t   frame_out_len;
    size_t   frame_in_len;
    uint8_t  seq_sent;
    uint32_t resp_dw_length;

    if (ctx == NULL || cmd == NULL || resp == NULL || resplen == NULL) {
        return WP11_CCID_ERR_PARAM;
    }
    if (cmdlen > 512u) {
        return WP11_CCID_ERR_PARAM;
    }
    if (ctx->desync) {
        /* A previous IN failure after a successful OUT desynchronized the
         * CCID conversation.  Per CCID spec r1.10 sec.6.1.6, an Abort command
         * or interface reset is required to resynchronize.  Fail until the
         * device context is closed and reopened. */
        return WP11_CCID_ERR_USB;
    }

    /* Build PC_to_RDR_XfrBlock frame */
    frame_out_len = CCID_HEADER_LEN + cmdlen;
    memset(frame_out, 0, frame_out_len);

    frame_out[0] = CCID_MSG_PC_TO_RDR_XFRBLOCK;  /* bMessageType */
    put_u32le(&frame_out[1], (uint32_t)cmdlen);   /* dwLength     */
    frame_out[5] = 0x00u;                          /* bSlot        */
    frame_out[6] = ctx->seq;                       /* bSeq         */
    frame_out[7] = 0x00u;                          /* bBWI         */
    frame_out[8] = 0x00u;                          /* wLevelParameter lo */
    frame_out[9] = 0x00u;                          /* wLevelParameter hi */
    memcpy(&frame_out[10], cmd, cmdlen);           /* abData       */

    seq_sent = ctx->seq;
    ctx->seq = (uint8_t)(ctx->seq + 1u);

    /* Dispatch */
    if (ctx->is_mock) {
        frame_in_len = sizeof(frame_in);
        if (ctx->mock_fn(ctx->mock_userdata,
                         frame_out, frame_out_len,
                         frame_in, &frame_in_len) != 0) {
            return WP11_CCID_ERR_USB;
        }
    }
#ifdef WOLFP11_CFG_USB_BACKEND
    else {
        int transferred = 0;
        int ret;

        ret = libusb_bulk_transfer(ctx->usb_dev, ctx->ep_out,
                                   frame_out, (int)frame_out_len,
                                   &transferred, ctx->timeout_ms);
        if (ret != 0) {
            /* Failed OUT: nothing was sent, CCID conversation stays in sync. */
            if (ret == LIBUSB_ERROR_NO_DEVICE) return WP11_CCID_ERR_NO_CARD;
            if (ret == LIBUSB_ERROR_TIMEOUT)   return WP11_CCID_ERR_TIMEOUT;
            if (ret == LIBUSB_ERROR_PIPE) {
                (void)libusb_clear_halt(ctx->usb_dev, ctx->ep_out);
                return WP11_CCID_ERR_USB;
            }
            return WP11_CCID_ERR_USB;
        }

        transferred = 0;
        ret = libusb_bulk_transfer(ctx->usb_dev, ctx->ep_in,
                                   frame_in, (int)sizeof(frame_in),
                                   &transferred, ctx->timeout_ms);
        if (ret != 0) {
            /* OUT succeeded -- device processed the command and is waiting to
             * send its response.  CCID conversation is now desynchronized.
             * LIBUSB_ERROR_TIMEOUT is not device removal -- RSA-2048 sign on
             * slow tokens can take >2s.  Do NOT conflate these two errors. */
            /* wolfP11-xwqv: desync is permanent -- never cleared.  An OUT
             * that succeeded followed by a failed IN means the device has
             * processed our command and is waiting to send a response we
             * can no longer receive.  The CCID sequence counters are now
             * out of step and there is no safe in-band recovery; the
             * caller must close and reopen the device to resynchronize.
             * Attempting to send another command on this context would
             * deliver our OUT before reading the pending IN, which some
             * devices interpret as a protocol error or reset. */
            ctx->desync = 1;
            if (ret == LIBUSB_ERROR_NO_DEVICE) return WP11_CCID_ERR_NO_CARD;
            if (ret == LIBUSB_ERROR_TIMEOUT)   return WP11_CCID_ERR_TIMEOUT;
            if (ret == LIBUSB_ERROR_PIPE) {
                (void)libusb_clear_halt(ctx->usb_dev, ctx->ep_in);
                return WP11_CCID_ERR_USB;
            }
            return WP11_CCID_ERR_USB;
        }
        frame_in_len = (size_t)transferred;
    }
#endif

    /* Validate response frame */
    if (frame_in_len < CCID_HEADER_LEN) {
        return WP11_CCID_ERR_USB;
    }
    if (frame_in[0] != CCID_MSG_RDR_TO_PC_DATABLOCK) {
        return WP11_CCID_ERR_USB;
    }
    if (frame_in[6] != seq_sent) {
        return WP11_CCID_ERR_SEQ;
    }
    /* Inspect CCID bStatus byte (frame_in[7]) per CCID spec r1.10 Table 6.1.3:
     * bits 0-1: bmICCStatus (0=active, 1=inactive, 2=no ICC, 3=reserved)
     * bits 6-7: bmCommandStatus (0=no error, 1=failed, 2=time extension) */
    {
        uint8_t icc_status = frame_in[7] & 0x03u;
        uint8_t cmd_status = (frame_in[7] >> 6) & 0x03u;
        if (icc_status == 1u || icc_status == 2u) {
            /* Token inactive or absent -- caller should trigger slot removal */
            return WP11_CCID_ERR_NO_CARD;
        }
        if (cmd_status != 0u) {
            /* bmCommandStatus=1: reader error.
             * bmCommandStatus=2: time extension request -- a retry loop is
             * required (CCID spec sec.6.1.5) but not yet implemented; treat as
             * error so callers see a clear failure rather than stale data. */
            return WP11_CCID_ERR_STATUS;
        }
    }

    resp_dw_length = get_u32le(&frame_in[1]);

    if (resp_dw_length > *resplen) {
        return WP11_CCID_ERR_BUFSIZE;
    }
    /* wolfP11-zeh: resp_dw_length is uint32_t read from untrusted card data.
     * On 32-bit targets (SIZE_MAX = 0xFFFFFFFF), adding CCID_HEADER_LEN to a
     * value near UINT32_MAX wraps to a small number, making the bounds check
     * pass when the card has sent a malformed oversized length field.  Check
     * for overflow before the addition. */
    if (resp_dw_length > (uint32_t)(SIZE_MAX - CCID_HEADER_LEN) ||
        frame_in_len < CCID_HEADER_LEN + (size_t)resp_dw_length) {
        return WP11_CCID_ERR_USB;
    }

    memcpy(resp, &frame_in[CCID_HEADER_LEN], resp_dw_length);
    *resplen = resp_dw_length;

    return WP11_CCID_OK;
}

/* -------------------------------------------------------------------------
 * wp11_ccid_close
 * ---------------------------------------------------------------------- */

void wp11_ccid_close(wp11_ccid_ctx_t *ctx)
{
    if (ctx == NULL) {
        return;
    }

#ifdef WOLFP11_CFG_USB_BACKEND
    if (!ctx->is_mock) {
        if (ctx->usb_dev != NULL) {
            /* Release the specific interface we claimed -- not hardcoded 0.
             * CCID interface may be at any index, not necessarily 0. */
            if (ctx->claimed_iface >= 0) {
                libusb_release_interface(ctx->usb_dev, ctx->claimed_iface);
            }
            libusb_close(ctx->usb_dev);
        }
        if (ctx->usb_ctx != NULL) {
            libusb_exit(ctx->usb_ctx);
        }
    }
#endif

    free(ctx);
}
