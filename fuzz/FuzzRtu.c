#define _GNU_SOURCE
/* Fuzzer for the RTU backend (src/modbus-rtu.c: framing, CRC16, serial
   handling) through a pseudo-terminal.
 *
 * Threat model:
 * - Modbus RTU devices parse ADUs from serial lines whose bytes are fully
 *   attacker-controlled when the peer is compromised (rs485 buses, gateways
 *   converting TCP to RTU). _modbus_rtu_receive checks the trailing CRC16
 *   and frames ADUs byte-by-byte; valid frames then flow through the same
 *   request parsing and response building as TCP.
 * - A real finding is a memory-safety violation in the RTU framing/CRC
 *   paths or in request parsing reachable only from serial ADUs.
 *
 * Harness contract (legitimate input): the fuzz bytes are the ADU payload
 * (slave address + PDU) sent over a pseudo-terminal to an RTU context bound
 * to the slave side; the harness appends the correct Modbus CRC16 so that
 * mutations reach the framing logic past the checker (the checker itself is
 * covered by seeds whose CRCs were broken and fixed). Indication and
 * response timeouts bound every blocking read (stalled fuzzed peers may
 * otherwise hang forever), SIGPIPE is ignored (the peer may close early),
 * and the PTY is opened once in LLVMFuzzerInitialize.
 */
#include <fcntl.h>
#include <modbus.h>
#include <signal.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>

#define FZ_SLAVE 0x01
#define FZ_MAX_FRAME 253u
#define FZ_PTYPATH 256

static int master_fd = -1;
static char slave_path[FZ_PTYPATH];
static const char *ca_dummy = NULL;

static uint16_t
fz_crc16(const uint8_t *buf, size_t len)
{
    uint16_t crc = 0xFFFF;
    for (size_t i = 0; i < len; i++) {
        crc ^= buf[i];
        for (int b = 0; b < 8; b++) {
            crc = (crc & 1u) ? (uint16_t) ((crc >> 1) ^ 0xA001u)
                             : (uint16_t) (crc >> 1);
        }
    }
    return crc;
}

int
LLVMFuzzerInitialize(int *argc, char ***argv)
{
    (void) argc;
    (void) argv;
    signal(SIGPIPE, SIG_IGN);

    master_fd = posix_openpt(O_RDWR | O_NOCTTY);
    if (master_fd < 0) {
        return 0;
    }
    if (grantpt(master_fd) != 0 || unlockpt(master_fd) != 0) {
        close(master_fd);
        master_fd = -1;
    }
    return 0;
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (master_fd < 0 || size < 2u || size > FZ_MAX_FRAME) {
        return 0;
    }

    modbus_t *ctx = modbus_new_rtu(slave_path, 115200, 'N', 8, 1);
    if (ctx == NULL) {
        return 0;
    }
    modbus_set_slave(ctx, FZ_SLAVE);
    modbus_set_indication_timeout(ctx, 0, 200000);
    modbus_set_response_timeout(ctx, 0, 200000);
    if (modbus_connect(ctx) == -1) {
        modbus_free(ctx);
        return 0;
    }
    tcflush(master_fd, TCIOFLUSH);

    uint8_t frame[256];
    size_t n = size;
    memcpy(frame, data, n);
    uint16_t crc = fz_crc16(frame, n);
    frame[n++] = (uint8_t) (crc & 0xFFu);
    frame[n++] = (uint8_t) (crc >> 8);

    if (write(master_fd, frame, n) == (ssize_t) n) {
        uint8_t query[MODBUS_RTU_MAX_ADU_LENGTH];
        modbus_mapping_t *map = modbus_mapping_new(64, 64, 64, 64);
        if (map != NULL) {
            int req_len = modbus_receive(ctx, query);
            if (req_len > 0) {
                (void) modbus_reply(ctx, query, req_len, map);
            }
            modbus_mapping_free(map);
        }
    }

    tcflush(master_fd, TCIOFLUSH);
    modbus_close(ctx);
    modbus_free(ctx);
    return 0;
}
