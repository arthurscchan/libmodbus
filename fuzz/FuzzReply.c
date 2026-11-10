#define _GNU_SOURCE
/* Fuzzer for the Modbus response builder (modbus_reply/modbus_reply_exception).
 *
 * Threat model:
 * - modbus_reply() parses request ADUs arriving from untrusted Modbus TCP
 *   clients, validates function/address/quantity fields against the server
 *   mapping, reads and writes the process mapping, and builds responses.
 *   FuzzServer only reaches this through a one-shot loopback socket; here
 *   the request ADU is driven directly, so every function-code branch,
 *   address/quantity validation path and exception route is reachable
 *   without any networking.
 * - A real finding is a memory-safety violation while parsing a
 *   length-consistent request ADU, an out-of-bounds mapping access for
 *   in-range-but-unmapped quantities, or a response-length defect.
 *
 * Harness contract (legitimate input): the input is the request ADU exactly
 * as a client sends it over TCP (7-byte MBAP header + PDU), passed with its
 * true length — the same (buffer, length) consistency modbus_receive()
 * guarantees to real callers. modbus_reply() length-checks every branch
 * before reading; a matching mapping of 64 objects backs the requests.
 * Both objects are freed every iteration.
 */
#include <modbus.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define FZ_MIN_INPUT 8u
#define FZ_MAX_INPUT 260u

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size < FZ_MIN_INPUT || size > FZ_MAX_INPUT) {
        return 0;
    }

    modbus_t *ctx = modbus_new_tcp("127.0.0.1", 15020);
    if (ctx == NULL) {
        return 0;
    }
    modbus_mapping_t *map = modbus_mapping_new(64, 64, 64, 64);
    if (map == NULL) {
        modbus_free(ctx);
        return 0;
    }

    uint8_t *req = malloc(size);
    if (req == NULL) {
        modbus_mapping_free(map);
        modbus_free(ctx);
        return 0;
    }
    memcpy(req, data, size);

    (void) modbus_reply(ctx, req, (int) size, map);
    (void) modbus_reply_exception(ctx, req, (unsigned int) (data[0] % 11u));

    free(req);
    modbus_mapping_free(map);
    modbus_free(ctx);
    return 0;
}
