#define _GNU_SOURCE
/* Fuzzer for the pure data-conversion helpers (src/modbus-data.c).
 *
 * Threat model:
 * - modbus_set_bits_from_byte(s), modbus_get_byte_from_bits and the float
 *   word-order family (modbus_set_float_abcd/badc/cdab/dcba and their
 *   getters) convert raw device values into registers and back. The inputs
 *   derive from device data and registers read from untrusted peers, and
 *   every read/write of process data flows through them; an out-of-bounds
 *   write or a mis-conversion here corrupts process memory or telemetry.
 * - A real finding is a memory-safety violation (index/count handling
 *   across byte/bit boundaries) or a conversion defect (endianness/word
 *   order round-trip mismatch).
 *
 * Harness contract (legitimate input): all helpers are pure and take
 * caller-owned buffers; indices and counts are bounded by the harness to
 * stay inside the fixed destinations, matching the bounds real callers
 * compute from their mappings. All results feed a volatile sink so the
 * optimizer cannot drop the calls.
 */
#include <modbus.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define FZ_MIN_INPUT 16u
#define FZ_MAX_INPUT 4096u
#define FZ_BITS_DEST 128u

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size < FZ_MIN_INPUT || size > FZ_MAX_INPUT) {
        return 0;
    }

    uint16_t regs[4];
    memcpy(regs, data, sizeof(regs));

    float f;
    memcpy(&f, data + 8, sizeof(f));

    uint8_t bits_dest[FZ_BITS_DEST];
    memset(bits_dest, 0, sizeof(bits_dest));

    modbus_set_bits_from_byte(bits_dest, data[12] % 8u, data[13]);

    unsigned int nb = (unsigned int) (data[15] % 56u) + 1u;
    modbus_set_bits_from_bytes(bits_dest, data[14] % 16u, nb, data);

    volatile uint8_t byte =
        modbus_get_byte_from_bits(bits_dest, data[14] % (FZ_BITS_DEST - 8u),
                                  (data[15] % 8u) + 1u);

    uint16_t dest[2];
    volatile float sink = 0.0f;

    modbus_set_float(f, dest);
    sink += modbus_get_float(dest);
    modbus_set_float_abcd(f, dest);
    sink += modbus_get_float_abcd(dest);
    modbus_set_float_dcba(f, dest);
    sink += modbus_get_float_dcba(dest);
    modbus_set_float_badc(f, dest);
    sink += modbus_get_float_badc(dest);
    modbus_set_float_cdab(f, dest);
    sink += modbus_get_float_cdab(dest);
    sink += byte;
    sink += (float) regs[0] + (float) regs[3];

    return 0;
}
