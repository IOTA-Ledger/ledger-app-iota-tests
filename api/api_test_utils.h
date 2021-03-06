#ifndef API_TEST_UTILS_H
#define API_TEST_UTILS_H

#include <string.h>
#include "test_common.h"
#include "iota/seed.h"
#include "api.h"

#define BIP32_PATH_LENGTH 5
#define BIP32_PATH                                                             \
    {                                                                          \
        0x8000002C, 0x8000107A, 0x80000000, 0x00000001, 0x00000001             \
    }

#define EXPECT_API_OK_ANY_OUTPUT(INS, p1, input)                               \
    ({                                                                         \
        expect_any(io_send, ptr);                                              \
        expect_any(io_send, length);                                           \
        expect_value(io_send, sw, 0x9000);                                     \
        api_##INS(p1, (unsigned char *)&(input), sizeof(input));               \
    })

#define EXPECT_API_OK(INS, p1, input)                                          \
    ({                                                                         \
        expect_value(io_send, ptr, NULL);                                      \
        expect_value(io_send, length, 0);                                      \
        expect_value(io_send, sw, 0x9000);                                     \
        api_##INS(p1, (unsigned char *)&(input), sizeof(input));               \
    })

#define EXPECT_API_DATA_OK(INS, p1, input, output)                             \
    ({                                                                         \
        expect_memory(io_send, ptr, &(output), sizeof(output));                \
        expect_value(io_send, length, sizeof(output));                         \
        expect_value(io_send, sw, 0x9000);                                     \
        api_##INS(p1, (unsigned char *)&(input), sizeof(input));               \
    })

#define EXPECT_API_EXCEPTION(INS, p1, input)                                   \
    ({                                                                         \
        expect_assert_failure(                                                 \
            api_##INS(p1, (unsigned char *)&(input), sizeof(input)));          \
    })

// Create struct with a fixed path length
typedef IO_STRUCT SET_SEED_FIXED_INPUT
{
    uint8_t security;
    uint32_t bip32_path_length;
    uint32_t bip32_path[BIP32_PATH_LENGTH];
}
SET_SEED_FIXED_INPUT;

// Pubkey input struct with seed input
typedef IO_STRUCT SET_SEED_PUBKEY_INPUT
{
    SET_SEED_FIXED_INPUT set_seed;
    PUBKEY_INPUT pubkey;
}
SET_SEED_PUBKEY_INPUT;

// Tx input struct with seed input
typedef IO_STRUCT SET_SEED_TX_INPUT
{
    SET_SEED_FIXED_INPUT set_seed;
    TX_INPUT tx;
}
SET_SEED_TX_INPUT;

static inline void SET_SEED_IN_INPUT(const char *seed, int security,
                                     void *input)
{
    const SET_SEED_FIXED_INPUT seed_input = {security, BIP32_PATH_LENGTH,
                                             BIP32_PATH};

    expect_memory(seed_derive_from_bip32, path, seed_input.bip32_path,
                  sizeof(seed_input.bip32_path));
    expect_value(seed_derive_from_bip32, pathLength,
                 seed_input.bip32_path_length);

    will_return(seed_derive_from_bip32,
                cast_ptr_to_largest_integral_type(seed));

    memcpy(input, &seed_input, sizeof(seed_input));
}

static inline void EXPECT_API_SET_BUNDLE_OK(const char *seed, int security,
                                            const TX_INPUT *tx, int last_index,
                                            const char *bundle_hash)
{
    {
        SET_SEED_TX_INPUT input;
        SET_SEED_IN_INPUT(seed, security, &input);
        memcpy(&input.tx, &tx[0], sizeof(TX_INPUT));

        TX_OUTPUT output = {};
        output.finalized = false;

        EXPECT_API_DATA_OK(tx, P1_FIRST, input, output);
    }

    for (int i = 1; i < last_index; i++) {
        TX_OUTPUT output = {};
        output.finalized = false;

        EXPECT_API_DATA_OK(tx, P1_MORE, tx[i], output);
    }

    {
        TX_OUTPUT output = {};
        strncpy(output.bundle_hash, bundle_hash, 81);
        output.finalized = true;

        EXPECT_API_DATA_OK(tx, P1_MORE, tx[last_index], output);
    }
}

#endif // API_TEST_UTILS_H
