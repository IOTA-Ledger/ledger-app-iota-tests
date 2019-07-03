#include <stdint.h>
#include "test_common.h"
#include "os.h"
#include "iota/conversion.h"
#include "iota/iota_types.h"
#include "test_vectors.h"
// include the c-file to be able to test static functions
#include "bundle_test_utils.c"

static void create_bundle_from_input(const TX_INPUT *input,
                                     BUNDLE_CTX *bundle_ctx)
{
    const unsigned int num_txs = input[0].last_index + 1;
    TX_ENTRY txs[num_txs];

    for (unsigned int i = 0; i < num_txs; i++) {
        strncpy(txs[i].address, input[i].address, NUM_HASH_TRYTES);
        rpad_chars(txs[i].tag, input[i].tag, NUM_TAG_TRYTES);

        txs[i].timestamp = input[i].timestamp;
        txs[i].value = input[i].value;
    }

    bundle_create(txs, num_txs, bundle_ctx);

    // copy the indices
    for (unsigned int i = 0; i < num_txs; i++) {
        bundle_ctx->bundle.indices[i] = input[i].address_idx;
    }
}

static void test_increment_tag(void **state)
{
    UNUSED(state);

    const int64_t value = -1;
    const uint32_t timestamp = 0;
    const uint32_t current_index = 0;
    const uint32_t last_index = 1;
    char tag[] = "999999999999999999999999999";

    unsigned char bytes[NUM_HASH_BYTES];
    create_bundle_bytes(value, tag, timestamp, current_index, last_index,
                        bytes);
    bytes_increment_trit_area_81(bytes);

    // incrementing the 82nd trit should be equivalent to incrementing the tag
    tag[0] = 'A';

    unsigned char exp_bytes[NUM_HASH_BYTES];
    create_bundle_bytes(value, tag, timestamp, current_index, last_index,
                        exp_bytes);

    assert_memory_equal(bytes, exp_bytes, NUM_HASH_BYTES);
}

static void test_normalize_hash(void **state)
{
    UNUSED(state);

    tryte_t hash_trytes[NUM_HASH_TRYTES] = {0};

    // test_hash is randomly generated using KeePass. Not an actual hash (but
    // shoudln't matter).
    char test_hash[] = "IGSCBIJOFWHFLSXJV9ZENNTNWTEWGFMZKT9UBWRHVOJRLULQELXWS9Z"
                       "HPGVBUTAVMCPHIMRWSHWMSYAKP";
    chars_to_trytes(test_hash, hash_trytes, NUM_HASH_TRYTES);
    normalize_hash(hash_trytes);

    // exp_trytes is taken directly from iota.lib.js
    tryte_t exp_trytes[NUM_HASH_TRYTES] = {
        13,  9,  -8, 3,  2,  9,   10,  -12, 6,  -4,  8,   6,  12, -8,
        -3,  10, -5, 0,  -1, 5,   -13, -13, -7, -13, -4,  -7, 5,  -13,
        6,   6,  13, -1, 11, -7,  0,   -6,  2,  -4,  -9,  8,  -5, -12,
        10,  -9, 12, -6, 12, -10, 5,   12,  -3, -4,  -8,  0,  -6, 8,
        -11, 7,  -5, 2,  -6, -7,  1,   -5,  13, 3,   -11, 8,  9,  13,
        -9,  -4, -8, 8,  -4, 13,  -8,  -2,  1,  11,  -11};
    assert_memory_equal(hash_trytes, exp_trytes, NUM_HASH_TRYTES);
}

static void test_normalize_hash_zero(void **state)
{
    UNUSED(state);

    tryte_t hash_trytes[NUM_HASH_TRYTES] = {0};
    normalize_hash(hash_trytes);

    // all zero hash is already normalized
    static const tryte_t exp_trytes[NUM_HASH_TRYTES] = {0};
    assert_memory_equal(hash_trytes, exp_trytes, NUM_HASH_TRYTES);
}

static void test_normalize_hash_one(void **state)
{
    UNUSED(state);

    tryte_t hash_trytes[NUM_HASH_TRYTES] = {TRYTE_MAX, TRYTE_MAX};
    normalize_hash(hash_trytes);

    // in the normalized hash the first tryte will be reduced to lowest value
    static const tryte_t exp_trytes[NUM_HASH_TRYTES] = {TRYTE_MIN, TRYTE_MAX};
    assert_memory_equal(hash_trytes, exp_trytes, NUM_HASH_TRYTES);
}

static void test_normalize_hash_neg_one(void **state)
{
    UNUSED(state);

    tryte_t hash_trytes[NUM_HASH_TRYTES] = {TRYTE_MIN, TRYTE_MIN};
    normalize_hash(hash_trytes);

    // in the normalized hash the first tryte will be reduced to highest value
    static const tryte_t exp_trytes[NUM_HASH_TRYTES] = {TRYTE_MAX, TRYTE_MIN};
    assert_memory_equal(hash_trytes, exp_trytes, NUM_HASH_TRYTES);
}

static void test_empty_bundle(void **state)
{
    UNUSED(state);

    BUNDLE_CTX bundle_ctx;
    expect_assert_failure(bundle_create(NULL, 0, &bundle_ctx));
}

static void test_one_tx_bundle(void **state)
{
    UNUSED(state);

    const TX_ENTRY txs[] = {
        {"LHWIEGUADQXNMRKQSBDJOAFMBIFKHHZXYEFOU9WFRMBGODSNJAPGFHOUOSGDICSFVA9K"
         "OUPPCMLAHPHAW",
         10, "999999999999999999999999999", 0}};

    BUNDLE_CTX bundle_ctx;
    expect_assert_failure(bundle_create(txs, ARRAY_SIZE(txs), &bundle_ctx));
}

static void test_bundle_is_input_tx(void **state)
{
    UNUSED(state);

    BUNDLE_CTX bundle_ctx;
    create_bundle_from_input(PETER_VECTOR.bundle, &bundle_ctx);

    // output transaction
    assert_false(bundle_is_input_tx(&bundle_ctx, 0));
    // input transaction
    assert_true(bundle_is_input_tx(&bundle_ctx, 1));
    // meta transaction
    assert_false(bundle_is_input_tx(&bundle_ctx, 2));

    // invalid index
    expect_assert_failure(bundle_is_input_tx(&bundle_ctx, 3));
}

static void test_bundle_get_num_value_txs(void **state)
{
    UNUSED(state);

    BUNDLE_CTX bundle_ctx;
    create_bundle_from_input(PETER_VECTOR.bundle, &bundle_ctx);

    assert_int_equal(bundle_get_num_value_txs(&bundle_ctx), 2);
}

static void test_bundle_hash(void **state)
{
    UNUSED(state);

    BUNDLE_CTX bundle_ctx;
    create_bundle_from_input(PETER_VECTOR.bundle, &bundle_ctx);

    compute_hash(&bundle_ctx);

    char hash_chars[NUM_HASH_TRYTES + 1];
    bytes_to_chars(bundle_get_hash(&bundle_ctx), hash_chars, NUM_HASH_BYTES);

    assert_memory_equal(hash_chars, PETER_VECTOR.bundle_hash, NUM_HASH_TRYTES);
}

static void test_validate_bundle_nonzero_balance(void **state)
{
    UNUSED(state);
    static const int security = 2;

    TX_INPUT txs[MAX_BUNDLE_SIZE];
    // output transaction
    memcpy(&txs[0], &PETER_VECTOR.bundle[0], sizeof(TX_INPUT));
    txs[0].value += 1;
    // input transaction
    memcpy(&txs[1], &PETER_VECTOR.bundle[1], sizeof(TX_INPUT));
    // meta transaction
    memcpy(&txs[2], &PETER_VECTOR.bundle[2], sizeof(TX_INPUT));

    BUNDLE_CTX bundle_ctx;
    create_bundle_from_input(txs, &bundle_ctx);

    unsigned char seed_bytes[NUM_HASH_BYTES];
    chars_to_bytes(PETER_VECTOR.seed, seed_bytes, NUM_HASH_TRYTES);

    assert_int_equal(
        validate_bundle(&bundle_ctx, UINT8_MAX, seed_bytes, security),
        NONZERO_BALANCE);
}

static void test_validate_bundle_invalid_index(void **state)
{
    UNUSED(state);
    static const int security = 2;

    TX_INPUT txs[MAX_BUNDLE_SIZE];
    // output transaction
    memcpy(&txs[0], &PETER_VECTOR.bundle[0], sizeof(TX_INPUT));
    // input transaction
    memcpy(&txs[1], &PETER_VECTOR.bundle[1], sizeof(TX_INPUT));
    txs[1].address_idx += 1;
    // meta transaction
    memcpy(&txs[2], &PETER_VECTOR.bundle[2], sizeof(TX_INPUT));

    BUNDLE_CTX bundle_ctx;
    create_bundle_from_input(txs, &bundle_ctx);

    unsigned char seed_bytes[NUM_HASH_BYTES];
    chars_to_bytes(PETER_VECTOR.seed, seed_bytes, NUM_HASH_TRYTES);

    assert_int_equal(
        validate_bundle(&bundle_ctx, UINT8_MAX, seed_bytes, security),
        INVALID_ADDRESS_INDEX);
}

static void test_validate_bundle_unsecure_hash(void **state)
{
    UNUSED(state);
    static const int security = 2;

    TX_INPUT txs[MAX_BUNDLE_SIZE];
    // output transaction
    memcpy(&txs[0], &PETER_VECTOR.bundle[0], sizeof(TX_INPUT));
    txs[0].tag[0] = '\0';
    // input transaction
    memcpy(&txs[1], &PETER_VECTOR.bundle[1], sizeof(TX_INPUT));
    // meta transaction
    memcpy(&txs[2], &PETER_VECTOR.bundle[2], sizeof(TX_INPUT));

    BUNDLE_CTX bundle_ctx;
    create_bundle_from_input(txs, &bundle_ctx);

    unsigned char seed_bytes[NUM_HASH_BYTES];
    chars_to_bytes(PETER_VECTOR.seed, seed_bytes, NUM_HASH_TRYTES);

    assert_int_equal(bundle_validating_finalize(&bundle_ctx, UINT8_MAX,
                                                seed_bytes, security),
                     UNSECURE_HASH);
}

static void test_bundle_finalize(void **state)
{
    UNUSED(state);

    const TX_ENTRY txs[] = {
        {"LHWIEGUADQXNMRKQSBDJOAFMBIFKHHZXYEFOU9WFRMBGODSNJAPGFHOUOSGDICSFVA9K"
         "OUPPCMLAHPHAW",
         10, "999999999999999999999999999", 0},
        {"WLRSPFNMBJRWS9DFXCGIROJCZCPJQG9PMOO9CUZNQXTLLQAYXGXT9LECGEQ9MQIWIBGQ"
         "REFHULPOETHNZ",
         -5, "999999999999999999999999999", 0},
        {"UMDTJXHIFVYVCHXKZNMQWMDHNLVQNMJMRULXUFRLNFVVUMKYZOAETVQOWSDUAKTXVNDS"
         "VAJCASTRQNV9D",
         -5, "999999999999999999999999999", 0}};
    const char exp_hash[] = "VMSEGGHKOUYTE9JNZEQIZWFUYHATWEVXAIJNPG9EDPCQRFAFWP"
                            "CVGHYJDJWXAFNWRGUUPULXOCEJDBUVD";
    const unsigned int exp_tag_increment = 404;

    BUNDLE_CTX bundle_ctx;
    bundle_create(txs, ARRAY_SIZE(txs), &bundle_ctx);

    const uint32_t tag_increment = bundle_finalize(&bundle_ctx);
    assert_int_equal(tag_increment, exp_tag_increment);

    char hash_chars[NUM_HASH_TRYTES + 1];
    bytes_to_chars(bundle_get_hash(&bundle_ctx), hash_chars, NUM_HASH_BYTES);
    // make null-terminated
    hash_chars[NUM_HASH_TRYTES] = '\0';

    assert_string_equal(hash_chars, exp_hash);
}

static void test_max_value_txs_bundle_finalize(void **state)
{
    UNUSED(state);

    const TX_ENTRY txs[] = {
        {"UMDTJXHIFVYVCHXKZNMQWMDHNLVQNMJMRULXUFRLNFVVUMKYZOAETVQOWSDUAKTXVNDSV"
         "AJCASTRQNV9D",
         MAX_IOTA_VALUE, "MMMMMMMMMMMMMMMMMMMMMMMMMMM", 0xFFFFFFFF},
        {"WLRSPFNMBJRWS9DFXCGIROJCZCPJQG9PMOO9CUZNQXTLLQAYXGXT9LECGEQ9MQIWIBGQR"
         "EFHULPOETHNZ",
         -MAX_IOTA_VALUE, "MMMMMMMMMMMMMMMMMMMMMMMMMMM", 0xFFFFFFFF}};
    const char exp_hash[] = "9ZARQDSKQGVYEKJGVILRTTLBGCTYITLIYBDBGSFDUKWINXSHCP"
                            "AWNXSCIPVVDDFWYEHQITKGOUYGYAPRD";
    const unsigned int exp_tag_increment = 79;

    BUNDLE_CTX bundle_ctx;
    bundle_create(txs, ARRAY_SIZE(txs), &bundle_ctx);

    const uint32_t tag_increment = bundle_finalize(&bundle_ctx);
    assert_int_equal(tag_increment, exp_tag_increment);

    char hash_chars[NUM_HASH_TRYTES + 1];
    bytes_to_chars(bundle_get_hash(&bundle_ctx), hash_chars, NUM_HASH_BYTES);
    // make null-terminated
    hash_chars[NUM_HASH_TRYTES] = '\0';

    assert_string_equal(hash_chars, exp_hash);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_increment_tag),
        cmocka_unit_test(test_normalize_hash),
        cmocka_unit_test(test_normalize_hash_zero),
        cmocka_unit_test(test_normalize_hash_one),
        cmocka_unit_test(test_normalize_hash_neg_one),
        cmocka_unit_test(test_empty_bundle),
        cmocka_unit_test(test_one_tx_bundle),
        cmocka_unit_test(test_bundle_is_input_tx),
        cmocka_unit_test(test_bundle_get_num_value_txs),
        cmocka_unit_test(test_bundle_hash),
        cmocka_unit_test(test_validate_bundle_nonzero_balance),
        cmocka_unit_test(test_validate_bundle_invalid_index),
        cmocka_unit_test(test_validate_bundle_unsecure_hash),
        cmocka_unit_test(test_bundle_finalize),
        cmocka_unit_test(test_max_value_txs_bundle_finalize)};

    return cmocka_run_group_tests(tests, NULL, NULL);
}
