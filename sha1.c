/*
 * Implementations for SHA1 algorithm
 */

#include "sha1.h"
#include <string.h>

SHA1_WORD_t SHA1_circular_shift(int n, SHA1_WORD_t word)
{
    return (word << n) | (word >> (32 - n));
}

SHA1_ERRCODE SHA1_pad_message(SHA1_SHA1Object_p_t sha1_p, uint8_t *msg, uint64_t msg_length)
{

    /*
     * NOTE
     * This function assumes that msg_length < 2^64
     */

    SHA1_ERRCODE err = 0;

    uint8_t remaining_until_448 = 448 - msg_length;

    /*
     * Step 1
     * Add a "1" to the end of the message_block
     */

    return err;
}
/*
    H0 0x67452301
    H1 0xEFCDAB89
    H2 0x98BADCFE
    H3 0x10325476
    H4 0xC3D2E1F0
*/
