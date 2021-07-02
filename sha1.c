/*
 * Implementations for SHA1 algorithm
 */

#include "sha1.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h> // only needed for exit() right now

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

/*
 * PROCESS BLOCK
 * TODO
 */
SHA1_ERRCODE SHA1_process_block(SHA1_SHA1Object_p_t sha1_p)
{

    /*
     * variable initialization
     */
    SHA1_ERRCODE err = SHA1_SUCCESS;
    SHA1_WORD_t word_80[80];             /* 80-word sequence */
    SHA1_WORD_t temp_word;               /* Temporary word value */
    SHA1_WORD_t A, B, C, D, E;           /* Word buffers */
    int t = 0;                           /* loop counter */
    const SHA1_WORD_t constants_K[4] = { /* defined in Sec. 4 */
        0x5A827999,
        0x6ED9EBA1,
        0x8F1BBCDC,
        0xCA62C1D6
    };

    printf("80-word sequence (first 20):\n");
    for (size_t i=0; i<20; ++i)
    {
        printf("%08X ", word_80[i]);
    }
    printf("\n\n");

    /*
     * For the first 15-th elements of W, compute the bitwise OR of
     * the message block at elements spaced by multiples of 4. These
     * elements are then left-shifted, except for the last.
     */

    /*
     * NOTE
     * If you were to use SHA1_WORD_t as the data type
     * for W, you'd have to account for the spacing differently
     */
    for(t = 0; t < 16; t++)
    {
        word_80[t] = (
            sha1_p->message_block[t * 4]     << 24 |
            sha1_p->message_block[t * 4 + 1] << 16 |
            sha1_p->message_block[t * 4 + 2] << 8  |
            sha1_p->message_block[t * 4 + 3]
        );
    } 

    printf("First 10 of W after initializing with message block:\n");
    for (int i=0; i<10; ++i)
    {
        printf("%08X ", word_80[i]);
    }
    printf("\n\n");
    //printf("bitwise operation, 16 -> 80:\n");
    /*
     * This step in the algorithm is really cool. We start off with
     * the first 15-th elements already initialized from the previous
     * step. Beginning at the 16-th element, we compute the bitwise XOR
     * of the 13-th, 8-th, 2-th, and 1-th elements. Then we send that
     * result into the circular shift, computing the bitwise OR of
     * that word left-shifted 1 bit and that word right-shifted 32-1
     * bits. That final result is then assigned to the 16-th slot.
     * Proceeding in the loop, now we have 16-th elements in W. This
     * repeats until all elements of the array W are filled, replacing
     * any garbage values that W started with at compile-time initialization.
     */
    for (t=16; t<80; ++t)
    {
        temp_word = SHA1_circular_shift(1, word_80[t-3] ^ word_80[t-8] ^ word_80[t-14] ^ word_80[t-16]);
        //printf("t=%02i; CIRCSHIFT(1, W[t-3] ^ W[t-8] ^ W[t-14] ^ W[t-16] = %08X ^ %08X ^ %08X ^ %08X) = %08X\n", t, W[t-3], W[t-8], W[t-14], W[t-16], tmp);
        word_80[t] = temp_word;
    }

    /*
     * set up temporary hash arrays
     */
    A = sha1_p->temp_hash[0];
    B = sha1_p->temp_hash[1];
    C = sha1_p->temp_hash[2];
    D = sha1_p->temp_hash[3];
    E = sha1_p->temp_hash[4];

    /*
     * For the first twenty values in the block, take the circular
     * shift of A and add it to (new line for clarity)
     * bitwise OR of (
     *   (bitwise AND of B, C)
     *   (bitwise AND of bitwise complement of B, D)
     * ) + E + word_80[t] + K[0]
     * and assign it to temp; set E to D, D to C, compute the circular
     * shift of B and assign it to C, set B to A, A to temp
     */
    //printf("bitwise operation, 0 -> 20\n");
    for(t=0; t<20; t++)
    {
        temp_word = SHA1_circular_shift(5,A) +
                ((B & C) | ((~B) & D)) + E + word_80[t] + constants_K[0];
        E = D;
        D = C;
        C = SHA1_circular_shift(30,B);

        B = A;
        A = temp_word;
    }

    //printf("bitwise operation, 20 -> 40\n");
    for(t=20; t<40; t++)
    {
        temp_word = SHA1_circular_shift(5,A) + (B ^ C ^ D) + E + word_80[t] + constants_K[1];
        E = D;
        D = C;
        C = SHA1_circular_shift(30,B);
        B = A;
        A = temp_word;
    }

    //printf("bitwise operation, 40 -> 60\n");
    for(t=40; t<60; t++)
    {
        temp_word = SHA1_circular_shift(5,A) +
               ((B & C) | (B & D) | (C & D)) + E + word_80[t] + constants_K[2];
        E = D;
        D = C;
        C = SHA1_circular_shift(30,B);
        B = A;
        A = temp_word;
    }

    //printf("bitwise operation, 60 -> 80\n");
    for(t=60; t<80; t++)
    {
        temp_word = SHA1_circular_shift(5,A) + (B ^ C ^ D) + E + word_80[t] + constants_K[3];
        E = D;
        D = C;
        C = SHA1_circular_shift(30,B);
        B = A;
        A = temp_word;
    }

    printf("printout of first 20 of word_80:\n");
    for (int i=0; i<20; ++i)
    {
        printf("%08X ", word_80[i]);
    }
    printf("\n\n");

    /*
     * Assign the newly computed WORDs to the temporary hash array
     */
    sha1_p->temp_hash[0] += A;
    sha1_p->temp_hash[1] += B;
    sha1_p->temp_hash[2] += C;
    sha1_p->temp_hash[3] += D;
    sha1_p->temp_hash[4] += E;

    printf("printout of first 20 of sha1_p->message_block (should be same):\n");
    for (int i=0; i<20; ++i)
    {
        printf("%08X ", sha1_p->message_block[i]);
    }
    printf("\n\n");

    printf("intermediate hash:\n");

    for (int i=0; i<5; ++i)
    {
        printf("%08X", sha1_p->temp_hash[i]);
    }
    printf("\n\n");

    return err;
}

/*
 * PROCESS MESSAGE
 */
SHA1_ERRCODE SHA1_process_message(const char *msg_p, SHA1_SHA1Object_p_t sha1_p)
{

    /*
     * initialize counter variables
     */
    int msg_length = 0;        /* to store message length */
    int block_idx  = 0;        /* store the block index posittion */
    SHA1_ERRCODE ret_code = 0; /* store return codes */

    //uint8_t *msg_p = NULL; /* pointer to message, probably will result from a read */

    /*
     * Calculate size of message string in bytes
     */
    msg_length = strlen(msg_p);
    printf("INITIAL MESSAGE LENTGH: %08X\n", msg_length);

    /*
     * Process the message string in 512 bit blocks. For each block,
     * compute the temporary hash and store it. Only after the message
     * string has ended can we produce the final result.
     */

    /* While the message length is nonzero, we process each 512-bit
     * WORD and compute its hash. This hash is stored temporarily,
     * and will be used in the computations of subsequent computations.
     */
    while (msg_length > 0)
    {

        while (msg_length > 0 && block_idx < 64)
        {
            /* Assign the value of msg_p[block_idx] to the
             * message block. Increment the index counter and message ptr
             */
            sha1_p->message_block[block_idx] = *(msg_p);
            msg_length--;
            block_idx++;
            msg_p++;
        }

        printf("Message block (first 20):\n");
        for (int i=0; i<20; ++i)
        {
            printf("%08X ", sha1_p->message_block[i]);
        }
        printf("\n\n");

        /*
         * The above while-loop has finished due to one of two conditions:
         * 1) the message isn't long enough or 2) we've filled the block
         */

        if (block_idx == 64)
        {
            /*
             * Process the block and store the intermediate hash.
             * The block_idx is reset after and NOT by the function
             * which processes the block.
             */
            ret_code = SHA1_process_block(sha1_p);
            if (ret_code != SHA1_SUCCESS) { printf("BORKED\n"); exit(ret_code); }

        }

        else if (block_idx > 55 && block_idx < 64)
        {
            /*
             * TODO
             * We need to create two WORDs and compute the has for each.
             * The first word will have a "1" added to it (8-bit int), and
             * then padded with "0" until the block_idx == 64, at which point
             * this WORD can be processed and its hash stored. Following this,
             * create another WORD out of all "0" until block_idx == 56; the
             * remaining 8 slots (8 bytes, 64 bits) will allow for a 64-bit
             * integer to denote the length of the original message.
             */
            printf("Got to first else-if, STOP!\n");
            return 0;
        }

        else if (block_idx < 56)
        {
            /*
             * TODO
             * This block is short enough where we can add the "separating 1"
             * and potentially padding 0s along with our 64-bit int length. This
             * will only comprise a single WORD.
             */
            printf("Got to second else-if, STOP!\n");
             return 0;
        }

        /*
         * resetting the block_idx
         */
        block_idx = 0;

    }

    return ret_code;
}
