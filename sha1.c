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

/*
 * PROCESS BLOCK
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

    for(t=20; t<40; t++)
    {
        temp_word = SHA1_circular_shift(5,A) + (B ^ C ^ D) + E + word_80[t] + constants_K[1];
        E = D;
        D = C;
        C = SHA1_circular_shift(30,B);
        B = A;
        A = temp_word;
    }

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

    for(t=60; t<80; t++)
    {
        temp_word = SHA1_circular_shift(5,A) + (B ^ C ^ D) + E + word_80[t] + constants_K[3];
        E = D;
        D = C;
        C = SHA1_circular_shift(30,B);
        B = A;
        A = temp_word;
    }

    /*
     * Assign the newly computed WORDs to the temporary hash array
     */
    sha1_p->temp_hash[0] += A;
    sha1_p->temp_hash[1] += B;
    sha1_p->temp_hash[2] += C;
    sha1_p->temp_hash[3] += D;
    sha1_p->temp_hash[4] += E;

#ifdef DEBUG
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
#endif

    return err;
}

/*
 * PAD AND PROCESS BLOCK
 */
SHA1_ERRCODE SHA1_pad_block(SHA1_SHA1Object_p_t sha1_p, int block_idx, const int msg_length)
{

    SHA1_ERRCODE err = 0;

    if (block_idx > 55 && block_idx < 64)
    {

#ifdef DEBUG
        printf("Padding block of size %02i with\"1\" and \"0s\"\n", (block_idx-1));
#endif

        /*
         * Add "1", then pad with "0" until block idx == 64
         */

        sha1_p->message_block[block_idx++] = 0x80; /* NOTE why is this "1" not 0x01? */
        /* NOTE the inline increment */

        while (block_idx < 64)
        {
            sha1_p->message_block[block_idx++] = 0x0;
        }

        /*
         * Process block;
         * Add second word of 0s and original length
         */
        err = SHA1_process_block(sha1_p);

        /* recursive call to itself to add block of 0s and length; the
         * below else-if branch should be hit at this point
         */
        block_idx = 0;
        SHA1_pad_block(sha1_p, block_idx, msg_length);

    }

    else if (block_idx < 55)
    {

        int len = msg_length * 8; /* in bits, not bytes */

#ifdef DEBUG
        printf("Padding block of size %02i with \"0s\" and creating "
                "fill block of \"0s\" and original length %010i\n",
                (block_idx-1), len);
#endif

        /*
         * NOTE
         * Does a 1 need to be appended here as well?
         * Double check reference implementation(s).
         */
        while (block_idx < 56)
        {
            sha1_p->message_block[block_idx++] = 0x0;
        }


        /*
         * Add original length of message
         */
        sha1_p->message_block[block_idx++] = len >> 24;
        sha1_p->message_block[block_idx++] = len >> 16;
        sha1_p->message_block[block_idx++] = len >> 8;
        sha1_p->message_block[block_idx++] = len;

        /* Now... zeros? The ref impl. looks like it's adding zeros */
        sha1_p->message_block[block_idx++] = 0;
        sha1_p->message_block[block_idx++] = 0;
        sha1_p->message_block[block_idx++] = 0;
        sha1_p->message_block[block_idx++] = 0;

        if (block_idx != 64)
        {

#ifdef DEBUG
            printf("ERROR block_idx == %i != 64 after adding length!\n", block_idx);
#endif

            err = SHA1_GENERIC_ERROR;
            return err;
        }

        /* compute intermediate hash */
        err = SHA1_process_block(sha1_p);
    }

    return err;
}

/*
 * PROCESS MESSAGE
 */
SHA1_ERRCODE SHA1_process_message(const char *msg_p, SHA1_SHA1Object_p_t sha1_p)
{

    /*
     * Process the message string in 512 bit blocks. For each block,
     * compute the temporary hash and store it. Only after the message
     * string has ended can we produce the final result.
     */

    /*
     * initialize counter variables
     */
    const int msg_length = strlen(msg_p); /* to store original message length */
    int mutable_msg_length = msg_length;     /* for counting */
    int block_idx  = 0;                   /* store the block index posittion */
    SHA1_ERRCODE ret_code = 0;            /* store return codes */

#ifdef DEBUG
    printf("INITIAL MESSAGE LENTGH: %08i\n", mutable_msg_length);
#endif

    /* While the message length is nonzero, we process each 512-bit
     * WORD and compute its hash. This hash is stored temporarily,
     * and will be used in the computations of subsequent computations.
     */

    /*
     * Initialize intermediate hash buffer with constants
     */
    sha1_p->temp_hash[0] = 0x67452301;
    sha1_p->temp_hash[1] = 0xEFCDAB89;
    sha1_p->temp_hash[2] = 0x98BADCFE;
    sha1_p->temp_hash[3] = 0x10325476;
    sha1_p->temp_hash[4] = 0xC3D2E1F0;

    while (mutable_msg_length > 0)
    {

        while (mutable_msg_length > 0 && block_idx < 64)
        {
            /* Assign the value of msg_p[block_idx] to the
             * message block. Increment the index counter and message ptr
             */
            sha1_p->message_block[block_idx] = *(msg_p);
            mutable_msg_length--;
            block_idx++;
            msg_p++;
        }

#ifdef DEBUG
        printf("Message block (first 20):\n");
        for (int i=0; i<20; ++i)
        {
            printf("%08X ", sha1_p->message_block[i]);
        }
        printf("\n\n");
#endif

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
            if (ret_code != SHA1_SUCCESS)
            {
                printf("BORKED after processing\n");
                return ret_code;
            }
        }

        else if (block_idx <= 56)
        {
            /*
             * We need to create two WORDs and compute the has for each.
             * The first word will have a "1" added to it (8-bit int), and
             * then padded with "0" until the block_idx == 64, at which point
             * this WORD can be processed and its hash stored. Following this,
             * create another WORD out of all "0" until block_idx == 56; the
             * remaining 8 slots (8 bytes, 64 bits) will allow for a 64-bit
             * integer to denote the length of the original message.
             */
            ret_code = SHA1_pad_block(sha1_p, block_idx, msg_length);
            if (ret_code != SHA1_SUCCESS)
            {
                printf("BORKED after padding\n");
                return ret_code;
            }
        }

        /*
         * resetting the block_idx
         */
        block_idx = 0;

        /*
         * if the original message was 64 bytes (512 bits) long exactly,
         * then we need to add a second WORD made of all 0s plus the
         * original length at the end
         */
        if (msg_length == 64)
        {
            ret_code = SHA1_pad_block(sha1_p, block_idx, msg_length);
            if (ret_code != SHA1_SUCCESS)
            {
                printf("BORKED after padding\n");
                return ret_code;
            }
        }
    }

    return ret_code;
}
