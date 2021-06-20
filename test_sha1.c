#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "sha1.h" /* SHA1_ */

int main()
{

    int ret_code = 0;

    /*
     * STEP 1
     * allocate a SHA1 object
     */
    SHA1_SHA1Object_p_t sha1_p = (SHA1_SHA1Object_p_t)malloc(sizeof(SHA1_SHA1Object_t));

    printf("Size in bytes of SHA1 WORD: %lu\n", sizeof(SHA1_WORD_t));
    printf("Size in bytes of SHA1 BLOCK: %lu\n", sizeof(SHA1_BLOCK_t));

    /*
     * STEP 2
     * TODO
     * create/read message string; can be any length
     */

    /* Initialize this message block for testing */
    uint8_t mblock[64];
    for (size_t i=0; i<64; ++i) // uint8_t WORD size, so up to 64 slots
    {
        //sha1_p->message_block[i] = (uint8_t)i;
        mblock[i] = (uint8_t)i;
    }


    //int msg_length = strlen((const char *)mblock);
    int msg_length = sizeof(mblock) / sizeof(uint8_t);
    printf("STARTING MESSAGE TOTAL LENGTH: %08d bytes\n", msg_length);
    /*
     * Copy contents of msg to sha1_p message_block
     * This is mainly for testing, will we use memcpy?
     */
    memcpy((void *)sha1_p->message_block, (void *)mblock, msg_length); 

    /*
     * STEP 3
     * TODO
     * THIS SHOULD BE ITS OWN FUNCTION

     * TODO this might be slightly more computationally intensive,
     * but could make each block a member of a linked list or stack...

     * Process the message string in 512 bit blocks. For each block,
     * compute the temporary hash and store it. Only after the message
     * string has ended can we produce the final result.
     */

    /*
     * Pad the message string to a multiple of 512
    ret_code = SHA1_pad_message(sha1_p, mblock, 64);     
    if (ret_code != SHA1_SUCCESS) { printf("BORKED\n"); exit(ret_code); }
     */

    printf("Message block:\n");
    for (int i=0; i<64; ++i)
    {
        printf("%08X ", sha1_p->message_block[i]);
    }
    printf("\n\n");

    /* STEP 4
     * Initialize 80 word sequence
     */
    // 80 word sequence
    // initialize with random garbage essentially
    SHA1_WORD_t W[80];
    printf("80-word sequence:\n");
    for (size_t i=0; i<80; ++i)
    {
        //W[i] = (SHA1_WORD_t)rand();
        printf("%08X ", W[i]);
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
    for(int t = 0; t < 16; t++)
    {
        W[t] = (
            sha1_p->message_block[t * 4]     << 24 |
            sha1_p->message_block[t * 4 + 1] << 16 |
            sha1_p->message_block[t * 4 + 2] << 8  |
            sha1_p->message_block[t * 4 + 3]
            /*
            sha1_p->message_block[t]
            */
        );
    } 
    //printf("\n\n");

    printf("First 16 of W after initializing with message block:\n");
    for (int i=0; i<16; ++i)
    {
        printf("%08X ", W[i]);
    }
    printf("\n\n");

    printf("Bitwise XOR paired with SHA1_circular_shift:\n");
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
    //for (int t=16; t<80; ++t)
    for (int t=16; t<20; ++t)
    {
        //uint32_t tmp = SHA1_circular_shift(1, W[t-3] ^ W[t-8] ^ W[t-14] ^ W[t-16]);
        SHA1_WORD_t tmp = SHA1_circular_shift(1, W[t-3] ^ W[t-8] ^ W[t-14] ^ W[t-16]);
        printf("t=%02i; CIRCSHIFT(1, W[t-3] ^ W[t-8] ^ W[t-14] ^ W[t-16] = %08X ^ %08X ^ %08X ^ %08X) = %08X\n", t, W[t-3], W[t-8], W[t-14], W[t-16], tmp);
        W[t] = tmp;
    }

    /*
     * free any dynamically allocated memory
     */
    free(sha1_p);

    return 0;
}
