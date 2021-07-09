/* SHA1 header file */

#include <stdint.h>

#ifndef _SHA1_H_
#define _SHA1_H_


/* Contextual definitions
 * 
 * 1. Bits and Integers
 *
 *    a. HEX DIGIT: representation of a 4-bit string; character of the set
 *       {0, 1, ..., 9, A, ..., F}
 *
 *    b. WORD: 32-bit string, able to be represented by 8 HEX digits
 *       (each 4-bit string converted to hex)
 *
 *    c. INTEGER BETWEEN 0, 2^32 - 1 inclusive: can be represented by sequence
 *       of 8 HEX digits (i.e. a WORD). The least-significant 4 bits are represented
 *       by the right-most HEX digit.
 *
 *       If z is an integer, 0 <= z < 2^64, then z = (2^32)x + y where 0 <=
 *       x < 2^32 and 0 <= y < 2^32.  Since x and y can be represented as
 *       WORDS X and Y, respectively, z can be represented as the pair of
 *       WORDS (X,Y).
 *
 *    d. BLOCK: 512-bit string. A BLOCK can be represented as 16 WORDS.
 *
 * 2. Operations on Words
 *
 *    a. Bitwise logical operations
 *       X AND Y: bitwise logical and of X and Y
 *       X OR Y : bitwise logical inclusive-or of X and Y
 *       X XOR Y: bitwise logical exlcusive-or of X and Y
 *       NOT X  : bitwise logical complement of X
 *
 *    b. Addition of words X and Y
 *       X + Y is defined
 *
 *       Words X and Y represent integers x and y, where 0 <= x <= 2^32 and
 *       0 <= y <= 2^32. Compute
 *       
 *       z = (x + y) % 2^32
 *       
 *       then 0 <= z <= 2^32. Convert z to a word, Z, then Z = X + Y
 * 
 *    c. Circular left-shift S^n(X)
 * 
 *       S^n(X) = (X << n) OR (X >> 32-n)
 * 
 * 3. Message Padding
 * 
 *    The SHA1 algorithm processes blocks of 512 bits to produce a message digest.
 *    Padding ensures the message is a multiple of 512 * n. A 64-bit integer at
 *    the end of the message indicates the length of the original message.
 *    
 *    Suppose a message has a length, l, where l < 2^64. Before input to the SHA1,
 *    the message is padded with the following procedure:
 *    
 *    a. a "1" is appended to the right
 *    b. "0"s are appended to the right until the message length is 448 bits.
 *    c. A 64 bit integer is added, indicating the length of the original message.
 *       This integer is represented by two words. If l < 2^32, then the first word
 *       is all 0s.
 *
 * 4. Functions and Constants Used
 * 
 *    A sequence of logical functions f(0), f(1),..., f(79) is used in
 *    SHA-1.  Each f(t), 0 <= t <= 79, operates on three 32-bit words B, C,
 *    D and produces a 32-bit word as output.  f(t;B,C,D) is defined as
 *    follows: for words B, C, D,
 * 
 *       f(t;B,C,D) = (B AND C) OR ((NOT B) AND D)         ( 0 <= t <= 19)
 * 
 *       f(t;B,C,D) = B XOR C XOR D                        (20 <= t <= 39)
 * 
 *       f(t;B,C,D) = (B AND C) OR (B AND D) OR (C AND D)  (40 <= t <= 59)
 * 
 *       f(t;B,C,D) = B XOR C XOR D                        (60 <= t <= 79).
 *
 *    A sequence of "constant words" K(0), K(1), ... , K(79) is used in the
 *    SHA-1.  In hex these are given by
 *
 *       K(t) = 5A827999         ( 0 <= t <= 19)
 *
 *       K(t) = 6ED9EBA1         (20 <= t <= 39)
 *
 *       K(t) = 8F1BBCDC         (40 <= t <= 59)
 *
 *       K(t) = CA62C1D6         (60 <= t <= 79).
 *
 * 5. Algorithm to compute the message digest
 * 
 *    In RFC 3174, there are two algorithms given for computing the message digest.
 *    This currently only covers the first.
 *
 *    The message digest is computed using the message padded as described
 *    in section 4.  The computation is described using two buffers, each
 *    consisting of five 32-bit words, and a sequence of eighty 32-bit
 *    words.  The words of the first 5-word buffer are labeled A,B,C,D,E.
 *    The words of the second 5-word buffer are labeled H0, H1, H2, H3, H4.
 *    The words of the 80-word sequence are labeled W(0), W(1),..., W(79).
 *    A single word buffer TEMP is also employed.
 *
 *    To generate the message digest, the 16-word blocks M(1), M(2),...,
 *    M(n) defined in section 4 are processed in order.  The processing of
 *    each M(i) involves 80 steps.
 *
 *    Before processing any blocks, the H's are initialized as follows: in
 *    hex,
 *
 *       H0 = 67452301
 *
 *       H1 = EFCDAB89
 *
 *       H2 = 98BADCFE
 *
 *       H3 = 10325476
 *
 *       H4 = C3D2E1F0.
 *
 *    Now M(1), M(2), ... , M(n) are processed.  To process M(i), we
 *    proceed as follows:
 *
 *       a. Divide M(i) into 16 words W(0), W(1), ... , W(15), where W(0)
 *          is the left-most word.
 *
 *       b. For t = 16 to 79 let
 *
 *          W(t) = S^1(W(t-3) XOR W(t-8) XOR W(t-14) XOR W(t-16)).
 *
 *       c. Let A = H0, B = H1, C = H2, D = H3, E = H4.
 *
 *       d. For t = 0 to 79 do
 *
 *          TEMP = S^5(A) + f(t;B,C,D) + E + W(t) + K(t);
 *
 *          E = D;  D = C;  C = S^30(B);  B = A; A = TEMP;
 *
 *       e. Let H0 = H0 + A, H1 = H1 + B, H2 = H2 + C, H3 = H3 + D, H4 = H4
 *          + E.
 *
 *    After processing M(n), the message digest is the 160-bit string
 *    represented by the 5 words
 *
 *          H0 H1 H2 H3 H4.
 */

/*
 * All typedefs
 * NOTE: why is each message block an array of 64 8-bit uints ("char" coloquially)
 * instead of 16 32-bit uints?
 */
typedef uint32_t SHA1_WORD_t, *SHA1_WORD_p_t;      /* 4-byte int */
typedef uint8_t SHA1_BLOCK_t[64], *SHA1_BLOCK_p_t; /* 1-byte char */

typedef struct SHA1_SHA1Object {
    SHA1_WORD_t digest[5];      /* digest is 5 WORDs */
    SHA1_BLOCK_t message_block; /* each block is 512 bits or 64 bytes */
    SHA1_WORD_t temp_hash[5];   /* store the hash temporarily */
} SHA1_SHA1Object_t, *SHA1_SHA1Object_p_t;

/*
 * Error codes as enum
 */
typedef enum _sha1_errcode
{
    SHA1_SUCCESS = 0,
    SHA1_GENERIC_ERROR = 1
} SHA1_ERRCODE;

/*
 * macro defines how many words per block; this could
 * change if we decide to use a different type for WORD_t
#define SHA1_BLOCK_MAX_WORD_SLOTS ( 512 / sizeof(SHA1_WORD_t) )
 */

/*
 * Constants
 */

/*
 * All function prototypes
 */

/*
 * CIRCULAR SHIFT
 * Perform the circular shift operation on a word as defined
 * above
 */
SHA1_WORD_t SHA1_circular_shift(int n, SHA1_WORD_t word);

/*
 * PAD MESSAGE STRING
 * Pad a given message string according to the padding algorithm
 * (defined above, excerpted below) to a length of a multiple of 512 bits:
 *    Suppose a message has a length, l, where l < 2^64. Before input to the SHA1,
 *    the message is padded with the following procedure:
 *    
 *    a. a "1" is appended to the right
 *    b. "0"s are appended to the right until the message length is 448 bits.
 *    c. A 64 bit integer is added, indicating the length of the original message.
 *       This integer is represented by two words. If l < 2^32, then the first word
 *       is all 0s.
 */
SHA1_ERRCODE SHA1_pad_message(SHA1_SHA1Object_p_t sha1_p, uint8_t *msg, uint64_t msgLength);

/*
 * PROCESS BLOCK
 * Compute the hash for a single 512-bit block. The resulting hash
 * is stored in the SHA1Object->temp_hash.
 *
 * Parameters
 *  sha1_p: pointer to SHA1Object_t
 *
 * Returns
 *  SHA1_ERRCODE
 */
SHA1_ERRCODE SHA1_process_block(SHA1_SHA1Object_p_t sha1_p);

/*
 * PAD BLOCK
 * Pad the block for a given SHA1Object to 512 bits (64 bytes). If
 * 55 < block_idx < 64, the block will be padded with a "1" then
 * "0s" until the block_idx is 64. If block_idx < 55, a "1" will be added,
 * followed by the required "0s" until the block_idx == 56. This leaves enough
 * space for a 64-bit integer at the end, containing the length of the
 * original message.
*
* Parameters
*   sha1_p: pointer to SHA1 object
*   block_idx: current block index (the next available spot)
*   msg_length: length of original message
*
* Returns
*   SHA1_ERRCODE int
 */
SHA1_ERRCODE SHA1_pad_block(SHA1_SHA1Object_p_t sha1_p, int block_idx, const int msg_length);

/*
 * PROCESS MESSAGE
 * Compute the hash for a variable-length message.
 *
 * Parameters
 *  msg_p: pointer to message
 *  sha1_p: pointer to SHA1Object_t
 *
 * Returns
 *  SHA1_ERRCODE
 */
SHA1_ERRCODE SHA1_process_message(const char *msg_p, SHA1_SHA1Object_p_t sha1_p);

#endif /* _SHA1_H_ */
