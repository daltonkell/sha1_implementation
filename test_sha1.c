#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "sha1.h" /* SHA1_ */

int main()
{

    /*
     * STEP 1
     * allocate a SHA1 object, initialize counter variables
     */
    SHA1_SHA1Object_p_t sha1_p = (SHA1_SHA1Object_p_t)malloc(sizeof(SHA1_SHA1Object_t));
    SHA1_ERRCODE err = 0;

    /* Initialize this message block for testing
     * THIS WILL NOT APPEAR IN ALGORITHM!
     */
    char mblock[] = "this is my message and it's around 64 bytes long so let's copmute a HASH!";
    printf("Original testing message:\n%s\n", mblock);

    /*
     * Invoke hash algorithm
     */
    err = SHA1_process_message((const char *)mblock, sha1_p);

    /*
     * free any dynamically allocated memory
     */
    free(sha1_p);

    return 0;
}
