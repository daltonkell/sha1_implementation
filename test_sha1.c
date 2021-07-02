#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "sha1.h" /* SHA1_ */

int main(const int argc, const char *argv[])
{

    /*
     * STEP 1
     * allocate a SHA1 object, initialize counter variables
     */
    SHA1_SHA1Object_p_t sha1_p = (SHA1_SHA1Object_p_t)malloc(sizeof(SHA1_SHA1Object_t));
    SHA1_ERRCODE err = 0;
    long int fsize = 0;       /* file size */
    long int fsize_read = 0;  /* to check against fsize */
    FILE *file_p = NULL; /* file pointer */

    /*
     * Open file. If file is too large, say 5MB, do not allocate.
     */
    file_p = fopen(argv[1], "r");
    if (file_p == NULL)
    {
        printf("Pointer to file is NULL! Exiting!\n");
        return 1;
    }
    fseek(file_p, SEEK_SET, 0L);
    fseek(file_p, 0L, SEEK_END);
    fsize = ftell(file_p);

    if (fsize > (5 * 1024 * 1024))
    {
        printf("File %s larger than 5MiB (%ld). Not allocating.\n", argv[1], fsize);
        return 1;
    }
    printf("File size: %ld\n", fsize);

    /*
     * Return to beginning of file
     * Allocate space for the file
     */
    fseek(file_p, SEEK_SET, 0L);
    void *msg_p = malloc(fsize);
    if (msg_p == NULL)
    {
        printf("Allocating buffer for message returned NULL!\n");
        return 1;
    }

    /*
     * Read data into msg_p array, close file
     */
    fsize_read = fread(msg_p, sizeof(char), fsize, file_p);
    if (fsize_read != fsize)
    {
        printf("fread failed with %li\n", fsize_read);
        return fsize_read;
    }
    fclose(file_p);

    /*
     * Invoke hash algorithm
     */
    err = SHA1_process_message((const char *)msg_p, sha1_p);

    /*
     * free any dynamically allocated memory
     */
    free(msg_p);
    free(sha1_p);

    return 0;
}
