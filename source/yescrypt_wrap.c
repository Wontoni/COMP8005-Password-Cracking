#define _GNU_SOURCE
#include <crypt.h>
#include <string.h>

/*
 * Return values:
 *   1 = password matches hash
 *   0 = password does not match
 *  -1 = error
 */
int verify_yescrypt(const char *password, const char *full_hash)
{
    struct crypt_data data;
    memset(&data, 0, sizeof(data));

    char *result = crypt_r(password, full_hash, &data);
    if (result == NULL)
    {
        return -1;
    }
    return strcmp(result, full_hash) == 0 ? 1 : 0;
}