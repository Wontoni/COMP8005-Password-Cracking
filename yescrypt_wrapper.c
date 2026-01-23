#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <crypt.h>

char *yescrypt_wrapper(const char *password, const char *salt) {
    // Use the yescrypt algorithm to hash the password with the given salt
    char *hashed = crypt(password, salt);
    return hashed;
}