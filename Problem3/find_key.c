#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>


void handleErrors(void)
{
    ERR_print_errors_fp(stderr);
    abort();
}

int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
            unsigned char *iv, unsigned char *plaintext)
{
    EVP_CIPHER_CTX *ctx;

    int len;

    int plaintext_len;

    if(!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors();

    if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
        handleErrors();

    if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
        handleErrors();
    plaintext_len = len;

    if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len))
        handleErrors();
    plaintext_len += len;

    EVP_CIPHER_CTX_free(ctx);

    return plaintext_len;
}

int hexchar2int(char c)
{
    if ('0' <= c && c <= '9')
        return c - '0';
    else if ('a' <= c && c <= 'f')
        return c - 'a' + 10;
    else if ('A' <= c && c <= 'F')
        return c - 'A' + 10;
    else
        return -1;
}

void hexstr2bytes(const char *hexstr, unsigned char *bytes, int *len)
{
    int hexstr_len = strlen(hexstr);
    int i;
    *len = 0;

    for (i = 0; i < hexstr_len; i += 2)
    {
        int high = hexchar2int(hexstr[i]);
        int low = hexchar2int(hexstr[i+1]);
        if (high == -1 || low == -1)
        {
            printf("Invalid hex character: %c%c\n", hexstr[i], hexstr[i+1]);
            exit(1);
        }
        bytes[(*len)++] = (unsigned char)((high << 4) + low);
    }
}

int main(void)
{
    /* Known plaintext */
    unsigned char *plaintext = (unsigned char *)"This is a top secret.";

    /* Ciphertext provided (hex format) */
    char *cipher_hex = "8d20e5056a8d24d0462ce74e4904c1b5"
                       "13e10d1df4a2ef2ad4540fae1ca0aaf9";

    unsigned char ciphertext[128];
    int ciphertext_len;

    /* Convert hex ciphertext to bytes */
    hexstr2bytes(cipher_hex, ciphertext, &ciphertext_len);

    /* IV of all zeros */
    unsigned char iv[16] = {0};

    /* Buffer for the decrypted text */
    unsigned char decryptedtext[128];
    int decryptedtext_len;

    /* Open words.txt */
    FILE *wordlist = fopen("words.txt", "r");
    if (wordlist == NULL)
    {
        perror("Unable to open words.txt");
        exit(1);
    }

    char word[128];
    while (fgets(word, sizeof(word), wordlist))
    {
        /* Remove newline character */
        size_t len = strlen(word);
        if (word[len - 1] == '\n')
            word[len - 1] = '\0';

        /* Skip words longer than 16 characters */
        if (strlen(word) > 16)
            continue;

        /* Prepare the key: pad with spaces to 16 bytes */
        unsigned char key[16];
        memset(key, 0x20, 16); // Fill with spaces
        memcpy(key, word, strlen(word));

        /* Attempt decryption */
        decryptedtext_len = decrypt(ciphertext, ciphertext_len, key, iv, decryptedtext);

        /* Check if decryption was successful */
        if (decryptedtext_len == -1)
        {
            /* Decryption failed, try next word */
            continue;
        }

        /* Add NULL terminator */
        decryptedtext[decryptedtext_len] = '\0';

        /* Check if decrypted text matches the plaintext */
        if (strcmp((char *)decryptedtext, (char *)plaintext) == 0)
        {
            printf("Key found: '%s'\n", word);
            fclose(wordlist);
            return 0;
        }
    }

    fclose(wordlist);
    printf("Key not found.\n");
    return 0;
}
