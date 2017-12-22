#include <unistd.h>
#include <stdio.h>
#include <iostream>
#include <cstring>
#include <cstdlib>
#include <openssl/md5.h>
#include <openssl/sha.h>

#define DEFAULT_CHARS "abcdefghijklmnopqsrtuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890!\"£$%^&*()_+-="
#define MAX_TEST_SIZE 256

void help(char *argv);
void md5(char* string, char* result);
void sha256(char* string, char* result);
int hashbreak(int hashtype, std::string hash, std::string chars, int testlen);

int main(int argc, char *argv[])
{
    int opt;
    //int threads;
    std::string chars (DEFAULT_CHARS);
    std::string hashtype;
    std::string hash;
    char * testlenopt;
    int testlenoptlen;
    int testlen = 0;

    while ((opt = getopt(argc, argv, "hb:s:c:l:")) != -1) {
        switch (opt) {
        case 'b':
            chars.assign(optarg);
            break;
        case 's':
            hashtype.assign(optarg);
            break;
        //case 't':
        //    threads = atoi(optarg);
        //    break;
        case 'c':
            hash.assign(optarg);
            break;
        case 'l':
            testlenopt = optarg;
            testlenoptlen = strlen(testlenopt);
            for (int i = 0; i < testlenoptlen; i++) {
                if (!isdigit(testlenopt[i])) {
                    std::cerr << "ERROR: Test length must be an integer" << std::endl;
                    help(argv[0]);
                    return 1;
                }
            }
            testlen = atoi(testlenopt);
            if (testlen > MAX_TEST_SIZE) {
                std::cerr << "ERROR: Test length is larger than the maximum test string size (" << MAX_TEST_SIZE << ")" << std::endl;
                help(argv[0]);
                return 1;
            } else if (testlen < 1) {
                std::cerr << "ERROR: Test length must be between 1 and " << MAX_TEST_SIZE << std::endl;
                help(argv[0]);
                return 1;
            }
            testlen--;
            break;
        case 'h':
        default:
            help(argv[0]);
            return 0;
        }
    }

    if (hash.length() == 0) {
        std::cerr << "ERROR: You must specify a hash code to break with -c" << std::endl;
        help(argv[0]);
        return 1;
    }

    if (hashtype.compare("md5") == 0) {
        if (hash.length() != 32) {
            std::cerr << "ERROR: md5 hash must be 32 characters" << std::endl;
            return 1;
        }
        return hashbreak(0, hash, chars, testlen);
    } else if (hashtype.compare("sha256") == 0) {
        if (hash.length() != 64) {
            std::cerr << "ERROR: sha256 hash must be 64 characters" << std::endl;
            return 1;
        }
        return hashbreak(1, hash, chars, testlen);
    } else {
        std::cerr << "ERROR: Unrecognized hash type (" << hashtype << ")" << std::endl;
        help(argv[0]);
        return 1;
    }

//    switch (hashtype) {
//        case 'md5':
//            return hashbreak(0, hash);
//            break;
//        case 'sha256':
//            return hashbreak(1, hash);
//            break;
//        default:
//            std::cout << "ERROR: Unrecognized hash type (" << hashtype << ")" << std::endl;
//            help(argv[0]);
//            return 1;
//    }

    return 0;
}

void help(char *argv)
{
    std::cout << "Single threaded hash brute forcer v0.10." << std::endl;
    std::cout << "Usage: " << argv << " -s [HASH_TYPE] -c [HASH]" << std::endl;
    std::cout << "-s Specify the type of hash. Supported: \"md5\" and \"sha256\"." << std::endl;
    std::cout << "-c The hash code to break." << std::endl;
    std::cout << "-b Brute force using the specified characters." << std::endl;
    std::cout << "-l Start at the specified test string length." << std::endl;
    std::cout << "Default brute force characters: " << DEFAULT_CHARS << std::endl;
    std::cout << "Max test string length: " << MAX_TEST_SIZE << std::endl;
}

void md5(char* string, char* result)
{
    unsigned char digest[16];

    MD5_CTX ctx;
    MD5_Init(&ctx);
    MD5_Update(&ctx, string, strlen(string));
    MD5_Final(digest, &ctx);

    for (int i = 0; i < 16; i++) {
        sprintf(&result[i*2], "%02x", (unsigned int)digest[i]);
    }
}

void sha256(char* string, char* result)
{
    unsigned char digest[32];

    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, string, strlen(string));
    SHA256_Final(digest, &ctx);

    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        sprintf(&result[i*2], "%02x", (unsigned int)digest[i]);
    }
}

int hashbreak(int hashtype, std::string hash, std::string chars, int testlen)
{
    std::string result ("");
    char md5hashresult[33];
    char sha256hashresult[65];
    int charslen = chars.length();
    //int testlen = 0;
    int oldtestlen = testlen;
    int charspos[MAX_TEST_SIZE];
    //charspos[0] = 0;
    for (int i = 0; i < testlen+1; i++) {
        charspos[i] = 0;
    }

    std::string teststring;
    int addnext = 0;

    std::cout << testlen+1 << std::endl;
    std::cout.flush();

    while (result.compare(hash) != 0) {
        teststring = "";
        if (testlen != oldtestlen) {
            std::cout << testlen+1 << std::endl;
            std::cout.flush();
            oldtestlen = testlen;
        }
        for (int v = 0; v < testlen+1; v = v + 1) {
            teststring.append(chars, charspos[v], 1);
        }
        addnext = 1;
        for (int v = 0; v < testlen+1; v = v + 1) {
            if ((charspos[v]+addnext) > charslen-1) {
                charspos[v] = 0;
                addnext = 1;
                if (v == testlen) {
                    if ((v+1) == MAX_TEST_SIZE) {
                        std::cout << "Maximum test string size of " << MAX_TEST_SIZE << " reached. Terminating." << std::endl;
                        return 2;
                    }
                    charspos[(v+1)] = 0;
                    testlen++;
                }
            } else {
                charspos[v] = charspos[v]+addnext;
                addnext = 0;
            }
        }
        if (hashtype == 0) {
            md5((char*)teststring.c_str(), md5hashresult);
            result = md5hashresult;
        } else if (hashtype == 1) {
            sha256((char*)teststring.c_str(), sha256hashresult);
            result = sha256hashresult;
        }
        //std::cout << "STRING: " << teststring << "  HASH: " << result << std::endl;
        //std::cout.flush();
    }
    std::cout << teststring << std::endl;
    return 0;
}

