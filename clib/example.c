#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "age-otp.h"

/* Macro CHECK: panggil fungsi, exit kalau error */
#define CHECK(call) \
    do { \
        OtpError _rc = (call); \
        if (_rc != Ok) { \
            fprintf(stderr, "Error code: %d\n", (int)_rc); \
            exit(1); \
        } \
    } while(0)

int main(void) {
    const char *pk = "age1ysxuaeqlk7xd8uqsh8lsnfwt9jzzjlqf49ruhpjrrj5yatlcuf7qke4pqe";
    
    /* Version */
    char *ver = otp_version();
    printf("age-otp v%s\n", ver);
    otp_string_free(ver);
    
    /* Constants */
    printf("Seed len: %d\n", (int)OTP_SEED_LEN);
    printf("Code len: %d-%d\n", (int)OTP_MIN_CODE_LEN, (int)OTP_MAX_CODE_LEN);
    
    /* Create engine from public key */
    COtpEngine *eng = NULL;
    CHECK(otp_engine_from_public_key(pk, &eng, NULL));
    
    /* Generate OTP code */
    COtpCode *code = NULL;
    CHECK(otp_engine_generate(eng, 6, 1000, 30, Numeric, &code, NULL));
    
    /* Print code */
    char *s = otp_code_as_str(code);
    printf("OTP: %s (born=%lu)\n", s, (unsigned long)otp_code_born_at(code));
    
    /* Verify the code */
    OtpError rc = otp_engine_verify_raw(
        eng, s, 6, 1000, 3600, 30, Numeric, NULL
    );
    printf("Verify: %s\n", (rc == Ok) ? "OK" : "FAIL");
    
    /* Cleanup */
    otp_string_free(s);
    otp_code_free(code);
    otp_engine_free(eng);
    
    return 0;
}