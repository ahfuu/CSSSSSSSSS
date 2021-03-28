#include <stdio.h>
#include <openssl/bn.h>
#include "rsa.c"
#include "util.c"
#define NBITS 256


int main () 
{	
	/*
		Task 3 - Decrypting a message
										*/
	// We are going to decrypt the following ciphertext
	// The ciphertext was given in hexadecimal format.
	// So we must convert to a BIGNUM for the computations.
	BIGNUM* task3_enc = BN_new();
	BN_hex2bn(&task3_enc, "8C0F971DF2F3672B28811407E2DABBE1DA0FEBBBDFC7DCB67396567EA1E2493F");
	
	
	// Assign the private key
	BIGNUM* priv_key = BN_new();
	BN_hex2bn(&priv_key, "74D806F9F3A62BAE331FFE3F0A68AFE35B3D2E4794148AACBC26AA381CD7D30D");

	// Assign the public key
	BIGNUM* pub_key = BN_new();
	BN_hex2bn(&pub_key, "DCBFFE3E51F62E09CE7032E2677A78946A849DC4CDDE3A4D0CB81629242FB1A5");
	
	
	// We already have the public and private keys. 
	// We can decrypt using our rsa_decrypt function.
	BIGNUM* dec = BN_new();
	
	dec = rsa_decrypt(task3_enc, priv_key, pub_key);
	printf("The decrypted message is: ");
	printHX(BN_bn2hex(dec));
	printf("\n");

	
}
