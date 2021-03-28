#include <stdio.h>
#include <openssl/bn.h>
#include "rsa.c"
#include "util.c"
#define NBITS 256


int main () 
{

	/*
		Task 2 - Encrypting a message
										*/
	// Assign the private key
	BIGNUM* priv_key = BN_new();
	BN_hex2bn(&priv_key, "74D806F9F3A62BAE331FFE3F0A68AFE35B3D2E4794148AACBC26AA381CD7D30D");

	// Assign the public key
	BIGNUM* pub_key = BN_new();
	BN_hex2bn(&pub_key, "DCBFFE3E51F62E09CE7032E2677A78946A849DC4CDDE3A4D0CB81629242FB1A5");
	printBN("The public key is: ", pub_key);

	// Assign the Modulus
	BIGNUM* mod = BN_new();
	BN_hex2bn(&mod, "010001");
	
	
	BIGNUM* enc = BN_new();
	BIGNUM* dec = BN_new();
	
	
	// We are going to encrypt the message 'A top secret!'.
	// In order to use RSA, first we need to convert this message into hex.
	// Then we can convert the hex into a BIGNUM for the computations.
	BIGNUM* message = BN_new();
	BN_hex2bn(&message, "4120746f702073656372657421");
	
	

	printBN("The plaintext message is: ", message);
	enc = rsa_encrypt(message, mod, pub_key);
	printBN("The encrypted message is: ", enc);
	dec = rsa_decrypt(enc, priv_key, pub_key);
	printf("The decrypted message is: ");
	printHX(BN_bn2hex(dec));
	printf("\n");
	
	

}
