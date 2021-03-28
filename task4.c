#include <stdio.h>
#include <openssl/bn.h>
#include "rsa.c"
#include "util.c"
#define NBITS 256


int main () 
{
	/*
		Task 4 - Signing a message
									*/
	// In this task, we are to generate the signature for a message.
	// The message is "I owe you $2000". First we must convert this to hex.
	// python -c ’print("I owe you $2000".encode("hex"))’
	// Once we have the hex, we convert to a BIGNUM for the computations.
	BIGNUM* BN_task4 = BN_new();
	BN_hex2bn(&BN_task4, "49206f776520796f752024333333332e");
	
	// Assign the private key
	BIGNUM* priv_key = BN_new();
	BN_hex2bn(&priv_key, "74D806F9F3A62BAE331FFE3F0A68AFE35B3D2E4794148AACBC26AA381CD7D30D");

	// Assign the public key
	BIGNUM* pub_key = BN_new();
	BN_hex2bn(&pub_key, "DCBFFE3E51F62E09CE7032E2677A78946A849DC4CDDE3A4D0CB81629242FB1A5");

	// Assign the Modulus
	BIGNUM* mod = BN_new();
	BN_hex2bn(&mod, "010001");
	

	// Since we already have the private key, all we need to do is encrypt.
	BIGNUM* enc = BN_new();
	BIGNUM* dec = BN_new();
	
	enc = rsa_encrypt(BN_task4, priv_key, pub_key);
	printBN("The signature is: ", enc);
	
	// To verify the operations were conducted correctly, we decrypt as well.
	dec = rsa_decrypt(enc, mod, pub_key);
	printf("The message is: ");
	printHX(BN_bn2hex(dec));
	printf("\n");

	
}
