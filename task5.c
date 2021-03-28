#include <stdio.h>
#include <openssl/bn.h>
#include "rsa.c"
#include "util.c"
#define NBITS 256


int main () 
{
	/*
		Task 5 - Verifying a signature
										*/
	// In this task, we are going to verify a signature.
	// So we will use our public key to decrypt a message 
	// that has been encrypted with the private key,
	// And then compare the message with our decrypted result.
	BIGNUM* BN_task5 = BN_new();
	BIGNUM* S = BN_new();
	BN_hex2bn(&BN_task5, "4c61756e63682061206d6973736c652e");
	
	BIGNUM* pub_key = BN_new();
	BN_hex2bn(&pub_key, "AE1CD4DC432798D933779FBD46C6E1247F0CF1233595113AA51B450F18116115");
	BN_hex2bn(&S, "643D6F34902D9C7EC90CB0B2BCA36C47FA37165C0005CAB026C0542CBDB6802F");
	
	// Assign the Modulus
	BIGNUM* mod = BN_new();
	BN_hex2bn(&mod, "010001");
	
	
	// Here we decrypt the message with the public key.
	BIGNUM* dec = BN_new();
	dec = rsa_decrypt(S, mod, pub_key);
	printf("The message for task5 is: ");
	
	printHX(BN_bn2hex(dec));
	printf("\n");
	
	printf("The corrupted message with the public key is: ");
	printf("\n");

	// Now we corrupt the signature, and try to verify again.
	BN_hex2bn(&S, "643D6F34902D9C7EC90CB0B2BCA36C47FA37165C0005CAB026C0542CBDB6803F");
	
	// Here we decrypt a corrupted message with the public key.
	dec = rsa_decrypt(S, mod, pub_key);
	printf("The message for task5 is: ");
	
	// We should see a corrupted output here.
	printHX(BN_bn2hex(dec));
	printf("\n");


}
