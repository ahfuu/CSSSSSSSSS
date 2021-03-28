#include <stdio.h>
#include <openssl/bn.h>
#include "rsa.c"
#include "util.c"
#define NBITS 256


int main () 
{
	/*
		Task 1 - Deriving a private key
											*/
	
	BIGNUM *p = BN_new();
	BIGNUM *q = BN_new();
	BIGNUM *e = BN_new();
	
	// Assign the first large prime
	BN_hex2bn(&p, "F7E75FDC469067FFDC4E847C51F452DF");
	
	// Assign the second large prime
	BN_hex2bn(&q, "E85CED54AF57E53E092113E62F436F4F");
	
	// Assign the Modulus
	BN_hex2bn(&e, "0D88C3");
		

	BIGNUM* priv_key1 = get_rsa_priv_key(p, q, e);
	printBN("The private key is:", priv_key1);

	
	printf("\n");

}
