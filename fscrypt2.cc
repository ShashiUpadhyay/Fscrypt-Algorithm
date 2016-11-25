
#include <iostream>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "fscrypt.h"

#define TEXTARRAYDEFAULTSIZE 100
#define PERMISSIBLE_KEY_SIZE 16 // 16 Bytes = 128 Bits (Permissible size)

/* Global Variables */
BF_KEY* bf_key_global_ptr;
unsigned char *plainText;
unsigned char *cipherText_ptr_global;
unsigned char *pointersubstr;
unsigned char *plaintext_substr_ptr;
unsigned char *pointer_XOR_ptr;
unsigned char *initializationvector;
unsigned char *recvbuf_decrypt;
unsigned char **blocks;
unsigned char **cipherblocks;
unsigned char **textpostxor;
int numberOfBlocks = 0;
int plainTextLength = 0;
/* Initialised varible for cbc scenario */
unsigned char *cbc_ivec;

void freeMemory2D(unsigned char **allocatedIn, int arraySizeIn) {
	int i;
	for (i = 0; i < arraySizeIn; i++) {
		free(allocatedIn[i]);
	}
	free(allocatedIn);
}

void deAllocateMemory() {
	freeMemory2D(blocks, numberOfBlocks);
	freeMemory2D(cipherblocks, numberOfBlocks);
	freeMemory2D(textpostxor, numberOfBlocks);
	free(bf_key_global_ptr);
	free(cbc_ivec);
	free(pointersubstr);
	free(cipherText_ptr_global);
	free(pointer_XOR_ptr);
	free(initializationvector);
	free(plaintext_substr_ptr);
}

unsigned char *allocateMemory1D(int sizeIn) {
	unsigned char *allocate;
	allocate = (unsigned char*) (calloc(sizeIn, sizeof(char)));
	return allocate;
}

unsigned char **allocateMemory2D(int arraySizeIn, int arrayofArraySizeIn) {
	unsigned char **allocatee;
	allocatee = (unsigned char**) (calloc(arraySizeIn, sizeof(char*)));
	for (int x = 0; x < arraySizeIn; x++) {
		allocatee[x] = (unsigned char*) (calloc(arrayofArraySizeIn,
				sizeof(char)));
	}
	return allocatee;
}

int calculateBlockSize(unsigned char *plainTextIn) {
	plainTextLength = strlen((char *) plainTextIn);
	int text_block = plainTextLength % BLOCKSIZE;
	int block_size = plainTextLength / BLOCKSIZE;
	if (text_block == 0) {
		numberOfBlocks = block_size;
	} else {
		numberOfBlocks = (block_size + 1);
	}
	return numberOfBlocks;
}

void allocateMemoryToVariables(unsigned char* plTextIn) {
	int numberOfBlocks = calculateBlockSize(plTextIn);
	blocks = allocateMemory2D(numberOfBlocks, BLOCKSIZE);
	textpostxor = allocateMemory2D(numberOfBlocks, BLOCKSIZE);
	cipherblocks = allocateMemory2D(numberOfBlocks, BLOCKSIZE);
	initializationvector = allocateMemory1D(BLOCKSIZE);
}

unsigned char* paddingZero(unsigned char* textIn, int lengthIn) {
	for (int i = plainTextLength; i < lengthIn; i++) {
		textIn[i] = 0;
	}
	return textIn;
}

void initialize_cbc_ivec() {
	cbc_ivec = (unsigned char*) (allocateMemory1D(BLOCKSIZE));
	for (int index = 0; index < BLOCKSIZE; index++) {
		cbc_ivec[index] = 'a';
	}
}

BF_KEY* BF_SetKey_Encrypt(int i, char* keystr, int enc_dec_scenario) {
	bf_key_global_ptr = (BF_KEY*) allocateMemory1D(1 * sizeof(BF_KEY));
	BF_set_key(bf_key_global_ptr, BLOCKSIZE, (const unsigned char*) (keystr));
	initialize_cbc_ivec();
	if (enc_dec_scenario == BF_ENCRYPT) {
		BF_cbc_encrypt((const unsigned char*) (textpostxor[i]), cipherblocks[i],
				sizeof(textpostxor[i]), bf_key_global_ptr, cbc_ivec,
				BF_ENCRYPT);
	} else if (enc_dec_scenario == BF_DECRYPT) {
		BF_cbc_encrypt((const unsigned char *) cipherblocks[i], blocks[i],
				sizeof(cipherblocks[i]), bf_key_global_ptr, cbc_ivec,
				BF_DECRYPT);
	}
	return bf_key_global_ptr;
}

unsigned char *copingStringIntoNewString(unsigned char *textIn,
		int firstsetsize_In, int secindsetsize_In) {
	pointersubstr = allocateMemory1D(secindsetsize_In + 1);
	int index;
	for (index = 0; index < firstsetsize_In; index++) {
		textIn++;
	}
	for (index = 0; index < secindsetsize_In; index++) {
		*(pointersubstr + index) = *textIn;
		textIn++;
	}
	*(pointersubstr + index) = '\0';
	return pointersubstr;
}

void addingCopiedStringInBlocks() {
	if (blocks != NULL) {
		for (int i = 0; i < numberOfBlocks; i++) {
			blocks[i] = copingStringIntoNewString(plaintext_substr_ptr,
					i * BLOCKSIZE, BLOCKSIZE);
		}
	}
}

void splitStringInSubStrings_further(
		char initial_text_array[TEXTARRAYDEFAULTSIZE], int blocksizeleftover,
		int total_length, int textlength, unsigned char* textIn) {
	sprintf(initial_text_array, "%d", blocksizeleftover);
	plaintext_substr_ptr = allocateMemory1D(total_length);
	plaintext_substr_ptr = textIn;
	for (int i = textlength; i < total_length; i++) {
		strcat((char*) (plaintext_substr_ptr), initial_text_array);
	}
	addingCopiedStringInBlocks();
}

void splitStringInSubStrings(unsigned char *textIn) {
	int blocksizeleftover = 0, total_length = 0;
	int textlength = strlen((char *) textIn);
	int text_block = textlength % BLOCKSIZE;
	char initial_text_array[TEXTARRAYDEFAULTSIZE];
	if (text_block == 0) {
		total_length = textlength;
	} else {
		blocksizeleftover = (BLOCKSIZE - text_block);
		total_length = textlength + blocksizeleftover;
	}
	splitStringInSubStrings_further(initial_text_array, blocksizeleftover,
			total_length, textlength, textIn);
}

void XOR_Operation(size_t blocklength, unsigned char* blockIn,
		unsigned char* initialvector_In) {
	for (int i = 0; i < blocklength; i++) {
		pointer_XOR_ptr[i] = (blockIn[i] ^ initialvector_In[i]);
	}
}

unsigned char* performXOROperation(unsigned char* blockIn,
		unsigned char* initialvector_In) {
	size_t blocklength = strlen((char *) blockIn);
	size_t keylength = strlen((char *) initializationvector);
	pointer_XOR_ptr = allocateMemory1D(blocklength + 1);
	XOR_Operation(blocklength, blockIn, initialvector_In);
	return pointer_XOR_ptr;
}

void performXORonDATA(int index_In) {
	if (index_In == 0) {
		textpostxor[index_In] = performXOROperation(blocks[index_In],
				initializationvector);
	} else {
		textpostxor[index_In] = performXOROperation(blocks[index_In],
				cipherblocks[index_In - 1]);
	}
}

void perform_Key_XOR_STRCAT(int buffersize_In, char* keystr_In,
		unsigned char* recvbuf_In, int scenarioIn) {
	if (scenarioIn == BF_ENCRYPT) {
		for (int i = 0; i < numberOfBlocks; i++) {
			performXORonDATA(i);
			BF_KEY* bf_key = BF_SetKey_Encrypt(i, keystr_In, BF_ENCRYPT);
			strncat((char*) (cipherText_ptr_global),
					(const char*) (cipherblocks[i]), buffersize_In + 1);
		}
	} else if (scenarioIn == BF_DECRYPT) {
		for (int i = 0; i < numberOfBlocks; i++) {
			BF_KEY* bf_key = BF_SetKey_Encrypt(i, keystr_In, BF_DECRYPT);
			performXORonDATA(i);
			strncat((char*) (recvbuf_In), (const char*) (textpostxor[i]),
					buffersize_In + 1);
		}
	}
}

bool validateKeySize(char* key_In) {
	bool isValid = false;
	int key_Size = (strlen((char*) (key_In)) + 1);
	if (key_Size <= PERMISSIBLE_KEY_SIZE) {
		isValid = true;
	} else {
		isValid = false;
	}
	return isValid;
}

void* fs_encrypt(void *inputtext_In, int buffersize_In, char *key_In,
		int *resultlen_In) {
	unsigned char *recvbuf;
	int length_encrytedText = 0;
	if (!validateKeySize(key_In)) {
		printf("%s \n", "Information : Permissible size of key should be 128 bits");
	}
	plainText = (unsigned char*) inputtext_In;
	cipherText_ptr_global = allocateMemory1D(buffersize_In + 1);
	allocateMemoryToVariables(plainText);
	splitStringInSubStrings(plainText);
	perform_Key_XOR_STRCAT(buffersize_In, key_In, recvbuf, BF_ENCRYPT);
	length_encrytedText = strlen((char *) cipherText_ptr_global);
	plainText = paddingZero(plainText, length_encrytedText);
	*resultlen_In = strlen((char *) cipherText_ptr_global);
	return (void *) cipherText_ptr_global;
}

void *fs_decrypt(void *ciphertext_In, int buffersize_In, char *key_In,
		int *recvlen_In) {
	int len = 0;
	if (!validateKeySize(key_In)) {
		printf("%s \n", "Information : Permissible size of key should be 128 bits");
	}
	recvbuf_decrypt = allocateMemory1D(buffersize_In + 1);
	splitStringInSubStrings((unsigned char *) ciphertext_In);
	perform_Key_XOR_STRCAT(buffersize_In, key_In, recvbuf_decrypt,
	BF_DECRYPT);
	len = strlen((char *) recvbuf_decrypt);
	recvbuf_decrypt = paddingZero(recvbuf_decrypt, len);
	*recvlen_In = strlen((char *) recvbuf_decrypt) + 1;
//	deAllocateMemory();
	return (void *) recvbuf_decrypt;
}
