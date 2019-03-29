#include <string>
#include <fstream>
#include <iostream>
#include <openssl/rsa.h>
#include <openssl/pem.h>
//Comment next line on linux-base OS
#include <openssl/applink.c>
#include <openssl/err.h>

#define PRIKEY_FILENAME "private"
#define PUBKEY_FILENAME "public"

using namespace std;

bool ReadFileContent(string fileName, char** out, size_t& nLen)
{
	if (NULL == out)
		return false;

	ifstream file(fileName, ios::in | ios::binary | ios::ate);
	if (file.is_open())
	{
		nLen = (int)file.tellg();
		*out = new char[nLen];
		file.seekg(0, ios::beg);
		file.read(*out, nLen);

		file.close();
	}
	else
	{
		cout << "Unable to open file \"" << fileName << " \"\n";
		return false;
	}
	return true;
}

bool WriteFileContent(const char* data, int nLen, string fileName)
{
	if (NULL == data)
		return false;

	ofstream file(fileName, ios::out | ios::binary | ios::ate);
	if (file.is_open())
	{
		file.write(data, nLen);
		file.close();
	}
	else
	{
		cout << "Unable to open file \"" << fileName << " \"\n";
		return false;
	}
	return true;
}

bool GenerateKeyPairs()
{
	int             ret = 0;
	RSA* r = NULL;
	BIGNUM* bne = NULL;
	BIO* bp_public = NULL, * bp_private = NULL;

	int             bits = 2048;
	unsigned long   e = RSA_F4;

	// 1. generate rsa key
	bne = BN_new();
	ret = BN_set_word(bne, e);
	if (ret != 1)
	{
		goto free_all;
	}

	r = RSA_new();
	ret = RSA_generate_key_ex(r, bits, bne, NULL);
	if (ret != 1)
	{
		goto free_all;
	}

	// 2. save public key
	bp_public = BIO_new_file(PUBKEY_FILENAME, "w+");
	ret = PEM_write_bio_RSAPublicKey(bp_public, r);
	if (ret != 1)
	{
		goto free_all;
	}

	// 3. save private key
	bp_private = BIO_new_file(PRIKEY_FILENAME, "w+");
	ret = PEM_write_bio_RSAPrivateKey(bp_private, r, NULL, NULL, 0, NULL, NULL);

	// 4. free
free_all:

	BIO_free_all(bp_public);
	BIO_free_all(bp_private);
	RSA_free(r);
	BN_free(bne);

	return (ret == 1);
}

bool DoSign(string priKeyFile, string fileName)
{
	int     ret;
	unsigned char* data = NULL;
	unsigned char* encodedData = NULL;
	size_t  nFileSize = 0;

	RSA* priKey = NULL;
	FILE* fp = NULL;

	if (!ReadFileContent(fileName, (char**)& data, nFileSize))
	{
		return false;
	}

	if (data == NULL || nFileSize <= 0)
		return false;

	fp = fopen(PRIKEY_FILENAME, "r");
	if (NULL == fp)
	{
		delete[] data;
		return false;
	}

	priKey = PEM_read_RSAPrivateKey(fp, &priKey, NULL, NULL);
	if (NULL == priKey)
	{
		fclose(fp);
		delete[] data;
		return false;
	}
	fclose(fp);

	unsigned char*  sig = new unsigned char[RSA_size(priKey)];
	unsigned int nLen = 0;

	/* Sign */
	ret = RSA_sign(NID_sha512, data, (unsigned int)nFileSize, sig, &nLen, priKey);
	if (1 != ret)
	{
		delete[] data;
		return false;
	}

	delete[] data;

	if (!WriteFileContent((char*)sig, nLen, fileName + ".sign"))
	{
		delete[] sig;
		return false;
	}

	cout << "Signed Successfully.\n";
	delete[] sig;
	return true;
}

bool DoVerify(string pubKeyFile, string fileName, string signature)
{
	int ret = 0;
	unsigned char* data = NULL;
	size_t  nFileSize = 0;
	FILE* fp = NULL;
	RSA* pubkey = NULL;

	unsigned char* sigData = NULL;
	size_t  nSigLen = 0;

	if (!ReadFileContent(fileName, (char**)& data, nFileSize))
	{
		return false;
	}

	if (data == NULL || nFileSize <= 0)
		return false;

	if (!ReadFileContent(signature, (char**)& sigData, nSigLen))
	{
		delete[] data;
		return false;
	}

	if (sigData == NULL || nSigLen <= 0)
	{
		delete[] data;
		return false;
	}

	fp = fopen(PUBKEY_FILENAME, "r");
	if (NULL == fp)
	{
		delete[] data;
		delete[] sigData;
		return false;
	}

	pubkey = PEM_read_RSAPublicKey(fp, NULL, NULL, NULL);
	if (NULL == pubkey)
	{
		fclose(fp);
		delete[] data;
		delete[] sigData;
		return false;
	}
	fclose(fp);

	ret = RSA_verify(NID_sha512, data, (unsigned int)nFileSize, sigData, (unsigned int)nSigLen, pubkey);
	if (ret != 1)
	{
		delete[] data;
		delete[] sigData;
		return false;
	}

	cout << "Verified Successfully\n";
	delete[] data;
	delete[] sigData;
	return true;
}

int main()
{
	if (!GenerateKeyPairs())
	{
		cout << "Error with generating keys.\n";
	}
	else
	{
		if (DoSign(PRIKEY_FILENAME, "Hello.txt"))
		{
			if (!DoVerify(PUBKEY_FILENAME, "Hello.txt", "Hello.txt.sign"))
			{
				cout << "Error with verifying.\n";
			}
		}
		else
		{
			cout << "Error with signing.\n";
		}
	}
	return 0;
}