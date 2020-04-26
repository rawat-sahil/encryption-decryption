//
// Created by ra_watt on 4/25/20.
//

#ifndef SE_ASSIGNMENT_4_HELPER_H
#define SE_ASSIGNMENT_4_HELPER_H
#include<iostream>
#include <stdlib.h>
#include<string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include<fcntl.h>
#include<errno.h>
#include <fstream>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include<openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/aes.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include<shadow.h>
#include <pwd.h>
bool RSASign( RSA* rsa,const unsigned char* Msg,size_t MsgLen,unsigned char** EncMsg,size_t* MsgLenEnc);
bool RSAVerifySignature( RSA* rsa,unsigned char* MsgHash,size_t MsgHashLen,const char* Msg,size_t MsgLen,bool* Authentic);
void fsign(std::string filename,std::string privatekeyFile);
void fverify(std::string filename,std::string publickeyFile);
void get_key_iv(unsigned char * key,unsigned char *iv,int uid);
void gen_rand(std::string filename);
int check_file_exist(std::string filename,struct stat *statbuf);
int check_read_permission(std::string filename);
int check_write_permission(std::string filename);
void get_key_iv(unsigned char *key, unsigned char *iv,int uid,std::string randomfile);
void handleErrors();
int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,unsigned char *iv, unsigned char *plaintext);
int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,unsigned char *iv, unsigned char *ciphertext);


#endif //SE_ASSIGNMENT_4_HELPER_H
