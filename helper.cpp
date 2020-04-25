//
// Created by ra_watt on 4/25/20.
//
#include"helper.h"



void fsign(std::string filename,std::string privatekeyFile){
    std::fstream myfile;
    myfile.open(privatekeyFile,std::ios::in);
    std::string privatekey;
    getline(myfile,privatekey);
    RSA *rsa;
    BIO * keybio = BIO_new_mem_buf((void*)privatekey.c_str(), -1);
    rsa = PEM_read_bio_RSAPrivateKey(keybio, &rsa,NULL, NULL);
}
void fverify(std::string filename,std::string publickeyFile){

}

void get_key_iv(unsigned char *key, unsigned char *iv,int uid,std::string randomfile){
    /* A 256 bit key */
    unsigned char randkey[33];

    /* A 128 bit IV */
    unsigned char randiv[17] ;
    get_key_iv(randkey,randiv,uid);

    std::fstream myfile;
        myfile.open(randomfile.c_str(),std::ios::in);
    std::string encrypted_randomkey;
    getline(myfile,encrypted_randomkey);
    unsigned  char randomkey[100];
//    std::cout<<"enter\n";
    int random_key_len=decrypt((unsigned char *)encrypted_randomkey.c_str(),strlen(encrypted_randomkey.c_str()),randkey,randiv,randomkey);
    randomkey[random_key_len]='\0';
    std::cout<<"random key"<<randkey<<"\n";

    unsigned char out[200];
    int len=49;
    std::cout << PKCS5_PBKDF2_HMAC_SHA1((const char *)randkey, strlen((char *)randkey), nullptr, 0, 1000, len, out) << std::endl;
    out[len]='\0';
//    std::cout << out <<strlen((char *)out)<< "\n";

    strncpy((char*)key,(char *)out,32);
    key[32]='\0';
    strncpy((char*)iv,(char *)(out+32),17);
    iv[17]='\0';

}

void get_key_iv(unsigned char *key,unsigned char *iv,int uid){
    char * username=getpwuid(uid)->pw_name;
    char* hashed_password=getspnam(username)->sp_pwdp;
//    std::cout<<hashed_password<<"  len:"<<strlen(hashed_password)<<"\n";
    unsigned char out[200];
    int len=49;
    std::cout << PKCS5_PBKDF2_HMAC_SHA1(hashed_password, strlen(hashed_password), nullptr, 0, 1000, len, out) << std::endl;
    out[len]='\0';
//    std::cout << out <<strlen((char *)out)<< "\n";

    strncpy((char*)key,(char *)out,32);
    key[32]='\0';
    strncpy((char*)iv,(char *)(out+32),17);
    iv[17]='\0';

//    std::cout<<"finished"<<std::endl;
}


int check_file_exist(std::string filename,struct stat *statbuf){ // return 1 if file exist
    int value=stat(filename.c_str(),statbuf);
    if(value==0)return 1;
    return 0;
}

int check_read_permission(std::string filename){
    int permission=access(filename.c_str(),R_OK);
    if(permission==0)return 1;
    std::cout<<"error occured  "<<strerror(errno)<<std::endl;
    exit(errno);
}

int check_write_permission(std::string filename){
    int permission=access(filename.c_str(),W_OK);
    if(permission==0)return 1;
    std::cout<<"error occured  "<<strerror(errno)<<std::endl;
    exit(errno);
}

void handleErrors(void)
{
    ERR_print_errors_fp(stderr);
    abort();
}

int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
            unsigned char *iv, unsigned char *plaintext){
    EVP_CIPHER_CTX *ctx;

    int len;

    int plaintext_len;

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors();

    /*
     * Initialise the decryption operation. IMPORTANT - ensure you use a key
     * and IV size appropriate for your cipher
     * In this example we are using 256 bit AES (i.e. a 256 bit key). The
     * IV size for *most* modes is the same as the block size. For AES this
     * is 128 bits
     */
    if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_ecb(), NULL, key, iv))
        handleErrors();

    /*
     * Provide the message to be decrypted, and obtain the plaintext output.
     * EVP_DecryptUpdate can be called multiple times if necessary.
     */
    if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
        handleErrors();
    plaintext_len = len;

    /*
     * Finalise the decryption. Further plaintext bytes may be written at
     * this stage.
     */
    if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len))
        handleErrors();
    plaintext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return plaintext_len;
}
int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
            unsigned char *iv, unsigned char *ciphertext){
    EVP_CIPHER_CTX *ctx;

    int len;

    int ciphertext_len;

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors();

    /*
     * Initialise the encryption operation. IMPORTANT - ensure you use a key
     * and IV size appropriate for your cipher
     * In this example we are using 256 bit AES (i.e. a 256 bit key). The
     * IV size for *most* modes is the same as the block size. For AES this
     * is 128 bits
     */
    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_ecb(), NULL, key, iv))
        handleErrors();

    /*
     * Provide the message to be encrypted, and obtain the encrypted output.
     * EVP_EncryptUpdate can be called multiple times if necessary
     */
    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
        handleErrors();
    ciphertext_len = len;

    /*
     * Finalise the encryption. Further ciphertext bytes may be written at
     * this stage.
     */
    if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
        handleErrors();
    ciphertext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}

