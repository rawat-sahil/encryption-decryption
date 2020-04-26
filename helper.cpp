//
// Created by ra_watt on 4/25/20.
//
#include"helper.h"



void fsign(std::string filename,std::string privatekeyFile){
    std::fstream myfile;
    myfile.open(privatekeyFile,std::ios::in);
    std::string privatekey,line;
    if (myfile.is_open())
    {
        while ( getline (myfile,line) )
        {
            privatekey.append(line);
            privatekey.append("\n");
        }
        myfile.close();
    }
//    std::cout<<privatekey;
    RSA *rsa=NULL;
    BIO * keybio = BIO_new_mem_buf((void*)privatekey.c_str(), -1);
    rsa = PEM_read_bio_RSAPrivateKey(keybio, &rsa,NULL, NULL);
    myfile.close();

    struct stat statbuf;
    check_file_exist(filename, &statbuf);

    myfile.open(filename.c_str(),std::ios::in);
    std::string wholefile,signatureFile;
    signatureFile=std::string(filename);
    signatureFile.append(".sign");
    if (myfile.is_open())
    {
        while ( getline (myfile,line) )
        {
            wholefile.append(line);
        }
        myfile.close();
    }

    int fd=creat(signatureFile.c_str(),0664);
    fchown(fd,statbuf.st_uid,statbuf.st_gid);
    close(fd);
    myfile.open(signatureFile.c_str(),std::ios::out|std::ios::binary);

    unsigned char * EncMsg;
    size_t MsgLenEnc;
   std::cout<<RSASign(rsa,(const unsigned char *)wholefile.c_str(),strlen(wholefile.c_str()),&EncMsg,&MsgLenEnc);
//   std::cout<<"after sign\n";
    EncMsg[MsgLenEnc]='\0';
//    std::cout<<"hmac length"<<MsgLenEnc<<"  size  "<<strlen((char*)EncMsg)<<" \n";
//    std::cout<<"hmac "<<EncMsg<<"\n";
   myfile.write((char *)EncMsg,MsgLenEnc);
    myfile.close();
}
void fverify(std::string filename,std::string publickeyFile){
    check_read_permission(filename);
    std::fstream myfile;
    myfile.open(publickeyFile,std::ios::in);
    std::string publickey,line;
    if (myfile.is_open())
    {
        while ( getline (myfile,line) )
        {
            publickey.append(line);
            publickey.append("\n");
        }
        myfile.close();
    }
//    std::cout<<publickey;
    RSA *rsa=NULL;
    BIO * keybio = BIO_new_mem_buf((void*)publickey.c_str(), -1);
    rsa = PEM_read_bio_RSA_PUBKEY(keybio, &rsa,NULL, NULL);
//    std::cout<<"rsa converted\n";

    std::string signatureFile;
    char  wholefile[256];
    signatureFile=std::string(filename);
    signatureFile.append(".sign");
    check_read_permission(signatureFile);
    myfile.open(signatureFile.c_str(),std::ios::in);
    myfile.read(wholefile,256);
//    std::cout<<wholefile<<"\n";
    myfile.close();

    std::string encrypted_text;
    myfile.open(filename,std::ios::in);
    if (myfile.is_open())
    {
        while ( getline (myfile,line) )
        {
            encrypted_text.append(line);
        }
        myfile.close();
    }

//    myfile.open("temp.txt",std::ios::out);
//    myfile<<wholefile;
//    myfile.close();




//    std::cout<<"encrypted_text "<<wholefile<<"\n";
//    std::cout<<"length as calculated by strlen"<<strlen(wholefile)<<"\n";
    bool authentic,result;
    result=RSAVerifySignature(rsa,(unsigned char *)wholefile,256,encrypted_text.c_str(),strlen(encrypted_text.c_str()),&authentic);
//    std::cout<<"result "<<result<<"  authentic "<<authentic<<std::endl;
    if(authentic){
        std::cout<<"rsa hmac verified\n";
    } else{
        std::cout<<"rsa hmac verification failed\n";
        exit(-1);
    }

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
//    std::cout<<"random key"<<randkey<<"\n";

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

int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,unsigned char *iv, unsigned char *plaintext){
    EVP_CIPHER_CTX *ctx;

    int len;

    int plaintext_len;

    // Create and initialise the context
    ctx = EVP_CIPHER_CTX_new();

    //decrypt initialisation using aes 256 ecb
    EVP_DecryptInit_ex(ctx, EVP_aes_256_ecb(), NULL, key, iv);

    EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len);
    plaintext_len = len;
    EVP_DecryptFinal_ex(ctx, plaintext + len, &len);
    plaintext_len += len;
    EVP_CIPHER_CTX_free(ctx);

    return plaintext_len;
}
int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
            unsigned char *iv, unsigned char *ciphertext){
    EVP_CIPHER_CTX *ctx;

    int len;

    int ciphertext_len;
    ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_256_ecb(), NULL, key, iv);
    EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len);
    ciphertext_len = len;
    EVP_EncryptFinal_ex(ctx, ciphertext + len, &len);
    ciphertext_len += len;
    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}

bool RSASign( RSA* rsa,const unsigned char* Msg,size_t MsgLen,unsigned char** EncMsg,size_t* MsgLenEnc) {
    EVP_MD_CTX* m_RSASignCtx = EVP_MD_CTX_create();
    EVP_PKEY* priKey  = EVP_PKEY_new();
    EVP_PKEY_assign_RSA(priKey, rsa);
    if (EVP_DigestSignInit(m_RSASignCtx,NULL, EVP_sha256(), NULL,priKey)<=0) {
        return false;
    }
    if (EVP_DigestSignUpdate(m_RSASignCtx, Msg, MsgLen) <= 0) {
        return false;
    }
    if (EVP_DigestSignFinal(m_RSASignCtx, NULL, MsgLenEnc) <=0) {
        return false;
    }
    *EncMsg = (unsigned char*)malloc(*MsgLenEnc);
    if (EVP_DigestSignFinal(m_RSASignCtx, *EncMsg, MsgLenEnc) <= 0) {
        return false;
    }return true;
}

bool RSAVerifySignature( RSA* rsa,unsigned char* MsgHash,size_t MsgHashLen,const char* Msg,size_t MsgLen,bool* Authentic) {
    *Authentic = false;
    EVP_PKEY* pubKey  = EVP_PKEY_new();
    EVP_PKEY_assign_RSA(pubKey, rsa);
    EVP_MD_CTX* m_RSAVerifyCtx = EVP_MD_CTX_create();

    if (EVP_DigestVerifyInit(m_RSAVerifyCtx,NULL, EVP_sha256(),NULL,pubKey)<=0) {
        return false;
    }
    if (EVP_DigestVerifyUpdate(m_RSAVerifyCtx, Msg, MsgLen) <= 0) {
        return false;
    }
    int AuthStatus = EVP_DigestVerifyFinal(m_RSAVerifyCtx, MsgHash, MsgHashLen);
    if (AuthStatus==1) {
        *Authentic = true;

        return true;
    } else if(AuthStatus==0){
        *Authentic = false;

        return true;
    } else{
        *Authentic = false;

        return false;
    }
}