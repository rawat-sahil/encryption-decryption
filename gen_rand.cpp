//
// Created by ra_watt on 4/25/20.
//
#include "helper.h"
#include <sstream>


void gen_rand(std::string string_num,std::string filename){
    std::fstream myfile;
    std::stringstream temp(string_num);
    int num;
    temp>>num;
    unsigned char key[33],iv[17];
    get_key_iv(key,iv,getuid());

    unsigned char  buff[100],ciphertext[100];
    RAND_priv_bytes(buff,num);
    buff[num]='\0';

    int cipher_len=   encrypt(buff,strlen((char*)buff),key,iv,ciphertext);
    ciphertext[cipher_len]='\0';



    int fd=creat(filename.c_str(),0644);
    fchown(fd,getuid(),getgid());
    close(fd);
    myfile.open(filename.c_str(),std::ios::out|std::ios::binary);
    myfile<<ciphertext<<"\n";
//    std::cout<<"random key "<<buff<<"\n";
//    std::cout<<"encrypted random key "<<ciphertext<<"\n";
    myfile.close();


    myfile.open(filename.c_str(),std::ios::in);
    std::string yoboi;
    getline(myfile,yoboi);
    std::cout<<"random key "<<buff<<" "<<strlen((char*)buff)<<"\n";
    std::cout<<"encrypted random key "<<ciphertext<<" "<<strlen((char *)ciphertext)<<"\n";
    std::cout<<"read from file "<<yoboi<<" "<<strlen(yoboi.c_str())<<"\n";
    unsigned  char expected[100];
//    expected[num+1]='\0';
    int expected_len=decrypt((unsigned char *)yoboi.c_str(),strlen(yoboi.c_str()),key,iv,expected);
    expected[expected_len]='\0';
    std::cout<<"decrypted  "<<expected<<" "<<strlen((char *)expected)<<"\n";
}
int main(int argc,char * argv[]){
    if(argc==1){
        std::cout<<"file name is required"<<std::endl;
        return(-1);
    }
    gen_rand(std::string(argv[1]),std::string(argv[2]));
}
