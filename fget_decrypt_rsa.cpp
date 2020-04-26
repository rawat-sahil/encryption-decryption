//
// Created by ra_watt on 4/25/20.
//

#include "helper.h"

void fget_decrypt_rsa(std::string randomfile,std::string publickeyFile,std::string filename){
    check_read_permission(randomfile);
    check_read_permission(filename); // exits the program either the file does not exist or does not have read permission
    unsigned char key[33];
    unsigned char iv[17] ;
    struct stat statbuf;
    check_file_exist(filename, &statbuf);
    get_key_iv(key,iv,statbuf.st_uid,randomfile);
//    std::cout<<key<<"    "<<iv<<"\n";

    unsigned char decryptedtext[200];
    int  decryptedtext_len;


    fverify(filename,publickeyFile);
    std::ifstream myfile;
    myfile.open(filename.c_str());
    std::string line;
    if (myfile.is_open())
    {
        while ( getline (myfile,line) )
        {
//            std::cout<<(unsigned char *)line.c_str()<<"\n";
            decryptedtext_len=decrypt((unsigned char *)line.c_str(),strlen(line.c_str()),key,iv,decryptedtext);
            decryptedtext[decryptedtext_len]='\0';
            std::cout<<decryptedtext<<std::endl;
        }
        myfile.close();
    }

    else std::cout << "Unable to open file";
}



int main(int argc ,char*argv[]){
    if(argc==1){
        std::cout<<"file name is required"<<std::endl;
        return(-1);
    }
    fget_decrypt_rsa(std::string(argv[1]),std::string(argv[2]),std::string(argv[3]));
}