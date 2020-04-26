//
// Created by ra_watt on 4/25/20.
//

#include "helper.h"

void fput_encrypt_rsa(std::string randomfile,std::string privatkeyFile,std::string filename){
    /* A 256 bit key */
    unsigned char key[33];

    /* A 128 bit IV */
    unsigned char iv[17] ;

//    std::cout<<key<<"    "<<iv<<"\n";

    struct stat statbuf;
    std::fstream myfile;
    std::string temp;
    unsigned char ciphertext[200];
    int ciphertext_len;
    if (check_file_exist(filename, &statbuf) == 1) { //check whether file exist or not
        get_key_iv(key,iv,statbuf.st_uid,randomfile);
        check_write_permission(filename);// exits the program if the file does not have write permission for the user

        myfile.open(filename.c_str(), std::ios::app);

        std::getline(std::cin, temp);
        while (temp.compare("//end") != 0) {
            ciphertext_len = encrypt((unsigned char *)temp.c_str(), strlen(temp.c_str()), key, iv, ciphertext);
            ciphertext[ciphertext_len]='\0';
            myfile << ciphertext << "\n";
            std::getline(std::cin, temp);
        }
        myfile.close();
    }
    else { //if file does not exist create one
        get_key_iv(key,iv,getuid(),randomfile);

        int fd=creat(filename.c_str(),0664);
        fchown(fd,getuid(),getgid());
        close(fd);


        myfile.open(filename.c_str(), std::ios::out);
        if (!myfile) {
            std::cout << "Error in creating file!!!" << std::endl;
            exit(-1);
        }

        std::getline(std::cin, temp);
        while (temp.compare("//end") != 0) {
            ciphertext_len = encrypt((unsigned char *)temp.c_str(), strlen(temp.c_str()), key, iv, ciphertext);
//            std::cout<<ciphertext<<"   before\n";
            ciphertext[ciphertext_len]='\0';
//            std::cout<<ciphertext<<"   after\n";
            myfile << ciphertext << "\n";
            std::getline(std::cin, temp);
        }
        myfile.close();



    }
    fsign(filename,privatkeyFile);
}

int main(int argc ,char*argv[]){
    if(argc==1){
        std::cout<<"file name is required"<<std::endl;
        return(-1);
    }
    fput_encrypt_rsa(std::string(argv[1]),std::string(argv[2]),std::string(argv[3]));
}