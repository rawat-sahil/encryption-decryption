//
// Created by ra_watt on 4/25/20.
//

#include "helper.h"


int main(int argc ,char*argv[]){
    if(argc==1){
        std::cout<<"file name is required"<<std::endl;
        return(-1);
    }
    fput(std::string(argv[1]));
}