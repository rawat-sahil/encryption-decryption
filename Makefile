flags=-g -lcrypto
dependecy= helper.h
helperfunction=helper.o
all:gen_rand fput_encrypt_rsa fget_decrypt_rsa


%.o:%.cpp $(depends)
	g++ $^ $(flags) -c -o $@

gen_rand:gen_rand.o $(helperfunction)
	g++ $^ $(flags) -o $@
	sudo chmod u+s $@

fput_encrypt_rsa:$(helperfunction) fput_encrypt_rsa.o
	g++ $^ $(flags) -o $@
	sudo chmod u+s $@


fget_decrypt_rsa:$(helperfunction) fget_decrypt_rsa.o
	g++ $^ $(flags) -o $@
	sudo chmod u+s $@


clean:
	-rm *o gen_rand fput_encrypt_rsa fget_decrypt_rsa randfile something something.sign
