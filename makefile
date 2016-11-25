all: compile_main compile_extra execute_main execute_extra

compile_main:
	g++ -g main.cc fscrypt.cc -lcrypto -o fscrypt.out

compile_extra:
	g++ -g main.cc fscrypt2.cc -lcrypto -o fscrypt2.out

execute_main:
	./fscrypt.out

execute_extra:
	./fscrypt2.out

clean:
	rm -rf *.out
	rm -rf *._