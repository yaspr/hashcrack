CC=gcc

all:
	$(CC) -g3 -Ofast yhashcrack.c -o yhashcrack -lyhash -Lyhash/ -lm -lpthread

run_md5:
	@echo "MD5: Hello"
	@LD_LIBRARY_PATH=yhash/ ./hashcrack -md5 dictionary/passwords.txt 8b1a9953c4611296a827abf8c47804d7 $(NT)

run_sha1:
	@echo "SHA1: Hello"
	@LD_LIBRARY_PATH=yhash/ ./hashcrack -sha1 dictionary/passwords.txt f7ff9e8b7bb2e09b70935a5d785e0cc5d9d0abf0 $(NT)

run_sha224:
	@echo "SHA224: Hello"
	@LD_LIBRARY_PATH=yhash/ ./hashcrack -sha224 dictionary/passwords.txt 4149da18aa8bfc2b1e382c6c26556d01a92c261b6436dad5e3be3fcc $(NT)

run_sha256:
	@echo "SHA256: Hello"
	@LD_LIBRARY_PATH=yhash/ ./hashcrack -sha256 dictionary/passwords.txt 185f8db32271fe25f561a6fc938b2e264306ec304eda518007d1764826381969 $(NT)

run_sha512:
	@echo "SHA512: Hello"
	@LD_LIBRARY_PATH=yhash/ ./hashcrack -sha512 dictionary/passwords.txt 3615f80c9d293ed7402687f94b22d58e529b8cc7916f8fac7fddf7fbd5af4cf777d3d795a7a00a16bf7e7f3fb9561ee9baae480da9fe7a18769e71886b03f315 $(NT)

run_dead256:
	@echo "SHA256: Kojak"
	@LD_LIBRARY_PATH=yhash/ ./hashcrack -sha256 dictionary/passwords.txt aa06d86e3caac2d288d1591d13a414958765b22dd5a3b12b8d46560327ef9c41 $(NT)
	@echo

run_dead512:
	@echo "SHA512: Kojak"
	@LD_LIBRARY_PATH=yhash/ ./hashcrack -sha512 dictionary/passwords.txt 4caf93fc2b76a082c6e8f1a6dd7442792519da79f977e8aaa812ea727b17ba96c3f12ad6f9283ea8e458dfb8e7929c55b0fe30c082843d2dd75c71aa219b9772 $(NT)
	@echo

clean:
	rm -Rf *~ yhashcrack
