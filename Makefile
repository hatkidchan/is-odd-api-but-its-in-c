

main:
	$(CC) main.c -o main -lmongoose -O2 $(CFLAGS)

clean:
	$(RM) main
