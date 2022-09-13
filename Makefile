

main:
	$(CC) main.c mongoose.c -o main -I. -O2 -lpthread $(CFLAGS)

anarchy:
	$(CC) main.c mongoose.c -o main -I. -O2 -DALLOCATE_EVERYTHING=1 -lpthread $(CFLAGS)

clean:
	$(RM) main
