

main:
	$(CC) main.c mongoose.c -o main -I. -O2 $(CFLAGS)

anarchy:
	$(CC) main.c mongoose.c -o main -I. -O2 -DALLOCATE_EVERYTHING=1 $(CFLAGS)

clean:
	$(RM) main
