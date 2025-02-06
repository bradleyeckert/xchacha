test: test.c ./src/xchacha.c
	gcc -o test test.c ./src/xchacha.c -I./src
