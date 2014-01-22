/*

Find rc632 keys encoded as 12 bytes for flash writing
Dobrica Pavlinusic <dpavlin@rot13.org> 2014-01-22

compile with:

gcc -o mifare_rc632_find_key mifare_rc632_find_key.c

try it out:

mifare_rc632_find_key some_binary_file_with_keys

*/

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>

int main ( int argc, char *argv[] ) {
	FILE *fd;
	char *filename;

	filename = argv[1];

	fd = fopen(filename,"rb");
	if ( fd == NULL ) {
		printf("error opening %s", filename);
		exit(1);
	}

	fseek(fd, 0, SEEK_END);
	long size = ftell(fd);
	fseek(fd, 0, SEEK_SET);

	char *str = malloc( size + 1 );
	fread(str, size, 1, fd);
	fclose(fd);

	int keys_found = 0;

	int i;
	for( i = 0; i <= size; i++ ) {

		bool found = true;
		int j;
		char key[12];

		for ( j = 0; j <= 11; j++ ) {
			char c = str[i + j];

			if ( ( ( ( c & 0xf0 ) ^ 0xf0 ) >> 4 ) != ( c & 0x0f ) ) {
				found = false;
				break;
			}
			key[j] = c;
		}
		if ( found ) {
			printf("%08x: ", i);
			for( j = 0; j <= 11; j++ ) {
				printf("%01x", (unsigned char)key[j] & 0x0f);
			}
			printf(" %s\n", filename);
			keys_found++;
		}

	}
}

