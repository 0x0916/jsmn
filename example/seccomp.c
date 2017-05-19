#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include "../jsmn.h"

/* Function realloc_it() is a wrapper function for standart realloc()
 * with one difference - it frees old memory pointer in case of realloc
 * failure. Thus, DO NOT use old data pointer in anyway after call to
 * realloc_it(). If your code has some kind of fallback algorithm if
 * memory can't be re-allocated - use standart realloc() instead.
 */
static inline void *realloc_it(void *ptrmem, size_t size) {
	void *p = realloc(ptrmem, size);
	if (!p)  {
		free (ptrmem);
		fprintf(stderr, "realloc(): errno=%d\n", errno);
	}
	return p;
}

static int jsoneq(const char *json, jsmntok_t *tok, const char *s) {
	if (tok->type == JSMN_STRING && (int) strlen(s) == tok->end - tok->start &&
			strncmp(json + tok->start, s, tok->end - tok->start) == 0) {
		return 0;
	}
	return -1;
}

static int print_args(const char *js, jsmntok_t *t, size_t count) {
	int i, j;
	int num;

	/* The top-level element is an object */
	if (count < 1 || t[0].type != JSMN_ARRAY) {
		printf("Object expected\n");
		return 1;
	}

	num = t[0].size;
	/* Loop over all keys of the root object */
	for (i = 1; i < count && num > 0; ) {
		if (t[i].type == JSMN_OBJECT) {
			int object_size = t[i].size;
			num--;
			i++;
			for (j = 0; j < object_size; i++, j++) {
				if (jsoneq(js, &t[i], "index") == 0) {
					printf("\t\tindex: %.*s", t[i+1].end-t[i+1].start,
							js + t[i+1].start);
					i++;
				} else if (jsoneq(js, &t[i], "value") == 0) {
					printf("\tvalue: %.*s", t[i+1].end-t[i+1].start,
							js + t[i+1].start);
					i++;
				} else if (jsoneq(js, &t[i], "valueTwo") == 0) {
					printf("\tvalueTwo: %.*s", t[i+1].end-t[i+1].start,
							js + t[i+1].start);
					i++;
				} else if (jsoneq(js, &t[i], "op") == 0) {
					printf("\top: %.*s\n", t[i+1].end-t[i+1].start,
							js + t[i+1].start);
					i++;
				} else {
					printf("Unexpected key: %.*s\n", t[i].end-t[i].start,
							js + t[i].start);
				}
			}
		} else {
			printf("Unexpected key: %.*s\n", t[i].end-t[i].start,
					js + t[i].start);
			i++;
		}
	}
	return i;
}


static int print_syscalls(const char *js, jsmntok_t *t, size_t count) {
	int i, j;

	if (count < 1 || t[0].type != JSMN_ARRAY) {
		printf("Object expected\n");
		return 1;
	}
	int num = t[0].size;

	/* Loop over all keys of the root object */
	for (i = 1; i < count && num > 0;) {
		if (t[i].type == JSMN_OBJECT) {
			int object_size = t[i].size;
			num--;
			i++;
			for (j = 0; j < object_size; j++, i++) {
				if(jsoneq(js, &t[i], "name") == 0) {
					/* We may use strndup() to fetch string value */
					printf("\tname: %.*s\n", t[i+1].end-t[i+1].start,
							js + t[i+1].start);
					i++;
				} else if (jsoneq(js, &t[i], "action") == 0) {
					printf("\taction: %.*s\n", t[i+1].end-t[i+1].start,
							js + t[i+1].start);
					i++;
				} else if (jsoneq(js, &t[i], "args") == 0) {
					int len = count - (i + 1) - 1;
					int ret;
					if (t[i+1].type != JSMN_ARRAY) {
						continue; /* We expect groups to be an array of objects */
					}
					printf("\targs:\n");
					ret = print_args(js, &t[i+1], len);
					i += ret;;
				} else {
					printf("Unexpected key: %.*s\n", t[i].end-t[i].start,
							js + t[i].start);
				}
			}
		} else {
			printf("Unexpected key: %.*s\n", t[i].end-t[i].start,
					js + t[i].start);
			i++;
		}
	}

	return i;
}

static int print_seccomp(const char *js, jsmntok_t *t, size_t count) {
	int i, j;

	/* The top-level element is an object */
	if (count < 1 || t[0].type != JSMN_OBJECT) {
		printf("Object expected\n");
		return 1;
	}

	/* Loop over all keys of the root object */
	for (i = 1; i < count; i++) {
		if (jsoneq(js, &t[i], "defaultAction") == 0) {
			/* We may use strndup() to fetch string value */
			printf("defaultAction: %.*s\n", t[i+1].end-t[i+1].start,
					js + t[i+1].start);
			i++;
		} else if (jsoneq(js, &t[i], "architectures") == 0) {
			int j;
			if (t[i+1].type != JSMN_ARRAY) {
				continue; /* We expect groups to be an array of strings */
			}
			printf("architectures:\n");
			for (j = 0; j < t[i+1].size; j++) {
				jsmntok_t *g = &t[i+j+2];
				printf("  * %.*s\n", g->end - g->start, js + g->start);
			}
			i += t[i+1].size + 1;
		} else if (jsoneq(js, &t[i], "syscalls") == 0) {
			int len = count - (i + 1) - 1;
			int ret;
			if (t[i+1].type != JSMN_ARRAY) {
				continue; /* We expect groups to be an array of objects */
			}
			printf("syscalls:\n");
			ret = print_syscalls(js, &t[i+1], len);
			i += ret;
		} else {
			printf("Unexpected key: %.*s\n", t[i].end-t[i].start,
					js + t[i].start);
		}
	}
	return 0;
}

int main() {
	int r;
	int eof_expected = 0;
	char *js = NULL;
	size_t jslen = 0;
	char buf[BUFSIZ];

	jsmn_parser p;
	jsmntok_t *tok;
	size_t tokcount = 2;

	/* Prepare parser */
	jsmn_init(&p);

	/* Allocate some tokens as a start */
	tok = malloc(sizeof(*tok) * tokcount);
	if (tok == NULL) {
		fprintf(stderr, "malloc(): errno=%d\n", errno);
		return 3;
	}

	for (;;) {
		/* Read another chunk */
		r = fread(buf, 1, sizeof(buf), stdin);
		if (r < 0) {
			fprintf(stderr, "fread(): %d, errno=%d\n", r, errno);
			return 1;
		}
		if (r == 0) {
			if (eof_expected != 0) {
				return 0;
			} else {
				fprintf(stderr, "fread(): unexpected EOF\n");
				return 2;
			}
		}

		js = realloc_it(js, jslen + r + 1);
		if (js == NULL) {
			return 3;
		}
		strncpy(js + jslen, buf, r);
		jslen = jslen + r;

again:
		r = jsmn_parse(&p, js, jslen, tok, tokcount);
		if (r < 0) {
			if (r == JSMN_ERROR_NOMEM) {
				tokcount = tokcount * 2;
				tok = realloc_it(tok, sizeof(*tok) * tokcount);
				if (tok == NULL) {
					return 3;
				}
				goto again;
			}
		} else {
			print_seccomp(js, tok, p.toknext);
			eof_expected = 1;
		}
	}
	return EXIT_SUCCESS;
}
