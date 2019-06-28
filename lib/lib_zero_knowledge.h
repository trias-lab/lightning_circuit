
#ifndef _LIB_H_
#define _LIB_H_

// __cplusplus gets defined when a C++ compiler processes the file
#ifdef __cplusplus
// extern "C" is needed so the C++ compiler exports the symbols without name
// manging.
extern "C" {
#endif

//called once
void init_setup();

//r1 + r2 = r3 
char *get_prove_data(char *r1, char *r2, char *r3, char *h1, char *h2, char *h3, char *x);


//if right, return 1. else return 0
int is_prove_right(char *h1, char *h2, char *h3, char *x, char *prove_data);




#ifdef __cplusplus
}
#endif
#endif



