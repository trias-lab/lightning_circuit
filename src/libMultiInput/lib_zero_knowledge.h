
#ifndef _LIB_H_
#define _LIB_H_

// __cplusplus gets defined when a C++ compiler processes the file
#ifdef __cplusplus
// extern "C" is needed so the C++ compiler exports the symbols without name
// manging.
extern "C" {
#endif

//called once
void init_setup(const char *pkPath, const char *vkPath);


//input + x = output
/*
{
	"input":["a0b0", "a0b0", ...],
	"output":["a0b0", "a0b0"],
	"input_hash":["abc", "def", ...],
	"output_hash":["abc", "def"],
	"x":"a0b0"
}
*/
char *get_prove_data(const char *jsonReqest);


//if right, return 1. else return 0
/*
{
	"input_hash":["abc", "def", ...],
	"output_hash":["abc", "def"],
	"x":"100000",
	"prove_data":"aefefefe"
}
*/
int is_prove_right(const char *jsonReqest);




#ifdef __cplusplus
}
#endif
#endif



