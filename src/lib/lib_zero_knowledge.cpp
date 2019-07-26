#include <stdlib.h>
#include <ctype.h>
#include <iostream>
#include <fstream>
#include <sstream>
#include <time.h>
#include <boost/optional/optional_io.hpp>

#include "snark.hpp"
#include "lib_zero_knowledge.h"

#define VK_PATH "./vk"
#define PK_PATH "./pk"



#define CHECK_STR_LEN(p, max, ret) if (strlen(p) > max) return ret;




using namespace libsnark;
using namespace std;

static r1cs_ppzksnark_proving_key<default_r1cs_ppzksnark_pp> proving_key;
static r1cs_ppzksnark_verification_key<default_r1cs_ppzksnark_pp> verifycation_key;


static void write_debug_vector(ofstream& out, vector<bool> &v, const char *prefix)
{
	if (strlen(prefix)) {
		out << prefix << "\n";
	}

	for(int i=0; i<v.size(); i++) {
		if (v[i]) {
			out << '1';
		} else {
			out << '0';
		}
		if (i && !(i % 8)) {
			out << ' ';
			if ( !(i % 32) ) {
				out << '\n';
			}
		}
	}
	out << "\n";

}

static void write_debug_array(ofstream& out, int *jw, const char *prefix)
{
	if (strlen(prefix)) {
		out << prefix << "\n";
	}

	for(int i=0; i<32; i++) {
		out << jw[i];
		if (i && !(i % 8)) {
			out << ' ';
			if ( !(i % 32) ) {
				out << '\n';
			}
		}
	}
	out << "\n";
}


static void write_debug(vector<bool> &h1_bv, vector<bool> &h2_bv, vector<bool> &h3_bv, 
	vector<bool> &r1_bv, vector<bool> &r2_bv, vector<bool> &r3_bv, 
	int *jw, const char *file_name)
{
	ofstream out;
	out.open(file_name);
	
    write_debug_vector(out, h1_bv, "h1");
	write_debug_vector(out, h2_bv, "h2");
	write_debug_vector(out, h3_bv, "h3");
	write_debug_vector(out, r1_bv, "r1");
	write_debug_vector(out, r2_bv, "r2");
	write_debug_vector(out, r3_bv, "r3");

	write_debug_array(out, jw, "jw");
	
    out.close();
}

static bool file_exist (const std::string& name) {
	ifstream f(name.c_str());
	return f.good();
}



//called once
void init_setup()
{
	int jw_neg[2][32];

	// Initialize the curve parameters.
    default_r1cs_ppzksnark_pp::init_public_params();

	bool need_gen = true;	
	if (file_exist(PK_PATH) && file_exist(VK_PATH)) { //only read 
		need_gen = false;
	} 
	
	if (need_gen) {
		//generate key
		auto keypair = generate_keypair_neg<default_r1cs_ppzksnark_pp>(jw_neg);
		//pk
		stringstream provingKey;
		provingKey << keypair.pk;
		ofstream pkOf;
		pkOf.open(PK_PATH);
		pkOf << provingKey.rdbuf();
		pkOf.close();
		//vk
		ofstream vkOf;
		stringstream verificationKey;
    	verificationKey << keypair.vk;
    	vkOf.open(VK_PATH);
    	vkOf << verificationKey.rdbuf();
    	vkOf.close();
	}
	
	//read
	ifstream vkIf, pkIf; 
	pkIf.open(PK_PATH); 
    stringstream provingKeyFromFile;
	provingKeyFromFile << pkIf.rdbuf();
	pkIf.close();
	provingKeyFromFile >> proving_key;

    vkIf.open(VK_PATH);  
    stringstream verifycationKeyFromFile;
    verifycationKeyFromFile << vkIf.rdbuf();
    vkIf.close();
    verifycationKeyFromFile >> verifycation_key;
}


static void hex_str_to_bytes(const char* source, unsigned char* dest, int source_len)
{
    unsigned char high, low;

    for (int i = 0; i < source_len; i += 2)
    {
        high = toupper(source[i]);
        low  = toupper(source[i + 1]);

        if (high > 0x39)
            high -= 0x37;
        else
            high -= 0x30;

        if (low > 0x39)
            low -= 0x37;
        else
            low -= 0x30;

        dest[i / 2] = (high << 4) | low;
    }
    return;
}

static void bytes_to_hex_str(const unsigned char* source, unsigned char* dest, int source_len)
{
    unsigned char high, low;

    for (int i = 0; i < source_len; i++)
    {
        high = source[i] >> 4;
        low = source[i] & 0x0f ;

        high += 0x30;

        if (high > 0x39)
                dest[i * 2] = high + 0x07;
        else
                dest[i * 2] = high;

        low += 0x30;
        if (low > 0x39)
            dest[i * 2 + 1] = low + 0x07;
        else
            dest[i * 2 + 1] = low;
    }
	dest[(source_len-1)*2+1+1] = 0;
    return ;
}



static void hex_str_to_vector(const char *source, std::vector<bool>& dest)
{
	unsigned char bytes[32];
	memset(bytes, 0, sizeof(bytes));
	hex_str_to_bytes(source, bytes, strlen(source));
	size_t wordsize = 8;
	for (size_t i = 0; i < sizeof(bytes); ++i)
	{
		for (size_t j = 0; j<wordsize ; ++j)
		{
			dest[i*wordsize + j] = (bytes[i] & (1ul<<(wordsize-1-j)));
		}
	}

}

static char *list_to_str(const std::initializer_list<unsigned char> &list)
{
	char *dest = (char *)malloc( list.size()*2 + 1);
	for (size_t i = 0; i < list.size(); ++i)
    {
		unsigned char c = *(list.begin()+i);
		sprintf(dest+i*2, "%02x", c);
    }
	dest[ list.size()*2 ] = 0;
	return dest;

}

static void set_flag(char *r1, char *r2, int *jw)
{
	unsigned char bytes_r1[32];
	memset(bytes_r1, 0, sizeof(bytes_r1));
	hex_str_to_bytes(r1, bytes_r1, strlen(r1));
	
	unsigned char bytes_r2[32];
	memset(bytes_r2, 0, sizeof(bytes_r2));
	hex_str_to_bytes(r2, bytes_r2, strlen(r2));

	int fv=0;
    for(int i=31;i>0;i--){
    	fv=((int)bytes_r1[i]+(int)bytes_r2[i]+fv)/256;
    	jw[i-1]=fv;
    }

}

//r1 + x = r2 + r3
char *get_prove_data(char *r1, char *r2, char *r3, char *h1, char *h2, char *h3, char *x)
{
	std::vector<bool> h1_bv(256);
	std::vector<bool> h2_bv(256);
	std::vector<bool> h3_bv(256);
	std::vector<bool> r1_bv(256);
	std::vector<bool> r2_bv(256);
	std::vector<bool> r3_bv(256);
	std::vector<bool> x_bv(256);

	const int max_len = (256 / 8) * 2;
	CHECK_STR_LEN(r1, max_len, NULL);
	CHECK_STR_LEN(r2, max_len, NULL);
	CHECK_STR_LEN(r3, max_len, NULL);
	CHECK_STR_LEN(h1, max_len, NULL);
	CHECK_STR_LEN(h2, max_len, NULL);
	CHECK_STR_LEN(h3, max_len, NULL);
	CHECK_STR_LEN(x, max_len, NULL);

	hex_str_to_vector(r1, r1_bv);
	hex_str_to_vector(r2, r2_bv);
	hex_str_to_vector(r3, r3_bv);
	hex_str_to_vector(h1, h1_bv);
	hex_str_to_vector(h2, h2_bv);
	hex_str_to_vector(h3, h3_bv);
	hex_str_to_vector(x, x_bv);

    int jw_neg[2][32];
	//memset((char *)jw, 0, sizeof(jw));
	//set_flag(r1, r2, jw);

	//write_debug(h1_bv, h2_bv, h3_bv, r1_bv, r2_bv, r3_bv, (int *)jw, "debug_lib.txt");

	auto proof_neg = generate_proof_neg<default_r1cs_ppzksnark_pp>(proving_key, h1_bv, h2_bv, h3_bv, r1_bv, r2_bv, r3_bv,x_bv,jw_neg);
	if (!proof_neg) {
		return NULL;
	}
	
	cout << "Proof_neg: " <<  proof_neg << endl;
	stringstream proofStream;
	proofStream << *proof_neg;

	std::string s = proofStream.str();
	unsigned char *dest = (unsigned char *)malloc( s.length() * 2 + 1 );
	bytes_to_hex_str((unsigned char *)s.c_str(), dest, s.length());
	return (char *)dest;
}


//if right, return 1. else return 0
int is_prove_right(char *h1, char *h2, char *h3, char *x, char *prove_data)
{
	std::vector<bool> h1_bv(256);
	std::vector<bool> h2_bv(256);
	std::vector<bool> h3_bv(256);
	std::vector<bool> x_bv(256);
 
	const int max_len = (256 / 8) * 2;
	CHECK_STR_LEN(h1, max_len, 0);
	CHECK_STR_LEN(h2, max_len, 0);
 	CHECK_STR_LEN(h3, max_len, 0);
 	CHECK_STR_LEN(x, max_len, 0);

	hex_str_to_vector(h1, h1_bv);
	hex_str_to_vector(h2, h2_bv);
	hex_str_to_vector(h3, h3_bv);
	hex_str_to_vector(x, x_bv);

	r1cs_ppzksnark_proof<default_r1cs_ppzksnark_pp> prove;
	unsigned char *bytes = (unsigned char *)malloc(strlen(prove_data) / 2);
	hex_str_to_bytes(prove_data, bytes, strlen(prove_data));

	string s((const char *)bytes, strlen(prove_data)/2);
	stringstream proofStream;
	proofStream << s;
	proofStream >> prove;
	

	int ret;
	 if(verify_proof(verifycation_key, prove, h1_bv, h2_bv, h3_bv,x_bv)){
	 	ret = 1;
    	cout<<"verify succ neg"<<endl;
     }else{
	 	ret = 0;
    	cout<<"verify fail neg"<<endl;
     }

	free(bytes);
	return ret;
}


#ifdef TEST_LIB

int main(int argc, char *argv[])
{
	//init
    double dur;
    clock_t start = clock();
	init_setup();
	dur = (double)(clock() - start);
    printf("Generate&Load keypair Use Time:%f\n\n",(dur/CLOCKS_PER_SEC));

	//gen prove
	start = clock();
	char *h1 = list_to_str({39,138,11,164,115,142,207,155,162,115,90,128,61,136,218,78,14,163,205,250,61,5,190,154,54,62,43,131,247,199,132,241});
	char *h2 = list_to_str({199,37,84,153,55,245,80,58,123,28,33,1,179,207,118,141,159,81,118,51,237,63,204,94,143,122,77,36,99,36,207,67});
	char *h3 = list_to_str({209,106,65,239,64,45,254,86,69,25,32,179,2,57,97,164,9,179,130,82,69,202,226,204,227,179,199,101,168,2,103,4});
	printf("h1=%s\n", h1);
	printf("h2=%s\n", h2);
	printf("h3=%s\n", h3);

	char *r1 = list_to_str({0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,51,49,49,49,122,49,49,49,122,49,49,49,122,49,49,49});
	char *r2 = list_to_str({0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,50,49,54,54,49,49,54,54,97,98,99,100,97,98,99,100});
	char *r3 = list_to_str({0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,50,97,98,99,100,101,102,103,122,97,98,99,100,101,102,103});
	char *x = list_to_str({0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,49,97,103,104,27,101,107,108,97,146,148,150,75,150,152,154});
	printf("r1=%s\n", r1);
	printf("r2=%s\n", r2);
	printf("r3=%s\n", r3);
	printf("x=%s\n", x);

	char *prove = get_prove_data(r1, r2, r3, h1, h2, h3, x);
	printf("prove=%s\n", prove);
	dur = (double)(clock() - start);
    printf("Generate proof Use Time:%f\n\n",(dur/CLOCKS_PER_SEC));

	//verify prove
	start = clock();
	int is_right = is_prove_right(h1, h2, h3, x, prove);
	//int is_right = is_prove_right(h1, h3, h2, prove);
	printf("is_right=%d\n", is_right);
	dur = (double)(clock() - start);
	printf("Verify proof Use Time:%f\n\n",(dur/CLOCKS_PER_SEC));

	free(prove);

	
}

#endif

