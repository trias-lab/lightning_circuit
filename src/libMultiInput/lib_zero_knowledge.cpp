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

//r1 + r4 + x = r2 + r3
char *get_prove_data(char *r1, char *r2, char *r3, char *r4, char *h1, char *h2, char *h3, char *h4, char *x)
{
	std::vector<bool> h1_bv(256);
	std::vector<bool> h2_bv(256);
	std::vector<bool> h3_bv(256);
	std::vector<bool> h4_bv(256);
	std::vector<bool> r1_bv(256);
	std::vector<bool> r2_bv(256);
	std::vector<bool> r3_bv(256);
	std::vector<bool> r4_bv(256);
	std::vector<bool> x_bv(256);

	const int max_len = (256 / 8) * 2;
	CHECK_STR_LEN(r1, max_len, NULL);
	CHECK_STR_LEN(r2, max_len, NULL);
	CHECK_STR_LEN(r3, max_len, NULL);
	CHECK_STR_LEN(r4, max_len, NULL);
	CHECK_STR_LEN(h1, max_len, NULL);
	CHECK_STR_LEN(h2, max_len, NULL);
	CHECK_STR_LEN(h3, max_len, NULL);
	CHECK_STR_LEN(h4, max_len, NULL);
	CHECK_STR_LEN(x, max_len, NULL);

	hex_str_to_vector(r1, r1_bv);
	hex_str_to_vector(r2, r2_bv);
	hex_str_to_vector(r3, r3_bv);
	hex_str_to_vector(r4, r4_bv);
	hex_str_to_vector(h1, h1_bv);
	hex_str_to_vector(h2, h2_bv);
	hex_str_to_vector(h3, h3_bv);
	hex_str_to_vector(h4, h4_bv);
	hex_str_to_vector(x, x_bv);

    int jw_neg[2][32];
	//memset((char *)jw, 0, sizeof(jw));
	//set_flag(r1, r2, jw);

	//write_debug(h1_bv, h2_bv, h3_bv, r1_bv, r2_bv, r3_bv, (int *)jw, "debug_lib.txt");

	auto proof_neg = generate_proof_neg<default_r1cs_ppzksnark_pp>(proving_key, h1_bv, h2_bv, h3_bv, h4_bv, r1_bv, r2_bv, r3_bv, r4_bv, x_bv,jw_neg);
	if (!proof_neg) {
		return NULL;
	}
	
	cout << "Proof_neg: " <<  proof_neg << endl;
	stringstream proofStream;
	proofStream << *proof_neg;

	std::string s = proofStream.str();
	unsigned char *dest = (unsigned char *)malloc( s.length() * 2 + 1);
	bytes_to_hex_str((unsigned char *)s.c_str(), dest, s.length());
	return (char *)dest;
}


//if right, return 1. else return 0
int is_prove_right(char *h1, char *h2, char *h3, char *h4, char *x, char *prove_data)
{
	std::vector<bool> h1_bv(256);
	std::vector<bool> h2_bv(256);
	std::vector<bool> h3_bv(256);
	std::vector<bool> h4_bv(256);
	std::vector<bool> x_bv(256);
 
	const int max_len = (256 / 8) * 2;
	CHECK_STR_LEN(h1, max_len, 0);
	CHECK_STR_LEN(h2, max_len, 0);
 	CHECK_STR_LEN(h3, max_len, 0);
	CHECK_STR_LEN(h4, max_len, 0);
 	CHECK_STR_LEN(x, max_len, 0);

	hex_str_to_vector(h1, h1_bv);
	hex_str_to_vector(h2, h2_bv);
	hex_str_to_vector(h3, h3_bv);
	hex_str_to_vector(h4, h4_bv);
	hex_str_to_vector(x, x_bv);

	r1cs_ppzksnark_proof<default_r1cs_ppzksnark_pp> prove;
	unsigned char *bytes = (unsigned char *)malloc(strlen(prove_data) / 2);
	hex_str_to_bytes(prove_data, bytes, strlen(prove_data));

	string s((const char *)bytes, strlen(prove_data)/2);
	stringstream proofStream;
	proofStream << s;
	proofStream >> prove;
	

	int ret;
	 if(verify_proof(verifycation_key, prove, h1_bv, h2_bv, h3_bv,h4_bv,x_bv)){
	 	ret = 1;
    	cout<<"verify succ neg"<<endl;
     }else{
	 	ret = 0;
    	cout<<"verify fail neg"<<endl;
     }

	free(bytes);
	return ret;
}


#if 1

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
	char *h1 = list_to_str({188,110,169,119,231,170,91,9,101,147,123,65,195,199,83,205,119,191,200,51,107,18,21,102,159,118,43,38,248,42,32,163});
	char *h2 = list_to_str({52,127,254,38,120,94,13,23,42,251,188,120,234,37,252,223,97,206,31,129,134,177,111,194,48,151,135,18,3,233,164,0});
	char *h3 = list_to_str({99,179,210,199,151,21,86,200,78,95,162,27,113,120,34,91,98,245,232,157,138,48,158,207,140,199,145,155,211,253,98,255});
	char *h4 = list_to_str({254,137,29,37,40,251,121,186,67,14,95,64,26,12,234,152,52,122,149,92,164,204,72,100,152,56,242,234,54,96,93,216});
	printf("h1=%s\n", h1);
	printf("h2=%s\n", h2);
	printf("h3=%s\n", h3);
	printf("h4=%s\n", h4);

	char *r1 = list_to_str({0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,13,224,182,179,167,100,0,0});
	char *r2 = list_to_str({0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,69,99,145,130,68,244,0,0});
	char *r3 = list_to_str({0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,83,68,72,53,236,88,0,0});
	char *r4 = list_to_str({0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,27,193,109,103,78,200,0,0});
	char *x = list_to_str({0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,111,5,181,157,59,32,0,0});
	printf("r1=%s\n", r1);
	printf("r2=%s\n", r2);
	printf("r3=%s\n", r3);
	printf("r4=%s\n", r4);
	printf("x=%s\n", x);

	char *prove = get_prove_data(r1, r2, r3, r4, h1, h2, h3, h4, x);
	printf("prove=%s\n", prove);
	dur = (double)(clock() - start);
    printf("Generate proof Use Time:%f\n\n",(dur/CLOCKS_PER_SEC));

	//verify prove
	start = clock();
	int is_right = is_prove_right(h1, h2, h3, h4, x, prove);
	//int is_right = is_prove_right(h1, h3, h2, prove);
	printf("is_right=%d\n", is_right);
	dur = (double)(clock() - start);
	printf("Verify proof Use Time:%f\n\n",(dur/CLOCKS_PER_SEC));

	free(prove);

	
}

#endif

