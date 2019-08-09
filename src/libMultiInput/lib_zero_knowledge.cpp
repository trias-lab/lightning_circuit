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



extern const int MAX_INPUT_NUMBER;
extern const int MAX_OUTPUT_NUMBER;



using namespace libsnark;
using namespace std;

static r1cs_ppzksnark_proving_key<default_r1cs_ppzksnark_pp> proving_key;
static r1cs_ppzksnark_verification_key<default_r1cs_ppzksnark_pp> verifycation_key;

/*
static void write_debug_vector(ofstream& out, vector<bool> &v, const char *prefix)
{
	if (strlen(prefix)) {
		out << prefix << "\n";
	}

	for(size_t i=0; i<v.size(); i++) {
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
*/

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

/*
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
*/

//return if success
bool fill_string_vec_from_json(const string& json, const char *key, vector<string>& dest)
{
	std::string::size_type start;
	std::string::size_type end;
	std::string toFind = string("\"") + key + string("\":[") ;
	start = json.find(toFind);
	if (start == std::string::npos) {
		cout << "fill_string_vec_from_json, not find " << toFind << ", " << json << endl;
		return false;
	}
	start += toFind.size();
	toFind = "]";
	end = json.find(toFind, start);
	if (end == std::string::npos) {
		cout << "fill_string_vec_from_json, not find " << toFind << ", " << json << endl;
		return false;
	}
	std::string s = json.substr(start, end-start);
	start = 0;
	while(true) {
		start = s.find("\"", start);
		if (start == std::string::npos) {
			break;
		}
		start += 1;
		end = s.find("\"", start);
		if (end == std::string::npos) {
			cout << "fill_string_vec_from_json, not find ending \"" << s << ", " << start << endl;
			return NULL;
		}
		dest.push_back( s.substr(start, end-start) );
		start = end+1;
	}
	return true;
}

//return if success
bool get_string_value_from_json(const string& json, const char *key, string& value)
{
	std::string::size_type start;
	std::string::size_type end;
	std::string toFind = string(key) + "\":\"";
	start = json.find(toFind);
	if (start == std::string::npos) {
		cout << "get_string_value_from_json, not find " << toFind << ", " << json << endl;
		return false;
	}
	start += toFind.size();
	toFind = "\"";
	end = json.find(toFind, start);
	if (start == std::string::npos) {
		cout << "get_string_value_from_json, not find " << toFind << ", " << json << endl;
		return false;
	}
	std::string s = json.substr(start, end-start);
	value = s;
	return true;
}



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
char *get_prove_data(const char *jsonReqest)
{
	//parse json data
	std::vector<std::string> inputStringVec;
	std::vector<std::string> outputStringVec;
	std::vector<std::string> inputHashStringVec;
	std::vector<std::string> outputHashStringVec;
	std::string xString;

	string json(jsonReqest);

	//inputVec
	bool success;
	success = fill_string_vec_from_json(json, "input", inputStringVec);
	if (!success) {
		return NULL;
	}
	success = fill_string_vec_from_json(json, "output", outputStringVec);
	if (!success) {
		return NULL;
	}
	success = fill_string_vec_from_json(json, "input_hash", inputHashStringVec);
	if (!success) {
		return NULL;
	}
	success = fill_string_vec_from_json(json, "output_hash", outputHashStringVec);
	if (!success) {
		return NULL;
	}
	success = get_string_value_from_json(json, "x", xString);
	if (!success) {
		return NULL;
	}

	//check vector count
	if (inputStringVec.size() != MAX_INPUT_NUMBER ||
		inputHashStringVec.size() != MAX_INPUT_NUMBER ||
		outputStringVec.size() != MAX_OUTPUT_NUMBER ||
		outputHashStringVec.size() != MAX_OUTPUT_NUMBER) 
	{
		cout << "vector length not right, " << inputStringVec.size() << "," << inputHashStringVec.size()
			<< "," << outputStringVec.size() << "," << outputHashStringVec.size();
		return NULL;
	}


	//check string length
	const int max_len = (256 / 8) * 2;
	for(size_t i=0; i<inputStringVec.size(); i++) {
		if (inputStringVec[i].size() > max_len) {
			return NULL;
		}
	}
	for(size_t i=0; i<outputStringVec.size(); i++) {
		if (outputStringVec[i].size() > max_len) {
			return NULL;
		}
	}
	for(size_t i=0; i<inputHashStringVec.size(); i++) {
		if (inputHashStringVec[i].size() > max_len) {
			return NULL;
		}
	}
	for(size_t i=0; i<outputHashStringVec.size(); i++) {
		if (outputHashStringVec[i].size() > max_len) {
			return NULL;
		}
	}
	if (xString.size() > max_len) {
		return NULL;
	}

	
	//convert to bit vector
	std::vector<bit_vector> input_vec;
	std::vector<bit_vector> output_vec;
	std::vector<bit_vector> hash_input_vec;
	std::vector<bit_vector> hash_output_vec;
	bit_vector x(256);

	for(size_t i=0; i<inputStringVec.size(); i++) {
		const char *p = inputStringVec[i].c_str();
		bit_vector v(256);
		hex_str_to_vector(p, v);
		input_vec.push_back( v );
	}
	for(size_t i=0; i<outputStringVec.size(); i++) {
		const char *p = outputStringVec[i].c_str();
		bit_vector v(256);
		hex_str_to_vector(p, v);
		output_vec.push_back( v );
	}
	for(size_t i=0; i<inputHashStringVec.size(); i++) {
		const char *p = inputHashStringVec[i].c_str();
		bit_vector v(256);
		hex_str_to_vector(p, v);
		hash_input_vec.push_back( v );
	}
	for(size_t i=0; i<outputHashStringVec.size(); i++) {
		const char *p = outputHashStringVec[i].c_str();
		bit_vector v(256);
		hex_str_to_vector(p, v);
		hash_output_vec.push_back( v );
	}
	hex_str_to_vector(xString.c_str(), x);
	

	int jw_neg[2][32];
	//memset((char *)jw, 0, sizeof(jw));
	//set_flag(r1, r2, jw);

	//write_debug(h1_bv, h2_bv, h3_bv, r1_bv, r2_bv, r3_bv, (int *)jw, "debug_lib.txt");
	
	auto proof_neg = generate_proof_neg<default_r1cs_ppzksnark_pp>(proving_key, hash_input_vec, hash_output_vec, input_vec, output_vec, x,jw_neg);
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
/*
{
	"input_hash":["abc", "def", ...],
	"output_hash":["abc", "def"],
	"x":"100000",
	"prove_data":"aefefefe"
}
*/
int is_prove_right(const char *jsonReqest)
{
	//parse json data
	std::vector<std::string> inputHashStringVec;
	std::vector<std::string> outputHashStringVec;
	std::string xString;
	std::string proveDataString;

	string json(jsonReqest);

	//inputVec
	bool success;
	success = fill_string_vec_from_json(json, "input_hash", inputHashStringVec);
	if (!success) {
		return 0;
	}
	success = fill_string_vec_from_json(json, "output_hash", outputHashStringVec);
	if (!success) {
		return 0;
	}
	success = get_string_value_from_json(json, "x", xString);
	if (!success) {
		return 0;
	}
	success = get_string_value_from_json(json, "prove_data", proveDataString);
	if (!success) {
		return 0;
	}

	//check vector count
	if (inputHashStringVec.size() != MAX_INPUT_NUMBER ||
		outputHashStringVec.size() != MAX_OUTPUT_NUMBER ) 
	{
		cout << "vector length not right, "  << inputHashStringVec.size()
			<< "," << outputHashStringVec.size();
		return 0;
	}

	//check string length
	const int max_len = (256 / 8) * 2;
	for(size_t i=0; i<inputHashStringVec.size(); i++) {
		if (inputHashStringVec[i].size() > max_len) {
			return 0;
		}
	}
	for(size_t i=0; i<outputHashStringVec.size(); i++) {
		if (outputHashStringVec[i].size() > max_len) {
			return 0;
		}
	}
	if (xString.size() > max_len) {
		return 0;
	}

	//convert to bit vector
	std::vector<bit_vector> hash_input_vec;
	std::vector<bit_vector> hash_output_vec;
	bit_vector x(256);
	
	for(size_t i=0; i<inputHashStringVec.size(); i++) {
		const char *p = inputHashStringVec[i].c_str();
		bit_vector v(256);
		hex_str_to_vector(p, v);
		hash_input_vec.push_back( v );
	}
	for(size_t i=0; i<outputHashStringVec.size(); i++) {
		const char *p = outputHashStringVec[i].c_str();
		bit_vector v(256);
		hex_str_to_vector(p, v);
		hash_output_vec.push_back( v );
	}
	hex_str_to_vector(xString.c_str(), x);

	const char *prove_data = proveDataString.c_str();
	r1cs_ppzksnark_proof<default_r1cs_ppzksnark_pp> prove;
	unsigned char *bytes = (unsigned char *)malloc(strlen(prove_data) / 2);
	hex_str_to_bytes(prove_data, bytes, strlen(prove_data));

	string s((const char *)bytes, strlen(prove_data)/2);
	stringstream proofStream;
	proofStream << s;
	proofStream >> prove;

	int ret;
	 if(verify_proof(verifycation_key, prove, hash_input_vec, hash_output_vec, x)){
	 	ret = 1;
    	cout<<"verify succ neg"<<endl;
     }else{
	 	ret = 0;
    	cout<<"verify fail neg"<<endl;
     }

	free(bytes);
	return ret;
}

#if TEST_LIB_MULTI

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
	const char *req = "{\"input\":[\"0000000000000000000000000000000000000000000000000000000000000001\",\"0000000000000000000000000000000000000000000000000000000000000002\",\"0000000000000000000000000000000000000000000000000000000000000003\",\"0000000000000000000000000000000000000000000000000000000000000004\",\"0000000000000000000000000000000000000000000000000000000000000005\",\"0000000000000000000000000000000000000000000000000000000000000006\",\"0000000000000000000000000000000000000000000000000000000000000007\",\"0000000000000000000000000000000000000000000000000000000000000008\",\"0000000000000000000000000000000000000000000000000000000000000009\",\"000000000000000000000000000000000000000000000000000000000000000a\"],\"output\":[\"0000000000000000000000000000000000000000000000000000000000000014\",\"0000000000000000000000000000000000000000000000000000000000000028\"],\"input_hash\":[\"ec4916dd28fc4c10d78e287ca5d9cc51ee1ae73cbfde08c6b37324cbfaac8bc5\",\"9267d3dbed802941483f1afa2a6bc68de5f653128aca9bf1461c5d0a3ad36ed2\",\"d9147961436944f43cd99d28b2bbddbf452ef872b30c8279e255e7daafc7f946\",\"e38990d0c7fc009880a9c07c23842e886c6bbdc964ce6bdd5817ad357335ee6f\",\"96de8fc8c256fa1e1556d41af431cace7dca68707c78dd88c3acab8b17164c47\",\"d1ec675902ef1633427ca360b290b0b3045a0d9058ddb5e648b4c3c3224c5c68\",\"48428bdb7ddd829410d6bbb924fdeb3a3d7e88c2577bffae073b990c6f061d08\",\"38df1c1f64a24a77b23393bca50dff872e31edc4f3b5aa3b90ad0b82f4f089b6\",\"887bf140ce0b6a497ed8db5c7498a45454f0b2bd644b0313f7a82acc084d0027\",\"81b04ae4944e1704a65bc3a57b6fc3b06a6b923e3c558d611f6a854b5539ec13\"],\"output_hash\":[\"4d68bf921d7fcf9f99a27e28f59b875c234193f9c330403dcf29f1872be57ccd\",\"1391854aca800961b604acd16f59e5ec4fd025a2fb0eb9ae166976bc2d42cb3c\"],\"x\":\"0000000000000000000000000000000000000000000000000000000000000005\"}";
	char *prove = get_prove_data(req);
	printf("prove=%s\n", prove);
	dur = (double)(clock() - start);
    printf("Generate proof Use Time:%f\n\n",(dur/CLOCKS_PER_SEC));


	//verify prove
	start = clock();
	req = "{\"input_hash\":[\"ec4916dd28fc4c10d78e287ca5d9cc51ee1ae73cbfde08c6b37324cbfaac8bc5\",\"9267d3dbed802941483f1afa2a6bc68de5f653128aca9bf1461c5d0a3ad36ed2\",\"d9147961436944f43cd99d28b2bbddbf452ef872b30c8279e255e7daafc7f946\",\"e38990d0c7fc009880a9c07c23842e886c6bbdc964ce6bdd5817ad357335ee6f\",\"96de8fc8c256fa1e1556d41af431cace7dca68707c78dd88c3acab8b17164c47\",\"d1ec675902ef1633427ca360b290b0b3045a0d9058ddb5e648b4c3c3224c5c68\",\"48428bdb7ddd829410d6bbb924fdeb3a3d7e88c2577bffae073b990c6f061d08\",\"38df1c1f64a24a77b23393bca50dff872e31edc4f3b5aa3b90ad0b82f4f089b6\",\"887bf140ce0b6a497ed8db5c7498a45454f0b2bd644b0313f7a82acc084d0027\",\"81b04ae4944e1704a65bc3a57b6fc3b06a6b923e3c558d611f6a854b5539ec13\"],\"output_hash\":[\"4d68bf921d7fcf9f99a27e28f59b875c234193f9c330403dcf29f1872be57ccd\",\"1391854aca800961b604acd16f59e5ec4fd025a2fb0eb9ae166976bc2d42cb3c\"],\"x\":\"0000000000000000000000000000000000000000000000000000000000000005\",\"prove_data\":\"3020313039303236373633333732393030313030383038323037383036303739303039323932393036363236373635353230303430343630333839383034333636383031333735353639363730363420312030203630393635383334323235373938353034393931333737393130303334353433393731313037383036303034353133333235333738313137303233393539323632353930313331393631333920310A30203230333334343834343132313137313031393236383637313336393238313132373430383831343930313334343435363631333536383638363931323031383138323037303933353035373520373834333931323930333538383330313530303734343037383539353631333436313531343538353034373538343634313135303438383239383230333737373931383134333938393837312030203020313136383231353538373231393137373934383736303930303436323739393536313130323736373739303139383733323231363535353335303438393732323331363035373830323938373220300A302031323834393437333133313436333330323537313135303434353536303334373630343633373630363435303735393830383234393032333430313334303632393238303334303338323735372030203020313338373239373137363833383430323733393537343732393932333131353335313636343238373235313935313630353337323730343832383835363237393935393138313939303737363520300A3020313634313933333839373936353738343038343432393439393239373738313432393037303635393434333138333237303137393034383034303536363536323234313930353032343335313320310A30203730363636323036373739303737363139313532343034313137333932313636333737323634353133343032393935393334323232323737333833383432303733343034393535373538313620300A\"}";
	int is_right = is_prove_right(req);
	printf("is_right=%d\n", is_right);
	dur = (double)(clock() - start);
	printf("Verify proof Use Time:%f\n\n",(dur/CLOCKS_PER_SEC));

	free(prove);

	
}

#endif

