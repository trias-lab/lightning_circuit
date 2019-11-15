#include <stdlib.h>
#include <ctype.h>
#include <iostream>
#include <fstream>
#include <sstream>
#include <time.h>
#include <boost/optional/optional_io.hpp>

#include "snark.hpp"
#include "lib_zero_knowledge.h"

//#define VK_PATH "/trias/log/vk"
//#define PK_PATH "/trias/log/pk"



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

static bool file_exist (const char * name) {
	ifstream f(name);
	return f.good();
}



//called once
void init_setup(const char *pkPath, const char *vkPath)
{
	int jw_neg[2][32];

	// Initialize the curve parameters.
    default_r1cs_ppzksnark_pp::init_public_params();

	std::cout << "init_setup, pkPath " << pkPath << ", vkPath " << vkPath << endl; 
	bool need_gen = true;	
	if (file_exist(pkPath) && file_exist(vkPath)) { //only read 
		need_gen = false;
	} 


	if (need_gen) {
		std::cout << "can not find pk&vk, please check file exist, " << pkPath << ", " << vkPath << endl;
		return;
		/*
		//generate key
		auto keypair = generate_keypair_neg<default_r1cs_ppzksnark_pp>(jw_neg);
		//pk
		stringstream provingKey;
		provingKey << keypair.pk;
		ofstream pkOf;
		pkOf.open(pkPath);
		pkOf << provingKey.rdbuf();
		pkOf.close();
		//vk
		ofstream vkOf;
		stringstream verificationKey;
    	verificationKey << keypair.vk;
    	vkOf.open(vkPath);
    	vkOf << verificationKey.rdbuf();
    	vkOf.close();
    	*/
	}
	
	
	//read
	ifstream vkIf, pkIf; 
	pkIf.open(pkPath); 
    stringstream provingKeyFromFile;
	provingKeyFromFile << pkIf.rdbuf();
	pkIf.close();
	provingKeyFromFile >> proving_key;

    vkIf.open(vkPath);  
    stringstream verifycationKeyFromFile;
    verifycationKeyFromFile << vkIf.rdbuf();
    vkIf.close();
    verifycationKeyFromFile >> verifycation_key;
	return;
}

void generate_proof_data_file() 
{
	int jw_neg[2][32];

	// Initialize the curve parameters.
    default_r1cs_ppzksnark_pp::init_public_params();

	const char *pkPath = "./pk";
	const char *vkPath = "./vk";
	std::cout << "generate_proof_data_file, pkPath " << pkPath << ", vkPath " << vkPath << endl; 
	
	//generate key
	auto keypair = generate_keypair_neg<default_r1cs_ppzksnark_pp>(jw_neg);
	//pk
	stringstream provingKey;
	provingKey << keypair.pk;
	ofstream pkOf;
	pkOf.open(pkPath);
	pkOf << provingKey.rdbuf();
	pkOf.close();
	//vk
	ofstream vkOf;
	stringstream verificationKey;
    verificationKey << keypair.vk;
    vkOf.open(vkPath);
    vkOf << verificationKey.rdbuf();
    vkOf.close();
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
	//generate_proof_data_file();
	//return 0;


	//init
    double dur;
    clock_t start = clock();
	init_setup("/8lab/log/pk", "/8lab/log/vk");
	dur = (double)(clock() - start);
    printf("Generate&Load keypair Use Time:%f\n\n",(dur/CLOCKS_PER_SEC));
	const char *req;
	char *prove;

	if (0) {
		//gen prove
		start = clock();
		req = "{\"input\":[\"0000000000000000000000000000000000000001431e0fae6d7217caa0000000\",\"0000000000000000000000000000000000000000000000000000000000000000\",\"0000000000000000000000000000000000000000000000000000000000000000\",\"0000000000000000000000000000000000000000000000000000000000000000\",\"0000000000000000000000000000000000000000000000000000000000000000\",\"0000000000000000000000000000000000000000000000000000000000000000\",\"0000000000000000000000000000000000000000000000000000000000000000\",\"0000000000000000000000000000000000000000000000000000000000000000\",\"0000000000000000000000000000000000000000000000000000000000000000\",\"0000000000000000000000000000000000000000000000000000000000000000\"],\"output\":[\"0000000000000000000000000000000000000002863c1f5cdae42f9540000000\",\"0000000000000000000000000000000000000003c95a2f0b4856475fe0000000\"],\"input_hash\":[\"26e61aa111f74216678ccb6ff936e0d6aa131cace797cd1edccc62b7313a4256\",\"66687aadf862bd776c8fc18b8e9f8e20089714856ee233b3902a591d0d5f2925\",\"66687aadf862bd776c8fc18b8e9f8e20089714856ee233b3902a591d0d5f2925\",\"66687aadf862bd776c8fc18b8e9f8e20089714856ee233b3902a591d0d5f2925\",\"66687aadf862bd776c8fc18b8e9f8e20089714856ee233b3902a591d0d5f2925\",\"66687aadf862bd776c8fc18b8e9f8e20089714856ee233b3902a591d0d5f2925\",\"66687aadf862bd776c8fc18b8e9f8e20089714856ee233b3902a591d0d5f2925\",\"66687aadf862bd776c8fc18b8e9f8e20089714856ee233b3902a591d0d5f2925\",\"66687aadf862bd776c8fc18b8e9f8e20089714856ee233b3902a591d0d5f2925\",\"66687aadf862bd776c8fc18b8e9f8e20089714856ee233b3902a591d0d5f2925\"],\"output_hash\":[\"cf41dc783e439326146d56ebb3be0838792ec1405a67648b64201e2bb9bfd692\",\"42248a90d2c36c08e846a92b2369c253bd596feabb417f1d7a659dd385edc3a9\"],\"x\":\"00000000000000000000000000000000000000050c783eb9b5c85f2a80000000\"}";
		prove = get_prove_data(req);
		printf("prove=%s\n", prove);
		dur = (double)(clock() - start);
    	printf("Generate proof Use Time:%f\n\n",(dur/CLOCKS_PER_SEC));
	}
	
	if (1) {
		//verify prove
		start = clock();
		req =  "{\"input_hash\":[\"26e61aa111f74216678ccb6ff936e0d6aa131cace797cd1edccc62b7313a4256\",\"66687aadf862bd776c8fc18b8e9f8e20089714856ee233b3902a591d0d5f2925\",\"66687aadf862bd776c8fc18b8e9f8e20089714856ee233b3902a591d0d5f2925\",\"66687aadf862bd776c8fc18b8e9f8e20089714856ee233b3902a591d0d5f2925\",\"66687aadf862bd776c8fc18b8e9f8e20089714856ee233b3902a591d0d5f2925\",\"66687aadf862bd776c8fc18b8e9f8e20089714856ee233b3902a591d0d5f2925\",\"66687aadf862bd776c8fc18b8e9f8e20089714856ee233b3902a591d0d5f2925\",\"66687aadf862bd776c8fc18b8e9f8e20089714856ee233b3902a591d0d5f2925\",\"66687aadf862bd776c8fc18b8e9f8e20089714856ee233b3902a591d0d5f2925\",\"66687aadf862bd776c8fc18b8e9f8e20089714856ee233b3902a591d0d5f2925\"],\"output_hash\":[\"cf41dc783e439326146d56ebb3be0838792ec1405a67648b64201e2bb9bfd692\",\"42248a90d2c36c08e846a92b2369c253bd596feabb417f1d7a659dd385edc3a9\"],\"x\":\"00000000000000000000000000000000000000050c783eb9b5c85f2a80000000\",\"prove_data\":\"30203230373339383031333630343837383932313431343731303237393036313437383635363837323135383631383835373735363138333736333935313534363337343435363336373837373631203020302036303933393032313633303735343631323734343837303736383931303839343935383639383439323335363930323831373535333936333335303934353533323639363139353830313920300A302031383736383137363639373130363737343736353839323736363836313335353538393432333036353339303936323135373930313536303438323531313236343638313434373333373338342032313038383632333837313637373330323636313239393531353731383837383639353236373231333634303032393333383731343232393039353737393235303634313939373432383434332031203020313134373737303434303138383638383131383037323735393436363330313638373837303930323633363730313336363539383531303734373636383039313938393837343235373133313620310A3020313437353237333839303936343639313434363331343036303232333735383836313138323235383833393532333337353735373239353731323038393337313733353530383139323836333120302030203833353839383031363832363634323032323834313133383239383938383730323831393030373531333131303939383032363133353837373836353931393731303134333534383231353920310A3020313939393534363738313238383338383738353638363730373635383933313437383632353538313136373530333438333939353038353838363438333538383339383531313730393038343120310A3020313336333337373335383130313239373233313437303235363238323536373233303839373239373932303434333830303130393333313331393035333033373836353137393930343338393720300A\"}";
		int is_right = is_prove_right(req);
		printf("is_right=%d\n", is_right);
		dur = (double)(clock() - start);
		printf("Verify proof Use Time:%f\n\n",(dur/CLOCKS_PER_SEC));
	}
	free(prove);

	
}

#endif

