#include <stdlib.h>
#include <iostream>
#include <fstream>
#include <sstream>
#include <time.h>
#include <boost/optional/optional_io.hpp>

#include "snark.hpp"
#include "test.h"

using namespace libsnark;
using namespace std;



//增加对每字节计算平衡的进制现象支持

int main(int argc, char *argv[])
{
    double dur;
    clock_t start = clock();
    ifstream fileIn;
    ofstream fileOut;


    // Initialize the curve parameters.
    default_r1cs_ppzksnark_pp::init_public_params();

    cout<<argc<<argv[0]<<endl;
    if(argc>1 and strcmp(argv[1],"gkey")==0){
    	cout<< "Generate new keypair......"<<endl;
        // Generate the verifying/proving keys. (This is trusted setup!)
        auto keypair = generate_keypair<default_r1cs_ppzksnark_pp>();

        //保存vk到文件
        stringstream verificationKey;
        verificationKey << keypair.vk;
        fileOut.open("vk");
        fileOut << verificationKey.rdbuf();
        fileOut.close();

        //保存pk到文件
        stringstream provingKey;
        provingKey << keypair.pk;
        fileOut.open("pk");
        fileOut << provingKey.rdbuf();
        fileOut.close();
    }

    // Initialize bit_vectors for all of the variables involved.
    std::vector<bool> h1_bv(256);
    std::vector<bool> h2_bv(256);
    std::vector<bool> h3_bv(256);
    std::vector<bool> r1_bv(256);
    std::vector<bool> r2_bv(256);
    std::vector<bool> r3_bv(256);


    /*
    // These are working test vectors.
    h1_bv = int_list_to_bits({30,2,147,172,7,90,253,151,155,212,128,82,121,206,72,133,86,169,200,187,196,148,47,65,231,17,204,194,228,237,224,180}, 8);
    h2_bv = int_list_to_bits({132,181,148,69,74,155,172,20,227,53,172,143,173,12,113,92,40,80,243,108,157,54,92,25,37,218,71,174,94,208,205,220}, 8);
    h3_bv = int_list_to_bits({176,85,50,53,72,175,168,51,93,254,188,209,226,128,228,170,210,7,251,243,5,149,127,27,138,19,202,220,28,142,94,227}, 8);

    // Constraint is num3 = num1 + num2
    r1_bv = int_list_to_bits({0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,73,48,49,50,47,48,49,50,73,48,49,50,46,47,48,49}, 8);
    r2_bv = int_list_to_bits({0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,49,49,49,49,53,53,53,53,49,49,49,49,54,54,54,54}, 8);
    r3_bv = int_list_to_bits({0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,122,97,98,99,100,101,102,103,122,97,98,99,100,101,102,103}, 8);
    */

    h1_bv = int_list_to_bits({73,138,113,231,182,74,164,21,132,47,66,182,209,38,202,5,237,83,114,116,205,146,16,6,49,120,229,66,80,190,2,103}, 8);
    h2_bv = int_list_to_bits({41,31,60,5,28,179,197,19,173,105,230,118,149,239,92,142,46,131,92,224,170,155,35,30,134,197,178,150,148,228,10,208}, 8);
    h3_bv = int_list_to_bits({147,250,206,29,44,67,218,158,190,136,58,56,197,6,4,137,209,216,152,247,149,77,246,144,120,117,3,17,44,174,8,182}, 8);

    // Constraint is num3 = num1 + num2
    const int r1[32]={0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,72,255,250,251,72,255,250,251,24,206,205,205,24,206,205,205};
    const int r2[32]={0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,49,49,54,54,49,49,54,54,97,98,99,100,97,98,99,100};
    const int r3[32]={0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,122,49,49,49,122,49,49,49,122,49,49,49,122,49,49,49};
    int jw[32];

    r1_bv = int_list_to_bits({0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,72,255,250,251,72,255,250,251,24,206,205,205,24,206,205,205}, 8);
    r2_bv = int_list_to_bits({0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,49,49,54,54,49,49,54,54,97,98,99,100,97,98,99,100}, 8);
    r3_bv = int_list_to_bits({0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,122,49,49,49,122,49,49,49,122,49,49,49,122,49,49,49}, 8);

    int fv=0;
    for(int i=31;i>0;i--){
    	fv=(r1[i]+r2[i]+fv)/256;
    	jw[i-1]=fv;
    }
    //cout<<jw<<endl;


    // 从文件中导入pk用于生成证明,vk用于验证
     r1cs_ppzksnark_proving_key<default_r1cs_ppzksnark_pp> provingKey_in;
     r1cs_ppzksnark_verification_key<default_r1cs_ppzksnark_pp> verifycation_in;


	 fileIn.open("pk");  //from file of pk read the data to type of  r1cs_ppzksnark_proving_key
     stringstream provingKeyFromFile;
     if (fileIn) {
        provingKeyFromFile << fileIn.rdbuf();
        fileIn.close();
     }
     // provingKey_in == keypair.pk
     provingKeyFromFile >> provingKey_in;

     fileIn.open("vk");  //from file of pk read the data to type of  r1cs_ppzksnark_proving_key
     stringstream verifycationKeyFromFile;
     if (fileIn) {
    	 verifycationKeyFromFile << fileIn.rdbuf();
        fileIn.close();
     }
     // verifycation_in == keypair.vk
     verifycationKeyFromFile >> verifycation_in;

    dur = (double)(clock() - start);
    printf("Generate&Load keypair Use Time:%f\n\n",(dur/CLOCKS_PER_SEC));
    start = clock();

     cout << "Trying to generate proof..." << endl;
     auto proof = generate_proof<default_r1cs_ppzksnark_pp>(provingKey_in, h1_bv, h2_bv, h3_bv, r1_bv, r2_bv, r3_bv,jw,"pos"); // provingKey_in == keypair.pk
     auto proof_neg = generate_proof<default_r1cs_ppzksnark_pp>(provingKey_in, h1_bv, h2_bv, h3_bv, r1_bv, r2_bv, r3_bv,jw,"neg"); // provingKey_in == keypair.pk

     cout << "Proof generated!" << endl;
     cout << "Proof: " <<  proof << endl;
     cout << "Proof_neg: " <<  proof_neg << endl;


      // 从保存证明数据，而后从文件读取证明数据进行验证
     stringstream proofStream;
     proofStream << *proof;
     fileOut.open("proof");
     fileOut << proofStream.rdbuf();
     fileOut.close();


     dur = (double)(clock() - start);
     printf("Proof Generated Use Time:%f\n\n",(dur/CLOCKS_PER_SEC));
     start = clock();


     //读入证明数据
     r1cs_ppzksnark_proof<default_r1cs_ppzksnark_pp> proof_in;
     fileIn.open("proof");
     stringstream proofFromFile;
     if (fileIn) {
     	proofFromFile << fileIn.rdbuf();
     	fileIn.close();
     }
     proofFromFile >> proof_in;


     if (!proof) {
         cout<<"Generate proof fail";
         exit(1);
     }else if(verify_proof(verifycation_in, proof_in, h1_bv, h2_bv, h3_bv)){
    	 cout<<"verify succ"<<endl;
         //assert(verify_proof(keypair.vk, *proof, h1_bv, h2_bv, h3_bv));
     }else{
    	 cout<<"verify fail"<<endl;
     }
     dur = (double)(clock() - start);
     printf("Proof Verify Use Time:%f\n\n",(dur/CLOCKS_PER_SEC));


     if(verify_proof(verifycation_in, *proof_neg, h1_bv, h2_bv, h3_bv)){
    	 cout<<"verify succ neg"<<endl;
     }else{
    	 cout<<"verify fail neg"<<endl;
     }

     cout<<"=========================="<<endl;
     if(verify_proof(verifycation_in, *proof_neg, h3_bv, h2_bv, h1_bv)){
    	 cout<<"verify succ neg"<<endl;
     }else{
    	 cout<<"verify fail neg"<<endl;
     }
}


