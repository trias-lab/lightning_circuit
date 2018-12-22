#include <stdlib.h>
#include <iostream>
#include <fstream>
#include <sstream>
#include <time.h>
#include <boost/optional/optional_io.hpp>

#include "snark.hpp"
#include "zktrias.hpp"

using namespace libsnark;
using namespace std;

//把byte list 转化成 bit list
bit_vector iv2bv(int iv[32]){
	bit_vector rs;
	for(int i=0;i<32;i++){
		for(int j=7;j>=0;j--){
			if((iv[i]&(1<<j))>0){
				rs.push_back(true);
			}else{
				rs.push_back(false);
			}
		}
	}
	return rs;
}

//zktrias R1=R2+R3+X   R1+X=R2+R3  X=a1+r1-a2-r2-a3-r3+f
//trias 应用实践demo

int main(int argc, char *argv[])
{
    double dur;
    clock_t start = clock();
    ifstream fileIn;
    ofstream fileOut;
    bool neg;
    int jw[32];
    int jw_neg[2][32];

    if(argc>2 and strcmp(argv[2],"neg")==0){
    	neg=true;
    	cout<<"Use neg data for test,R1+X=R2+R3,..."<<endl;
    }else{
    	neg=false;
    	cout<<"Use normal data for test,R1=R2+R3+X,..."<<endl;
    }

    // Initialize the curve parameters.
    default_r1cs_ppzksnark_pp::init_public_params();

    // Initialize bit_vectors for all of the variables involved.
      std::vector<bool> h1_bv(256);
      std::vector<bool> h2_bv(256);
      std::vector<bool> h3_bv(256);
      std::vector<bool> r1_bv(256);
      std::vector<bool> r2_bv(256);
      std::vector<bool> r3_bv(256);
      std::vector<bool> x_bv(256);

      if (!neg){
          // R1=R2+R3+X
          h1_bv = int_list_to_bits({147,250,206,29,44,67,218,158,190,136,58,56,197,6,4,137,209,216,152,247,149,77,246,144,120,117,3,17,44,174,8,182}, 8);
          h2_bv = int_list_to_bits({41,31,60,5,28,179,197,19,173,105,230,118,149,239,92,142,46,131,92,224,170,155,35,30,134,197,178,150,148,228,10,208}, 8);
          h3_bv = int_list_to_bits({209,106,65,239,64,45,254,86,69,25,32,179,2,57,97,164,9,179,130,82,69,202,226,204,227,179,199,101,168,2,103,4}, 8);

          int r1[32]={0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,122,49,49,49,122,49,49,49,122,49,49,49,122,49,49,49};
          int r2[32]={0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,49,49,54,54,49,49,54,54,97,98,99,100,97,98,99,100};
          int r3[32]={0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,50,97,98,99,100,101,102,103,122,97,98,99,100,101,102,103};
          int x[32]={0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,22,158,152,151,228,154,148,147,158,109,107,105,180,105,103,102};

          r1_bv = iv2bv(r1);
          r2_bv = iv2bv(r2);
          r3_bv = iv2bv(r3);
          x_bv = iv2bv(x);

          // Constraint is r1=r2+r3+x
          int fv=0;
          for(int i=31;i>0;i--){
          	fv=(r2[i]+r3[i]+x[i]+fv)/256;
          	jw[i-1]=fv;
          }
      }else{
    	  //R1+X=R2+R3
          h1_bv = int_list_to_bits({39,138,11,164,115,142,207,155,162,115,90,128,61,136,218,78,14,163,205,250,61,5,190,154,54,62,43,131,247,199,132,241}, 8);
          h2_bv = int_list_to_bits({199,37,84,153,55,245,80,58,123,28,33,1,179,207,118,141,159,81,118,51,237,63,204,94,143,122,77,36,99,36,207,67}, 8);
          h3_bv = int_list_to_bits({209,106,65,239,64,45,254,86,69,25,32,179,2,57,97,164,9,179,130,82,69,202,226,204,227,179,199,101,168,2,103,4}, 8);

          int r1[32]={0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,51,49,49,49,122,49,49,49,122,49,49,49,122,49,49,49};
          int r2[32]={0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,50,49,54,54,49,49,54,54,97,98,99,100,97,98,99,100};
          int r3[32]={0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,50,97,98,99,100,101,102,103,122,97,98,99,100,101,102,103};
          int x[32]={0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,49,97,103,104,27,101,107,108,97,146,148,150,75,150,152,154};

          r1_bv = iv2bv(r1);
          r2_bv = iv2bv(r2);
          r3_bv = iv2bv(r3);
          x_bv = iv2bv(x);

          // Constraint is r1+x=r2+r3

          int fv0=0,fv1=0;
          for(int i=31;i>0;i--){
          	fv0=(r1[i]+x[i]+fv0)/256;
          	fv1=(r2[i]+r3[i]+fv1)/256;
          	jw_neg[0][i-1]=fv0;
          	jw_neg[1][i-1]=fv1;
          }
      }


    cout<<argc<<argv[0]<<endl;
    if(argc>1 and strcmp(argv[1],"gkey")==0){
    	cout<< "Generate new keypair......"<<endl;
        // Generate the verifying/proving keys. (This is trusted setup!)
    	auto keypair=neg ? generate_keypair_neg<default_r1cs_ppzksnark_pp>(jw_neg) : generate_keypair<default_r1cs_ppzksnark_pp>(jw);

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
     auto proof=neg ? generate_proof_neg<default_r1cs_ppzksnark_pp>(provingKey_in, h1_bv, h2_bv, h3_bv, r1_bv, r2_bv, r3_bv,x_bv,jw_neg):generate_proof<default_r1cs_ppzksnark_pp>(provingKey_in, h1_bv, h2_bv, h3_bv, r1_bv, r2_bv, r3_bv,x_bv,jw);

     /*
     if(neg){
    	 proof = generate_proof_neg<default_r1cs_ppzksnark_pp>(provingKey_in, h1_bv, h2_bv, h3_bv, r1_bv, r2_bv, r3_bv,x_bv,jw_neg); // provingKey_in == keypair.pk
     }else{
    	 proof = generate_proof<default_r1cs_ppzksnark_pp>(provingKey_in, h1_bv, h2_bv, h3_bv, r1_bv, r2_bv, r3_bv,x_bv,jw); // provingKey_in == keypair.pk
     }*/

     cout << "Proof generated!" << endl;
     cout << "Proof: " <<  proof << endl;
     //cout << "Proof_neg: " <<  proof_neg << endl;


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
     }else if(verify_proof(verifycation_in, proof_in, h1_bv, h2_bv, h3_bv,x_bv)){
    	 cout<<"verify succ"<<endl;
         //assert(verify_proof(keypair.vk, *proof, h1_bv, h2_bv, h3_bv));
     }else{
    	 cout<<"verify fail"<<endl;
     }
     dur = (double)(clock() - start);
     printf("Proof Verify Use Time:%f\n\n",(dur/CLOCKS_PER_SEC));

     assert(!verify_proof(verifycation_in, proof_in, h3_bv, h2_bv, h1_bv,x_bv));//正常时检验失败，通过取反，通过断言

     /*
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
     */
}


