#include "libsnark/gadgetlib1/gadgets/hashes/sha256/sha256_gadget.hpp"
#include "algebra/fields/field_utils.hpp"
#include "utils.hpp"

bool sha256_padding[256] = {1,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
                            0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
                            0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
                            0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
                            0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
                            0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
                            0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
                            0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,1, 0,0,0,0,0,0,0,0};


const int MAX_INPUT_NUMBER = 10;
const int MAX_OUTPUT_NUMBER = 2;


//Trias 中经转化的计算平衡式为input_var[0] + ... + input_var[9] + x = output_var[0] + output_var[1]
//其中input_var[0-9], x, output_var[0-1] 都为正数
template<typename FieldT>
class l_gadget_neg : public gadget<FieldT> {
public:
    pb_variable_array<FieldT> input_as_field_elements; /* R1CS input */
    pb_variable_array<FieldT> input_as_bits; /* unpacked R1CS input */
    std::shared_ptr<multipacking_gadget<FieldT> > unpack_inputs; /* multipacking gadget */

   /* R1CS constraints for computing sum_i 2^i *x_i where [x_i] is bit-array */

	pb_variable_array<FieldT> intermediate_input_val[MAX_INPUT_NUMBER];
    pb_variable_array<FieldT> intermediate_output_val[MAX_OUTPUT_NUMBER];
    pb_variable_array<FieldT> intermediate_x_val;
	
    std::shared_ptr<digest_variable<FieldT>> hash_input_var[MAX_INPUT_NUMBER];
	std::shared_ptr<digest_variable<FieldT>> hash_output_var[MAX_OUTPUT_NUMBER];

	std::shared_ptr<digest_variable<FieldT>> input_var[MAX_INPUT_NUMBER];
	std::shared_ptr<digest_variable<FieldT>> output_var[MAX_OUTPUT_NUMBER];
    std::shared_ptr<digest_variable<FieldT>> x_var; /* X */

	std::shared_ptr<block_variable<FieldT>> input_var_block[MAX_INPUT_NUMBER];
	std::shared_ptr<sha256_compression_function_gadget<FieldT>> input_hash_gadget[MAX_INPUT_NUMBER];

	std::shared_ptr<block_variable<FieldT>> output_var_block[MAX_OUTPUT_NUMBER];
	std::shared_ptr<sha256_compression_function_gadget<FieldT>> output_hash_gadget[MAX_OUTPUT_NUMBER];

    pb_variable<FieldT> zero;
    pb_variable_array<FieldT> padding_var; /* SHA256 length padding */


    l_gadget_neg(protoboard<FieldT> &pb) : gadget<FieldT>(pb, "l_gadget_neg")
    {
        // Allocate space for the verifier input.
        const size_t input_size_in_bits = sha256_digest_len * (MAX_INPUT_NUMBER + MAX_OUTPUT_NUMBER + 1);
        {
            // We use a "multipacking" technique which allows us to constrain
            // the input bits in as few field elements as possible.
            const size_t input_size_in_field_elements = div_ceil(input_size_in_bits, FieldT::capacity());

            std::cout << "**************** input_size_in_field_elements: " << input_size_in_field_elements << "\n";
            std::cout << "**************** FieldT::capacity(): " << FieldT::capacity() << "\n";
            input_as_field_elements.allocate(pb, input_size_in_field_elements, "input_as_field_elements");
            this->pb.set_input_sizes(input_size_in_field_elements);
        }

        zero.allocate(this->pb, FMT(this->annotation_prefix, "zero"));

		for(int i=0; i<MAX_INPUT_NUMBER; i++) {
			stringstream ss;
			ss << "intermediate_input_val"; 
			ss << (i+1);
			intermediate_input_val[i].allocate(this->pb, sha256_digest_len, ss.str());
		}
		for(int i=0; i<MAX_OUTPUT_NUMBER; i++) {
			stringstream ss;
			ss << "intermediate_output_val"; 
			ss << (i+1);
			intermediate_output_val[i].allocate(this->pb, sha256_digest_len, ss.str());
		}
		intermediate_x_val.allocate(this->pb, sha256_digest_len, "intermediate_x_val");

        // SHA256's length padding
        for (size_t i = 0; i < 256; i++) {
            if (sha256_padding[i])
                padding_var.emplace_back(ONE);
            else
                padding_var.emplace_back(zero);
        }

        // Verifier inputs:
		for(int i=0; i<MAX_INPUT_NUMBER; i++) {
			stringstream ss;
			ss << "hash_input_var"; 
			ss << (i+1);
			hash_input_var[i].reset(new digest_variable<FieldT>(pb, sha256_digest_len, ss.str()));
		}
		for(int i=0; i<MAX_OUTPUT_NUMBER; i++) {
			stringstream ss;
			ss << "hash_output_var"; 
			ss << (i+1);
			hash_output_var[i].reset(new digest_variable<FieldT>(pb, sha256_digest_len, ss.str()));
		}
        x_var.reset(new digest_variable<FieldT>(pb, sha256_digest_len, "x"));

		for(int i=0; i<MAX_INPUT_NUMBER; i++) {
			input_as_bits.insert(input_as_bits.end(), hash_input_var[i]->bits.begin(), hash_input_var[i]->bits.end());
		}
		for(int i=0; i<MAX_OUTPUT_NUMBER; i++) {
			input_as_bits.insert(input_as_bits.end(), hash_output_var[i]->bits.begin(), hash_output_var[i]->bits.end());
		}
        input_as_bits.insert(input_as_bits.end(), x_var->bits.begin(), x_var->bits.end());
		

        // Multipacking
        assert(input_as_bits.size() == input_size_in_bits);
        unpack_inputs.reset(new multipacking_gadget<FieldT>(this->pb, input_as_bits, input_as_field_elements, FieldT::capacity(), FMT(this->annotation_prefix, " unpack_inputs")));

        // Prover inputs:
		for(int i=0; i<MAX_INPUT_NUMBER; i++) {
			stringstream ss;
			ss << "input_var"; 
			ss << (i+1);
			input_var[i].reset(new digest_variable<FieldT>(pb, sha256_digest_len, ss.str()));
		}
		for(int i=0; i<MAX_OUTPUT_NUMBER; i++) {
			stringstream ss;
			ss << "output_var"; 
			ss << (i+1);
			output_var[i].reset(new digest_variable<FieldT>(pb, sha256_digest_len, ss.str()));
		}

        // IV for SHA256
        pb_linear_combination_array<FieldT> IV = SHA256_default_IV(pb);

        // Initialize the block gadget for input hash
		for(int i=0; i<MAX_INPUT_NUMBER; i++) {
			stringstream ss;
			ss << "input_var_block"; 
			ss << (i+1);
			input_var_block[i].reset(new block_variable<FieldT>(pb, {
           		 input_var[i]->bits,
           		 padding_var
        	}, ss.str()));
		}
		// Initialize the hash gadget for input hash
		for(int i=0; i<MAX_INPUT_NUMBER; i++) {
			stringstream ss;
			ss << "input_hash_gadget"; 
			ss << (i+1);
			input_hash_gadget[i].reset(new sha256_compression_function_gadget<FieldT>(pb,
                                                                  IV,
                                                                  input_var_block[i]->bits,
                                                                  *(hash_input_var[i]),
                                                                  ss.str() ));
		}


		// Initialize the block gadget for output hash
		for(int i=0; i<MAX_OUTPUT_NUMBER; i++) {
			stringstream ss;
			ss << "output_var_block"; 
			ss << (i+1);
			output_var_block[i].reset(new block_variable<FieldT>(pb, {
           		 output_var[i]->bits,
           		 padding_var
        	}, ss.str()));
		}
		// Initialize the hash gadget for output hash
		for(int i=0; i<MAX_OUTPUT_NUMBER; i++) {
			stringstream ss;
			ss << "output_hash_gadget"; 
			ss << (i+1);
			output_hash_gadget[i].reset(new sha256_compression_function_gadget<FieldT>(pb,
                                                                  IV,
                                                                  output_var_block[i]->bits,
                                                                  *(hash_output_var[i]),
                                                                  ss.str() ));
		}

    }

    void generate_r1cs_constraints()//const int jw[2][32])
    {
        // Multipacking constraints (for input validation)
        unpack_inputs->generate_r1cs_constraints(true);

        // Ensure bitness of the digests. Bitness of the inputs
        // is established by `unpack_inputs->generate_r1cs_constraints(true)`
		for(int i=0; i<MAX_INPUT_NUMBER; i++) {
			input_var[i]->generate_r1cs_constraints();
		}
		for(int i=0; i<MAX_OUTPUT_NUMBER; i++) {
			output_var[i]->generate_r1cs_constraints();
		}
        generate_r1cs_equals_const_constraint<FieldT>(this->pb, zero, FieldT::zero(), "zero");


        {
        	linear_combination<FieldT> left_side;
			for(int i=0; i<MAX_INPUT_NUMBER; i++) {
				left_side = left_side +  packed_addition( intermediate_input_val[i] );
			}
			left_side = left_side + packed_addition(intermediate_x_val);

			linear_combination<FieldT> right_side;
			for(int i=0; i<MAX_OUTPUT_NUMBER; i++) {
				right_side = right_side + packed_addition( intermediate_output_val[i] );
			}

            // Ensure that both sides are equal
            this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(
                    1,
                    left_side,
                    right_side
            ));
        }
        /*
        //R1+x=R2+R3
        for (unsigned int i = 31; i > 0 ; i--) { //不对最高byte进行检查
            this->pb.add_r1cs_constraint(
                r1cs_constraint<FieldT>(
                    { intermediate_val1[i]+intermediate_valx[i]+jw[1][i-1]*256+jw[0][i]}, //计算式两边平衡，通过jw来进行进位平衡
                    { 1 },
                    { intermediate_val2[i],intermediate_val3[i],jw[1][i],jw[0][i-1]*256}),
                FMT(this->annotation_prefix, "finalsum_%zu", 0));
        }
         */



        // These are the constraints to ensure the hashes validate.
        for(int i=0; i<MAX_INPUT_NUMBER; i++) {
			input_hash_gadget[i]->generate_r1cs_constraints();
		}
		for(int i=0; i<MAX_OUTPUT_NUMBER; i++) {
			output_hash_gadget[i]->generate_r1cs_constraints();
		}
		
    }


	void generate_r1cs_witness(const std::vector<bit_vector> &hash_input_vec,
									const std::vector<bit_vector> &hash_output_vec,
									const std::vector<bit_vector> &input_vec,
									const std::vector<bit_vector> &output_vec,
									const bit_vector &x
								  ) 
   {
   		// Fill our digests with our witnessed data
   		for(int i=0; i<MAX_INPUT_NUMBER; i++) {
			input_var[i]->bits.fill_with_bits(this->pb, input_vec[i]);
   		}
		for(int i=0; i<MAX_OUTPUT_NUMBER; i++) {
			output_var[i]->bits.fill_with_bits(this->pb, output_vec[i]);
   		}
		x_var->bits.fill_with_bits(this->pb, x);
		
		for(int i=0; i<MAX_INPUT_NUMBER; i++) {
			std::vector<FieldT> iv= bv2iv2<FieldT>(input_vec[i]);
			intermediate_input_val[i].fill_with_field_elements(this->pb, iv);
   		}
		for(int i=0; i<MAX_OUTPUT_NUMBER; i++) {
			std::vector<FieldT> iv= bv2iv2<FieldT>(output_vec[i]);
			intermediate_output_val[i].fill_with_field_elements(this->pb, iv);
		}
		{
			std::vector<FieldT> iv= bv2iv2<FieldT>(x);
			intermediate_x_val.fill_with_field_elements(this->pb, iv);
		}

		// Set the zero pb_variable to zero
        this->pb.val(zero) = FieldT::zero();

		// Generate witnesses as necessary in our other gadgets
		for(int i=0; i<MAX_INPUT_NUMBER; i++) {
			input_hash_gadget[i]->generate_r1cs_witness();
		}
		for(int i=0; i<MAX_OUTPUT_NUMBER; i++) {
			output_hash_gadget[i]->generate_r1cs_witness();
		}
		unpack_inputs->generate_r1cs_witness_from_bits();

		
		for(int i=0; i<MAX_INPUT_NUMBER; i++) {
			hash_input_var[i]->bits.fill_with_bits(this->pb, hash_input_vec[i]);
		}
		for(int i=0; i<MAX_OUTPUT_NUMBER; i++) {
			hash_output_var[i]->bits.fill_with_bits(this->pb, hash_output_vec[i]);
		}
    	
   }

};

