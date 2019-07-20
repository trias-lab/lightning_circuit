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



//Trias 中经转化的计算平衡式为R1+R4=R2+R3+X ，其中R1，R2,R3,R4 都为正数，X可能为负数
//当X为负时，为简单计算，其平衡式转化为 R1+X+R4=R2+R3 ,并在本类中处理
template<typename FieldT>
class l_gadget_neg : public gadget<FieldT> {
public:
    pb_variable_array<FieldT> input_as_field_elements; /* R1CS input */
    pb_variable_array<FieldT> input_as_bits; /* unpacked R1CS input */
    std::shared_ptr<multipacking_gadget<FieldT> > unpack_inputs; /* multipacking gadget */

   /* R1CS constraints for computing sum_i 2^i *x_i where [x_i] is bit-array */

    pb_variable_array<FieldT> intermediate_val1;
    pb_variable_array<FieldT> intermediate_val2;
    pb_variable_array<FieldT> intermediate_val3;
	pb_variable_array<FieldT> intermediate_val4;
    pb_variable_array<FieldT> intermediate_valx;

    pb_variable_array<FieldT> zk_vpub_old;
    pb_variable_array<FieldT> zk_vpub_new;

    std::shared_ptr<digest_variable<FieldT>> h1_var; /* H(R1) */
    std::shared_ptr<digest_variable<FieldT>> h2_var; /* H(R2) */
    std::shared_ptr<digest_variable<FieldT>> h3_var; /* H(R3) */
	std::shared_ptr<digest_variable<FieldT>> h4_var; /* H(R4) */

    std::shared_ptr<digest_variable<FieldT>> r1_var; /* R1 */
    std::shared_ptr<digest_variable<FieldT>> r2_var; /* R2 */
    std::shared_ptr<digest_variable<FieldT>> r3_var; /* R3 */
	std::shared_ptr<digest_variable<FieldT>> r4_var; /* R3 */
    std::shared_ptr<digest_variable<FieldT>> x_var; /* X */

    std::shared_ptr<block_variable<FieldT>> h_r1_block; /* 512 bit block that contains r1 + padding */
    std::shared_ptr<sha256_compression_function_gadget<FieldT>> h_r1; /* hashing gadget for r1 */

    std::shared_ptr<block_variable<FieldT>> h_r2_block; /* 512 bit block that contains r2 + padding */
    std::shared_ptr<sha256_compression_function_gadget<FieldT>> h_r2; /* hashing gadget for r2 */

    std::shared_ptr<block_variable<FieldT>> h_r3_block; /* 512 bit block that contains r3 + padding */
    std::shared_ptr<sha256_compression_function_gadget<FieldT>> h_r3; /* hashing gadget for r3 */

	std::shared_ptr<block_variable<FieldT>> h_r4_block; /* 512 bit block that contains r4 + padding */
    std::shared_ptr<sha256_compression_function_gadget<FieldT>> h_r4; /* hashing gadget for r3 */


    pb_variable<FieldT> zero;
    pb_variable_array<FieldT> padding_var; /* SHA256 length padding */


    l_gadget_neg(protoboard<FieldT> &pb) : gadget<FieldT>(pb, "l_gadget_neg")
    {
        // Allocate space for the verifier input.
        const size_t input_size_in_bits = sha256_digest_len * 5;
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

        intermediate_val1.allocate(this->pb, sha256_digest_len, "intermediate_val1");
        intermediate_val2.allocate(this->pb, sha256_digest_len, "intermediate_val2");
        intermediate_val3.allocate(this->pb, sha256_digest_len, "intermediate_val3");
		intermediate_val4.allocate(this->pb, sha256_digest_len, "intermediate_val4");
        intermediate_valx.allocate(this->pb, sha256_digest_len, "intermediate_valx");


        // SHA256's length padding
        for (size_t i = 0; i < 256; i++) {
            if (sha256_padding[i])
                padding_var.emplace_back(ONE);
            else
                padding_var.emplace_back(zero);
        }

        // Verifier inputs:
        h1_var.reset(new digest_variable<FieldT>(pb, sha256_digest_len, "h1"));
        h2_var.reset(new digest_variable<FieldT>(pb, sha256_digest_len, "h2"));
        h3_var.reset(new digest_variable<FieldT>(pb, sha256_digest_len, "h3"));
		h4_var.reset(new digest_variable<FieldT>(pb, sha256_digest_len, "h4"));
        x_var.reset(new digest_variable<FieldT>(pb, sha256_digest_len, "x"));

        input_as_bits.insert(input_as_bits.end(), h1_var->bits.begin(), h1_var->bits.end());
        input_as_bits.insert(input_as_bits.end(), h2_var->bits.begin(), h2_var->bits.end());
        input_as_bits.insert(input_as_bits.end(), h3_var->bits.begin(), h3_var->bits.end());
		input_as_bits.insert(input_as_bits.end(), h4_var->bits.begin(), h4_var->bits.end());
        input_as_bits.insert(input_as_bits.end(), x_var->bits.begin(), x_var->bits.end());

        // Multipacking
        assert(input_as_bits.size() == input_size_in_bits);
        unpack_inputs.reset(new multipacking_gadget<FieldT>(this->pb, input_as_bits, input_as_field_elements, FieldT::capacity(), FMT(this->annotation_prefix, " unpack_inputs")));

        // Prover inputs:
        r1_var.reset(new digest_variable<FieldT>(pb, sha256_digest_len, "r1"));
        r2_var.reset(new digest_variable<FieldT>(pb, sha256_digest_len, "r2"));
        r3_var.reset(new digest_variable<FieldT>(pb, sha256_digest_len, "r3"));
		r4_var.reset(new digest_variable<FieldT>(pb, sha256_digest_len, "r4"));


        // IV for SHA256
        pb_linear_combination_array<FieldT> IV = SHA256_default_IV(pb);

        // Initialize the block gadget for r1's hash
        h_r1_block.reset(new block_variable<FieldT>(pb, {
            r1_var->bits,
            padding_var
        }, "h_r1_block"));

        // Initialize the hash gadget for r1's hash
        h_r1.reset(new sha256_compression_function_gadget<FieldT>(pb,
                                                                  IV,
                                                                  h_r1_block->bits,
                                                                  *h1_var,
                                                                  "h_r1"));

        // Initialize the block gadget for r2's hash
        h_r2_block.reset(new block_variable<FieldT>(pb, {
            r2_var->bits,
            padding_var
        }, "h_r2_block"));

        // Initialize the hash gadget for r2's hash
        h_r2.reset(new sha256_compression_function_gadget<FieldT>(pb,
                                                                  IV,
                                                                  h_r2_block->bits,
                                                                  *h2_var,
                                                                  "h_r2"));

        // Initialize the block gadget for r3's hash
        h_r3_block.reset(new block_variable<FieldT>(pb, {
            r3_var->bits,
            padding_var
        }, "h_r3_block"));

        // Initialize the hash gadget for r3's hash
        h_r3.reset(new sha256_compression_function_gadget<FieldT>(pb,
                                                                  IV,
                                                                  h_r3_block->bits,
                                                                  *h3_var,
                                                                  "h_r3"));
		

		// Initialize the block gadget for r4's hash
        h_r4_block.reset(new block_variable<FieldT>(pb, {
            r4_var->bits,
            padding_var
        }, "h_r4_block"));

        // Initialize the hash gadget for r4's hash
        h_r4.reset(new sha256_compression_function_gadget<FieldT>(pb,
                                                                  IV,
                                                                  h_r4_block->bits,
                                                                  *h4_var,
                                                                  "h_r4"));



    }

    void generate_r1cs_constraints()//const int jw[2][32])
    {
        // Multipacking constraints (for input validation)
        unpack_inputs->generate_r1cs_constraints(true);

        // Ensure bitness of the digests. Bitness of the inputs
        // is established by `unpack_inputs->generate_r1cs_constraints(true)`
        r1_var->generate_r1cs_constraints();
        r2_var->generate_r1cs_constraints();
        r3_var->generate_r1cs_constraints();
		r4_var->generate_r1cs_constraints();

        generate_r1cs_equals_const_constraint<FieldT>(this->pb, zero, FieldT::zero(), "zero");


        {
            linear_combination<FieldT> left_side = packed_addition(zk_vpub_old);
            linear_combination<FieldT> right_side = packed_addition(zk_vpub_new);

            left_side = left_side + packed_addition(intermediate_val1);
			left_side = left_side + packed_addition(intermediate_val4);
            left_side = left_side + packed_addition(intermediate_valx);

            right_side = right_side + packed_addition(intermediate_val2);
            right_side = right_side + packed_addition(intermediate_val3);

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
        h_r1->generate_r1cs_constraints();
        h_r2->generate_r1cs_constraints();
        h_r3->generate_r1cs_constraints();
		h_r4->generate_r1cs_constraints();
    }


    void generate_r1cs_witness(const bit_vector &h1,
                               const bit_vector &h2,
                               const bit_vector &h3,
                               const bit_vector &h4,
                               const bit_vector &r1,
                               const bit_vector &r2,
                               const bit_vector &r3,
                               const bit_vector &r4,
							   const bit_vector &x
                              )
    {
        // Fill our digests with our witnessed data
        r1_var->bits.fill_with_bits(this->pb, r1);
        r2_var->bits.fill_with_bits(this->pb, r2);
        r3_var->bits.fill_with_bits(this->pb, r3);
		r4_var->bits.fill_with_bits(this->pb, r4);
        x_var->bits.fill_with_bits(this->pb, x);
        
        cout<<"start test for bv2iv..."<<endl;

        std::vector<FieldT> iv1= bv2iv2<FieldT>(r1);
        std::vector<FieldT> iv2= bv2iv2<FieldT>(r2);
        std::vector<FieldT> iv3= bv2iv2<FieldT>(r3);
		std::vector<FieldT> iv4= bv2iv2<FieldT>(r4);
        std::vector<FieldT> ivx= bv2iv2<FieldT>(x);

        /*
        cout<< iv1<<endl;
        cout<< iv2<<endl;
        cout<< iv3<<endl;
        cout<< ivx<<endl;
		*/

        intermediate_val1.fill_with_field_elements(this->pb, iv1);
        intermediate_val2.fill_with_field_elements(this->pb, iv2);
        intermediate_val3.fill_with_field_elements(this->pb, iv3);
		intermediate_val4.fill_with_field_elements(this->pb, iv4);
        intermediate_valx.fill_with_field_elements(this->pb, ivx);

        // Set the zero pb_variable to zero
        this->pb.val(zero) = FieldT::zero();

        // Generate witnesses as necessary in our other gadgets
        h_r1->generate_r1cs_witness();
        h_r2->generate_r1cs_witness();
        h_r3->generate_r1cs_witness();
		h_r4->generate_r1cs_witness();
        unpack_inputs->generate_r1cs_witness_from_bits();

        h1_var->bits.fill_with_bits(this->pb, h1);
        h2_var->bits.fill_with_bits(this->pb, h2);
        h3_var->bits.fill_with_bits(this->pb, h3);
		h4_var->bits.fill_with_bits(this->pb, h4);
    }
};

