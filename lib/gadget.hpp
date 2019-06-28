#include "libsnark/gadgetlib1/gadgets/hashes/sha256/sha256_gadget.hpp"
#include "algebra/fields/field_utils.hpp"
#include "utils.hpp"

//const size_t sha256_digest_len = 256;

/*
computed by:

        unsigned long long bitlen = 256;

        unsigned char padding[32] = {0x80, 0x00, 0x00, 0x00, // 24 bytes of padding
                                     0x00, 0x00, 0x00, 0x00,
                                     0x00, 0x00, 0x00, 0x00,
                                     0x00, 0x00, 0x00, 0x00,
                                     0x00, 0x00, 0x00, 0x00,
                                     0x00, 0x00, 0x00, 0x00,
                                     bitlen >> 56, bitlen >> 48, bitlen >> 40, bitlen >> 32, // message length
                                     bitlen >> 24, bitlen >> 16, bitlen >> 8, bitlen
                                    };

        std::vector<bool> padding_bv(256);

        convertBytesToVector(padding, padding_bv);

        printVector(padding_bv);
*/
bool sha256_padding[256] = {1,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
                            0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
                            0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
                            0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
                            0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
                            0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
                            0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,
                            0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,1, 0,0,0,0,0,0,0,0};


//=======================================================================

template<typename FieldT>
class l_gadget : public gadget<FieldT> {
public:
    pb_variable_array<FieldT> input_as_field_elements; /* R1CS input */
    pb_variable_array<FieldT> input_as_bits; /* unpacked R1CS input */
    std::shared_ptr<multipacking_gadget<FieldT> > unpack_inputs; /* multipacking gadget */

   /* R1CS constraints for computing sum_i 2^i *x_i where [x_i] is bit-array */

    pb_variable_array<FieldT> intermediate_val1;
    pb_variable_array<FieldT> intermediate_val2;
    pb_variable_array<FieldT> intermediate_val3;
    pb_variable_array<FieldT> intermediate_valx;

    pb_variable_array<FieldT> zk_vpub_old;
    pb_variable_array<FieldT> zk_vpub_new;

    pb_variable_array<FieldT> zk_t1;
    pb_variable_array<FieldT> zk_t2;
    pb_variable_array<FieldT> zk_t3;

    std::shared_ptr<digest_variable<FieldT>> h1_var; /* H(R1) */
    std::shared_ptr<digest_variable<FieldT>> h2_var; /* H(R2) */
    std::shared_ptr<digest_variable<FieldT>> h3_var; /* H(R3) */

    std::shared_ptr<digest_variable<FieldT>> r1_var; /* R1 */
    std::shared_ptr<digest_variable<FieldT>> r2_var; /* R2 */
    std::shared_ptr<digest_variable<FieldT>> r3_var; /* R3 */
    std::shared_ptr<digest_variable<FieldT>> x_var; /* X */

    std::shared_ptr<block_variable<FieldT>> h_r1_block; /* 512 bit block that contains r1 + padding */
    std::shared_ptr<sha256_compression_function_gadget<FieldT>> h_r1; /* hashing gadget for r1 */

    std::shared_ptr<block_variable<FieldT>> h_r2_block; /* 512 bit block that contains r2 + padding */
    std::shared_ptr<sha256_compression_function_gadget<FieldT>> h_r2; /* hashing gadget for r2 */

    std::shared_ptr<block_variable<FieldT>> h_r3_block; /* 512 bit block that contains r3 + padding */
    std::shared_ptr<sha256_compression_function_gadget<FieldT>> h_r3; /* hashing gadget for r3 */


    pb_variable<FieldT> zero;
    pb_variable_array<FieldT> padding_var; /* SHA256 length padding */


    l_gadget(protoboard<FieldT> &pb) : gadget<FieldT>(pb, "l_gadget")
    {
        // Allocate space for the verifier input.
        const size_t input_size_in_bits = sha256_digest_len * 4;
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
        intermediate_valx.allocate(this->pb, sha256_digest_len, "intermediate_valx");

        zk_t1.allocate(this->pb, sha256_digest_len, "zk_t1");
        zk_t2.allocate(this->pb, sha256_digest_len, "zk_t2");
        zk_t3.allocate(this->pb, sha256_digest_len, "zk_t3");


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
        x_var.reset(new digest_variable<FieldT>(pb, sha256_digest_len, "x"));

        input_as_bits.insert(input_as_bits.end(), h1_var->bits.begin(), h1_var->bits.end());
        input_as_bits.insert(input_as_bits.end(), h2_var->bits.begin(), h2_var->bits.end());
        input_as_bits.insert(input_as_bits.end(), h3_var->bits.begin(), h3_var->bits.end());
        input_as_bits.insert(input_as_bits.end(), x_var->bits.begin(), x_var->bits.end());

        // Multipacking
        assert(input_as_bits.size() == input_size_in_bits);
        unpack_inputs.reset(new multipacking_gadget<FieldT>(this->pb, input_as_bits, input_as_field_elements, FieldT::capacity(), FMT(this->annotation_prefix, " unpack_inputs")));

        // Prover inputs:
        r1_var.reset(new digest_variable<FieldT>(pb, sha256_digest_len, "r1"));
        r2_var.reset(new digest_variable<FieldT>(pb, sha256_digest_len, "r2"));
        r3_var.reset(new digest_variable<FieldT>(pb, sha256_digest_len, "r3"));


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



    }

    void generate_r1cs_constraints()//const int jw[])
    {
        // Multipacking constraints (for input validation)
        unpack_inputs->generate_r1cs_constraints(true);

        // Ensure bitness of the digests. Bitness of the inputs
        // is established by `unpack_inputs->generate_r1cs_constraints(true)`
        r1_var->generate_r1cs_constraints();
        r2_var->generate_r1cs_constraints();
        r3_var->generate_r1cs_constraints();

        generate_r1cs_equals_const_constraint<FieldT>(this->pb, zero, FieldT::zero(), "zero");

        //后期需要验证r1cs_constraint 约束是否支持负数计算约束
        /*
         * 经验证，约束支持负数计算
        this->pb.add_r1cs_constraint(
                r1cs_constraint<FieldT>(
                        { 300 },
                        { 1 },
                        { 100, 100,-100}),
                FMT(this->annotation_prefix, "finalsum_test_negative", 0));
        */

        {
            linear_combination<FieldT> left_side = packed_addition(zk_vpub_old);
            linear_combination<FieldT> right_side = packed_addition(zk_vpub_new);

            left_side = left_side + packed_addition(intermediate_val1);

            right_side = right_side + packed_addition(intermediate_val2);
            right_side = right_side + packed_addition(intermediate_val3);
            right_side = right_side + packed_addition(intermediate_valx);

            // Ensure that both sides are equal
            this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(
                    1,
                    left_side,
                    right_side
            ));
        }


        //进行R_i=A_i+R_i+M_i 和 X=AR_1-AR_2-AR_3 的约束检查
        //当输入的R_i其中的包含负数攻击平衡的金额时，其输入的A_i,R_i,M_i无法通过检查，即不可能在现有约束下提供有效的A_i,R_i,M_i使负数攻击平衡攻击的数据通过
        {
            linear_combination<FieldT> left_side_t = packed_addition(zk_vpub_old);
            linear_combination<FieldT> right_side_t = packed_addition(zk_vpub_new);

            left_side_t = left_side_t + packed_addition(zk_t1);

            right_side_t = right_side_t + packed_addition(zk_t2);
            right_side_t = right_side_t + packed_addition(zk_t3);


            // Ensure that both sides are equal
            this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(
                    1,
                    left_side_t,
                    right_side_t
            ));
        }

        //疑似存在证明数据伪造的可能，其下约束本质不是检查的左右两边数值相等，而是把输入转化为字节数组并结算加法累进位数组之后进行的每字节上的数值平衡检查，
        //攻击者可能在本地伪造包含负数的加法累进数组使以下约束通过检查但其输入值不必是左右平衡的
        //解决方案：增加对进位数据的正数约束检查；增加对原始金额数据的正数约束检查
        /*
        for (unsigned int i = 31; i > 0 ; i--) { //不对最高byte进行检查
            this->pb.add_r1cs_constraint(
                r1cs_constraint<FieldT>(
                    { intermediate_val1[i]+jw[i-1]*256}, //jw[i]*256 进制平衡
                    { 1 },
                    { intermediate_val2[i], intermediate_val3[i],intermediate_valx[i],jw[i] }),
                FMT(this->annotation_prefix, "finalsum_%zu", 0));
        }
        */

        // These are the constraints to ensure the hashes validate.
        h_r1->generate_r1cs_constraints();
        h_r2->generate_r1cs_constraints();
        h_r3->generate_r1cs_constraints();
    }


    void generate_r1cs_witness(const bit_vector &h1,
                               const bit_vector &h2,
                               const bit_vector &h3,
                               const bit_vector &r1,
                               const bit_vector &r2,
                               const bit_vector &r3,
							   const bit_vector &x
                              )
    {
        // Fill our digests with our witnessed data
        r1_var->bits.fill_with_bits(this->pb, r1);
        r2_var->bits.fill_with_bits(this->pb, r2);
        r3_var->bits.fill_with_bits(this->pb, r3);
        x_var->bits.fill_with_bits(this->pb, x);
        
        cout<<"start test for bv2iv..."<<endl;

        std::vector<FieldT> iv1= bv2iv2<FieldT>(r1);
        std::vector<FieldT> iv2= bv2iv2<FieldT>(r2);
        std::vector<FieldT> iv3= bv2iv2<FieldT>(r3);
        std::vector<FieldT> ivx= bv2iv2<FieldT>(x);

        //以下是对R=a+r+m 的计算约束测试，在正常情况下针对每一个R_x参数需要提供对应的a_x,r_x,m_x的数据，通过计算约束其 R_x=a_x+r_x+m_x, X=AR_1-AR2-AR3 ; ar_i=a_i+r_i
        //以此验证使得输入的m_x只能是正数数，解决可能存在的计算平衡中存在负数平衡的攻击情况
        int t1[32]={0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,100};
        int t2[32]={0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,50};
        int t3[32]={0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,50};
        std::vector<bool> v_t1= iv2bv(t1);
        std::vector<bool> v_t2= iv2bv(t2);
        std::vector<bool> v_t3= iv2bv(t3);
        std::vector<FieldT> v_iv1= bv2iv2<FieldT>(v_t1);
        std::vector<FieldT> v_iv2= bv2iv2<FieldT>(v_t2);
        std::vector<FieldT> v_iv3= bv2iv2<FieldT>(v_t3);
        zk_t1.fill_with_field_elements(this->pb,v_iv1);
        zk_t2.fill_with_field_elements(this->pb,v_iv2);
        zk_t3.fill_with_field_elements(this->pb,v_iv3);
/*
        cout<< iv1<<endl;
        cout<< iv2<<endl;
        cout<< iv3<<endl;
        cout<< ivx<<endl;
*/

        intermediate_val1.fill_with_field_elements(this->pb, iv1);
        intermediate_val2.fill_with_field_elements(this->pb, iv2);
        intermediate_val3.fill_with_field_elements(this->pb, iv3);
        intermediate_valx.fill_with_field_elements(this->pb, ivx);



        // Set the zero pb_variable to zero
        this->pb.val(zero) = FieldT::zero();

        // Generate witnesses as necessary in our other gadgets
        h_r1->generate_r1cs_witness();
        h_r2->generate_r1cs_witness();
        h_r3->generate_r1cs_witness();
        unpack_inputs->generate_r1cs_witness_from_bits();

        h1_var->bits.fill_with_bits(this->pb, h1);
        h2_var->bits.fill_with_bits(this->pb, h2);
        h3_var->bits.fill_with_bits(this->pb, h3);
    }
};


