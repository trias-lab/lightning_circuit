//
// Created by lab8 on 1/25/19.
//
#ifndef UTILS_H
#define UTILS_H

const size_t sha256_digest_len = 256;


template<typename FieldT>
std::vector<FieldT> bv2iv(const bit_vector &v){
    int l=v.size()/8;
    std::vector<FieldT> rs;
    //cout << v.size()<<";"<<l<<endl;
    //int8_vector rs;
    int num_i=7;
    int num=0;
    for(unsigned i=0;i<v.size();i++){

        if(v[i]){
            num=num+(1<<num_i);
        }
        num_i--;

        if(num_i<0){ //存储int单元并归零
            //cout<<"Get int8:"<<num<<endl;
            rs.push_back(num);
            num_i=7;
            num=0;
        }
    }
    return rs;
}

template<typename FieldT>
std::vector<FieldT> bv2iv2(const bit_vector &v){
    std::vector<FieldT> rs;
    for(unsigned i=0;i<v.size();i++){
        rs.push_back(v[i]);
    }
    return rs;
}

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

/*
 * 对数据进行交换处理,适配在x86模式下的大小位存储问题
template<typename T>
T swap_endianness_u64(T v) {
    cout<< v.size()<<endl;
    for (size_t i = 0; i < 4; i++) {
        for (size_t j = 0; j < 8; j++) {
            std::swap(v[i*8 + j], v[((7-i)*8)+j]);
        }
    }

    return v;
}*/

template<typename FieldT>
linear_combination<FieldT> packed_addition(pb_variable_array<FieldT> input) {
    //auto input_swapped = swap_endianness_u64(input);

    //return pb_packing_sum<FieldT>(pb_variable_array<FieldT>(
    //      input_swapped.rbegin(), input_swapped.rend()
    //));
    return pb_packing_sum<FieldT>(pb_variable_array<FieldT>(
            input.rbegin(), input.rend()
    ));
}

																																	
template<typename FieldT>
r1cs_primary_input<FieldT> l_input_map(const std::vector<bit_vector> &hash_input_vec,
                                       const std::vector<bit_vector> &hash_output_vec,
                                       const bit_vector &x
)
{
	// Construct the multipacked field points which encode
    // the verifier's knowledge. This is the "dual" of the
    // multipacking gadget logic in the constructor.
    for(size_t  i=0; i<hash_input_vec.size(); i++) {
		assert(hash_input_vec[i].size() == sha256_digest_len);
	}
	for(size_t  i=0; i<hash_output_vec.size(); i++) {
		assert(hash_output_vec[i].size() == sha256_digest_len);
	}
	std::cout << "**** After assert(size() == sha256_digest_len) *****" << std::endl;

    bit_vector input_as_bits;
	for(size_t  i=0; i<hash_input_vec.size(); i++) {
		input_as_bits.insert(input_as_bits.end(), hash_input_vec[i].begin(), hash_input_vec[i].end());
	}
	for(size_t  i=0; i<hash_output_vec.size(); i++) {
		input_as_bits.insert(input_as_bits.end(), hash_output_vec[i].begin(), hash_output_vec[i].end());
	}
    input_as_bits.insert(input_as_bits.end(), x.begin(), x.end());
    std::vector<FieldT> input_as_field_elements = pack_bit_vector_into_field_element_vector<FieldT>(input_as_bits);

    std::cout << "**** After pack_bit_vector_into_field_element_vector *****" << std::endl;

    return input_as_field_elements;
}


#endif