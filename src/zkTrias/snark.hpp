#include "libsnark/gadgetlib1/gadgets/basic_gadgets.hpp"
#include "libsnark/zk_proof_systems/ppzksnark/r1cs_ppzksnark/r1cs_ppzksnark.hpp"
#include "libsnark/common/default_types/r1cs_ppzksnark_pp.hpp"
#include "libsnark/common/utils.hpp"
#include <boost/optional.hpp>

using namespace libsnark;
using namespace std;

#include "gadget.hpp"
#include "gadget_neg.hpp"


template<typename ppzksnark_ppT>
r1cs_ppzksnark_keypair<ppzksnark_ppT> generate_keypair(const int jw[32])
{
    typedef Fr<ppzksnark_ppT> FieldT;

    //根据预先定义的计算门和约束生成公共参数秘钥对
    //证明生成端若需要采用对应的公共秘钥生成证明数据成功，则必须使两端的数据符合预先定于的计算约束(R1=R2+R3+X)
    //如此，当验证端根据对应的验证秘钥验证证明数据为真时，验证者就能够相信对应的交易中是符合预定义的计算约束的，而不是生成假证明以通过检查
    protoboard<FieldT> pb;
    l_gadget<FieldT> g(pb);
    g.generate_r1cs_constraints();
    const r1cs_constraint_system<FieldT> constraint_system = pb.get_constraint_system();

    cout << "Number of R1CS constraints: " << constraint_system.num_constraints() << endl;

    return r1cs_ppzksnark_generator<ppzksnark_ppT>(constraint_system);
}

template<typename ppzksnark_ppT>
r1cs_ppzksnark_keypair<ppzksnark_ppT> generate_keypair_neg(const int jw[2][32])
{
    typedef Fr<ppzksnark_ppT> FieldT;

    //根据预先定义的计算门和约束生成公共参数秘钥对
    //证明生成端若需要采用对应的公共秘钥生成证明数据成功，则必须使两端的数据符合预先定于的计算约束(R1+X=R2+R3)
    //如此，当验证端根据对应的验证秘钥验证证明数据为真时，验证者就能够相信对应的交易中是符合预定义的计算约束的，而不是生成假证明以通过检查
    protoboard<FieldT> pb;
    l_gadget_neg<FieldT> g(pb);
    g.generate_r1cs_constraints();
    const r1cs_constraint_system<FieldT> constraint_system = pb.get_constraint_system();

    cout << "Number of R1CS constraints: " << constraint_system.num_constraints() << endl;

    return r1cs_ppzksnark_generator<ppzksnark_ppT>(constraint_system);
}

template<typename ppzksnark_ppT>
boost::optional<r1cs_ppzksnark_proof<ppzksnark_ppT>> generate_proof(r1cs_ppzksnark_proving_key<ppzksnark_ppT> proving_key,
                                                                   const bit_vector &h1,
                                                                   const bit_vector &h2,
                                                                   const bit_vector &h3,
                                                                   const bit_vector &r1,
                                                                   const bit_vector &r2,
                                                                   const bit_vector &r3,
																   const bit_vector &x,
																   const int jw[32]
                                                                   )
{
    typedef Fr<ppzksnark_ppT> FieldT;

    protoboard<FieldT> pb;
    l_gadget<FieldT> g(pb);
    g.generate_r1cs_constraints();
    g.generate_r1cs_witness(h1, h2, h3, r1, r2, r3,x);

    if (!pb.is_satisfied()) {
      std::cout << "System not satisfied!" << std::endl;
        return boost::none;
    }

    return r1cs_ppzksnark_prover<ppzksnark_ppT>(proving_key, pb.primary_input(), pb.auxiliary_input());
}

template<typename ppzksnark_ppT>
boost::optional<r1cs_ppzksnark_proof<ppzksnark_ppT>> generate_proof_neg(r1cs_ppzksnark_proving_key<ppzksnark_ppT> proving_key,
                                                                   const bit_vector &h1,
                                                                   const bit_vector &h2,
                                                                   const bit_vector &h3,
                                                                   const bit_vector &r1,
                                                                   const bit_vector &r2,
                                                                   const bit_vector &r3,
																   const bit_vector &x,
																   const int jw[2][32]
                                                                   )
{
    typedef Fr<ppzksnark_ppT> FieldT;

    protoboard<FieldT> pb;
    l_gadget_neg<FieldT> g(pb);
    g.generate_r1cs_constraints();
    g.generate_r1cs_witness(h1, h2, h3, r1, r2, r3,x);

    if (!pb.is_satisfied()) {
      std::cout << "System not satisfied!" << std::endl;
        return boost::none;
    }

    return r1cs_ppzksnark_prover<ppzksnark_ppT>(proving_key, pb.primary_input(), pb.auxiliary_input());
}

template<typename ppzksnark_ppT>
bool verify_proof(r1cs_ppzksnark_verification_key<ppzksnark_ppT> verification_key,
                  r1cs_ppzksnark_proof<ppzksnark_ppT> proof,
                  const bit_vector &h1,
                  const bit_vector &h2,
                  const bit_vector &h3,
				  const bit_vector &x
                 )
{
    typedef Fr<ppzksnark_ppT> FieldT;

    const r1cs_primary_input<FieldT> input = l_input_map<FieldT>(h1, h2, h3,x);

    std::cout << "**** After l_input_map *****" << std::endl;

    return r1cs_ppzksnark_verifier_strong_IC<ppzksnark_ppT>(verification_key, input, proof);

}


