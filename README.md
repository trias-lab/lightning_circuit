
This is a SNARK implementation using libsnark for the following:

``ZkPoK{ (R1||S1, R2||S2, R3||S3): Hi = sha256(Ri||Si) and R3 = R1 + R2 }``

Read: given public values `H1`, `H2`, `H3`, prove you know secret integers `R1`, `R2`, `R3` and secret 16-byte salt values `S1`, `S2`, `S3` such that the concatenation `R1||S1` is the SHA256 preimage of `H1`, `R2||S2` is the SHA256 preimage of `H2`, `R3||S3` is the preimage of `H3`, and `R3 = R1 + R2`.

This is an implementation and benchmark of the "Receive" zk-SNARK in the Confidential Transaction scheme from this article: <https://media.consensys.net/introduction-to-zksnarks-with-examples-3283b554fc3b>.

Code based on <https://github.com/ebfull/lightning_circuit>.

## performance

on my computer (MacBook Pro Early 2015):

* **key generation time**: 22.1s
* **proof generation time**: 5.14s
* **verification time**: 0.1445s
* **proof size**: 2294 bits
* **proving key size**: 153200114 bits
* **verifying key size**: 4586 bits
* **R1CS constraints**: 83766 (mostly sha256-related)

## performance me

on my computer (Deepin CPUi5 2.8*4,Mem 32G):

* **Generate keypair Use Time:36.996031**
* **Proof Generated Use Time:5.456362**
* **Proof Verify Use Time:0.028835**
* **Proof size in bits: 2294**


## howto

``./get-libsnark && make && ./test``

## anatomy

* `src/gadget.hpp` exposes the gadget, which is an abstraction of related constraint
and witness behavior in a circuit. This gadget uses other gadgets, creates its own
constraints, and exposes an interface for building input maps.

* `src/snark.hpp` exposes a loose wrapper around the constraint system and
key generation used by `test.cpp` to construct proofs and verify them as necessary.
