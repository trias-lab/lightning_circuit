
This is a SNARK implementation using libsnark for the following:

``ZkPoK{ (R1,R2,R3): Hi = sha256(Ri) and R3=R1+R2 or R1+R2=R3``

Read: given public values `H1`, `H2`, `H3`, prove you know secret integers `R1`, `R2`, `R3` 。

This is an implementation and benchmark of the "Receive" zk-SNARK in the Confidential Transaction scheme from this article: <https://media.consensys.net/introduction-to-zksnarks-with-examples-3283b554fc3b>.

## performance me

on my computer (Deepin CPUi5 2.8*4,Mem 32G):

* **Generate keypair Use Time:39.996031**
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
