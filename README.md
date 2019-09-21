
This is a SNARK implementation using libsnark for the following:

``ZkPoK{ (R1,R2, ... ,RN): Hi = sha256(Ri) and R1+R2=R3+R4+ ... +RN and Ri>=0``

Read: given public values `H1`, `H2`,  ... `HN`, prove you know secret integers `R1`, `R2`,  ... `RN` 。

## Performances

on my computer (Deepin CPUi5 2.8*4,Mem 32G):

* **Generate keypair Use Time:39.996031**
* **Proof Generated Use Time:5.456362**
* **Proof Verify Use Time:0.028835**
* **Proof size in bits: 2294**

# Requirements

| Requirement | Notes           |
| ----------- | --------------- |
| gcc          | 5.0 or higher |

Here are the requisite packages in some Linux distributions:

* On Ubuntu 18 LTS:

        sudo apt-get install build-essential cmake git libgmp3-dev libprocps-dev python-markdown libboost-all-dev libssl-dev

* On Ubuntu 16 LTS:

        sudo apt-get install build-essential cmake git libgmp3-dev libprocps4-dev python-markdown libboost-all-dev libssl-dev

* On Ubuntu 14 LTS:

        sudo apt-get install build-essential cmake git libgmp3-dev libprocps3-dev python-markdown libboost-all-dev libssl-dev

## Compile
``CURVE=ALT_BN128 ./get-libsnark``
``make libMultiInput_static``
## Test
``make libMultiInput_test``
``./libzero_knowledge``
## Copy static lib to go project 
``make cpMultiInput_static``
## Copy prove data files to go project 
``make cpKey``

## Anatomy

* `src/libMultiInput/gadget_neg.hpp` exposes the gadget, which is an abstraction of related constraint and witness behavior in a circuit. This gadget uses other gadgets, creates its own constraints, and exposes an interface for building input maps.

* `src/libMultiInput/snark.hpp` exposes a loose wrapper around the constraint system and key generation used by `lib_zero_knowledge.cpp` to construct proofs and verify them as necessary.
