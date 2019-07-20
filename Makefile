DEPSRC=./depsrc
DEPINST=./depinst

OPTFLAGS = -march=native -mtune=native -O2
CXXFLAGS += -g -Wall -Wextra -Wno-unused-parameter -std=c++11 -fPIC -Wno-unused-variable
CXXFLAGS += -I $(DEPINST)/include -I $(DEPINST)/include/libsnark -DUSE_ASM -DCURVE_ALT_BN128
LDFLAGS += -flto

#DEPSRC=../zkSNARK-toy/depsrc
#DEPINST=../zkSNARK-toy/depinst

LDLIBS += -L $(DEPINST)/lib -Wl,-rpath $(DEPINST)/lib -L . -lsnark -lgmpxx -lgmp

# apt-get install libboost-program-options-1.60
# apt-get install libboost-all-dev
LDLIBS += -lboost_system


test:
	$(CXX) -o test.o src/test.cpp -c $(CXXFLAGS)
	$(CXX) -o test test.o $(CXXFLAGS) $(LDFLAGS) $(LDLIBS)

lib:
	$(CXX) -o libzero_knowledge.o src/lib/lib_zero_knowledge.cpp -c $(CXXFLAGS)
	$(CXX) -o libzero_knowledge.so libzero_knowledge.o -shared $(CXXFLAGS) $(LDFLAGS) $(LDLIBS)

lib_test:
	$(CXX) -o libzero_knowledge.o src/lib/lib_zero_knowledge.cpp -c $(CXXFLAGS)
	$(CXX) -o libzero_knowledge libzero_knowledge.o $(CXXFLAGS) $(LDFLAGS) $(LDLIBS)
	
libMultiInput:
	$(CXX) -o libzero_knowledge.o src/libMultiInput/lib_zero_knowledge.cpp -c $(CXXFLAGS)
	$(CXX) -o libzero_knowledge.so libzero_knowledge.o -shared $(CXXFLAGS) $(LDFLAGS) $(LDLIBS)

libMultiInput_test:
	$(CXX) -o libzero_knowledge.o src/libMultiInput/lib_zero_knowledge.cpp -c $(CXXFLAGS)
	$(CXX) -o libzero_knowledge libzero_knowledge.o $(CXXFLAGS) $(LDFLAGS) $(LDLIBS)	

zktrias:
	$(CXX) -o zktrias.o src/zkTrias/zktrias.cpp -c $(CXXFLAGS)
	$(CXX) -o zktrias zktrias.o $(CXXFLAGS) $(LDFLAGS) $(LDLIBS)
	#$(CXX) -o libzktrias.so zktrias.o -shared $(CXXFLAGS) $(LDFLAGS) $(LDLIBS)

clean:
	$(RM) *.o *.so test zktrias libzero_knowledge

cp:
	cp libzero_knowledge.so ~/gopath/src/tribc/cpp_lib/
	cp src/lib/lib_zero_knowledge.h ~/gopath/src/tribc/cpp_lib/
	
