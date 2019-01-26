cmake_minimum_required(VERSION 3.13)
project(lightning_circuit)

set(CMAKE_CXX_STANDARD 14)

include_directories(src)
include_directories(src/zkTrias)
include_directories(../zkSNARK-toy/depinst/include)
include_directories(../zkSNARK-toy/depinst/include/libsnark)

#打开注释，使工程标注对应文件为源码文件，可以在浏览工程时进行标签式浏览(若要正常编译构建通过，需要注释下面的cmake构建指令，当前需要通过最后面的make调用来构建工程
add_executable(test
        src/gadget.hpp
        src/snark.hpp
        src/test.cpp
        src/test.h)

add_executable(zktrias
        src/zkTrias/gadget.hpp
        src/zkTrias/utils.hpp
        src/zkTrias/gadget_neg.hpp
        src/zkTrias/snark.hpp
        src/zkTrias/zktrias.cpp
        src/zkTrias/zktrias.hpp)

set(CURRENT_DIR "/home/lab8/Git/Github/lightning_circuit")
set(PROJECT_BINARY_DIR "/home/lab8/Git/Github/lightning_circuit")


message("hello\n")
message(${CURRENT_DIR})
message(${PROJECT_BINARY_DIR})

#set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")

#使用cmake 调用 makefile （基于CLion）
#本质上是通过cmake调用make命令，执行指定目录下的makefile文件，根据需要指定编译目标
add_custom_target(zktrias_make COMMAND make -C ${CURRENT_DIR} zktrias
        CLION_EXE_DIR=${PROJECT_BINARY_DIR}
        )
