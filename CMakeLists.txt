cmake_minimum_required(VERSION 3.13)
project(lightning_circuit)

set(CMAKE_CXX_STANDARD 14)
set(CURRENT_DIR "/home/lab8/Git/Github/lightning_circuit")
set(PROJECT_BINARY_DIR "/home/lab8/Git/Github/lightning_circuit")


message("hello\n")
message(${CURRENT_DIR})
message(${PROJECT_BINARY_DIR})

#set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")

#使用cmake 调用 makefile （基于CLion）
#本质上是通过cmake调用make命令，执行指定目录下的makefile文件，根据需要指定编译目标
add_custom_target(zktrias COMMAND make -C ${CURRENT_DIR} zktrias
        CLION_EXE_DIR=${PROJECT_BINARY_DIR}
        )
