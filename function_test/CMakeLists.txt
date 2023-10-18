CMAKE_MINIMUM_REQUIRED(VERSION 3.2)

Project(tests)

file(GLOB TEST_SRCS
    ${CMAKE_CURRENT_LIST_DIR}/*.c)

foreach(SRC ${TEST_SRCS})

    get_filename_component(SRC_NAME ${SRC} NAME)
    string(REPLACE ".c" "" EXEC_NAME ${SRC_NAME})
    add_executable(${EXEC_NAME} ${SRC_NAME} )


endforeach()
