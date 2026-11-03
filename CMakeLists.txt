cmake_minimum_required(VERSION 3.18)

project(kpqc_lua VERSION 0.1.0 LANGUAGES C)

option(KPQC_TEST_ENTROPY "Build deterministic entropy hooks for KATs" OFF)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

if(NOT LUA_INCLUDE_DIR)
    find_package(Lua 5.1 REQUIRED)
endif()

set(KPQC_CORE_SOURCES
    native/core_aimer128f.c
    native/core_aimer128s.c
    native/core_aimer192f.c
    native/core_aimer192s.c
    native/core_aimer256f.c
    native/core_aimer256s.c
    native/core_haetae2.c
    native/core_haetae3.c
    native/core_haetae5.c
    native/core_ntruplus768.c
    native/core_ntruplus864.c
    native/core_ntruplus1152.c
    native/core_smaugt128.c
    native/core_smaugt192.c
    native/core_smaugt256.c
    native/core_timer.c
)

set(KPQC_HAETAE_SOURCES
    native/core_haetae2.c
    native/core_haetae3.c
    native/core_haetae5.c
)

set(KPQC_SMAUGT_SOURCES
    native/core_smaugt128.c
    native/core_smaugt192.c
    native/core_smaugt256.c
    native/core_timer.c
)

set_source_files_properties(
    ${KPQC_HAETAE_SOURCES}
    PROPERTIES INCLUDE_DIRECTORIES
        "${CMAKE_CURRENT_SOURCE_DIR}/native/third_party/HAETAE/include"
)
set_source_files_properties(
    native/core_ntruplus768.c
    PROPERTIES INCLUDE_DIRECTORIES
        "${CMAKE_CURRENT_SOURCE_DIR}/native/third_party/NTRUplus/NTRU+768"
)
set_source_files_properties(
    native/core_ntruplus864.c
    PROPERTIES INCLUDE_DIRECTORIES
        "${CMAKE_CURRENT_SOURCE_DIR}/native/third_party/NTRUplus/NTRU+864"
)
set_source_files_properties(
    native/core_ntruplus1152.c
    PROPERTIES INCLUDE_DIRECTORIES
        "${CMAKE_CURRENT_SOURCE_DIR}/native/third_party/NTRUplus/NTRU+1152"
)
set_source_files_properties(
    ${KPQC_SMAUGT_SOURCES}
    PROPERTIES INCLUDE_DIRECTORIES
        "${CMAKE_CURRENT_SOURCE_DIR}/native/third_party/SMAUG-T/include"
)

add_library(kpqc MODULE src/kpqc.c ${KPQC_CORE_SOURCES})
target_include_directories(kpqc PRIVATE "${LUA_INCLUDE_DIR}")
set_source_files_properties(
    src/kpqc.c
    PROPERTIES COMPILE_OPTIONS "-Wall;-Wextra;-Wpedantic"
)
set_target_properties(
    kpqc
    PROPERTIES
        C_VISIBILITY_PRESET hidden
        PREFIX ""
        OUTPUT_NAME "kpqc"
)

if(LUA_LIBRARIES)
    target_link_libraries(kpqc PRIVATE ${LUA_LIBRARIES})
elseif(APPLE)
    target_link_options(kpqc PRIVATE "LINKER:-undefined,dynamic_lookup")
endif()

if(UNIX)
    target_link_libraries(kpqc PRIVATE m)
endif()

if(KPQC_TEST_ENTROPY)
    target_compile_definitions(kpqc PRIVATE KPQC_TEST_ENTROPY)
    target_sources(kpqc PRIVATE native/test/aes.c native/test/aes_bridge.c)
endif()

if(NOT KPQC_LUA_INSTALL_DIR)
    set(KPQC_LUA_INSTALL_DIR "lib/lua")
endif()

install(
    TARGETS kpqc
    LIBRARY DESTINATION "${KPQC_LUA_INSTALL_DIR}"
    RUNTIME DESTINATION "${KPQC_LUA_INSTALL_DIR}"
)
