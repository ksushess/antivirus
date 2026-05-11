cmake_minimum_required(VERSION 3.21)
project(antivirus LANGUAGES C CXX)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

add_compile_definitions(UNICODE _UNICODE WIN32_LEAN_AND_MEAN NOMINMAX)

set(RPC_IDL "${CMAKE_CURRENT_SOURCE_DIR}/antivirus_rpc.idl")
set(RPC_GEN_DIR "${CMAKE_CURRENT_BINARY_DIR}/generated/rpc")
set(RPC_HEADER "${RPC_GEN_DIR}/antivirus_rpc.h")
set(RPC_CLIENT_STUB "${RPC_GEN_DIR}/antivirus_rpc_c.c")
set(RPC_SERVER_STUB "${RPC_GEN_DIR}/antivirus_rpc_s.c")
set(MIDL_STAGE_DIR "$ENV{TEMP}/antivirus_midl_stage")
set(MIDL_STAGE_INPUT "${MIDL_STAGE_DIR}/antivirus_rpc.idl")
set(MIDL_STAGE_HEADER "${MIDL_STAGE_DIR}/antivirus_rpc.h")
set(MIDL_STAGE_CLIENT_STUB "${MIDL_STAGE_DIR}/antivirus_rpc_c.c")
set(MIDL_STAGE_SERVER_STUB "${MIDL_STAGE_DIR}/antivirus_rpc_s.c")

file(GLOB MIDL_CANDIDATES
    "C:/Program Files (x86)/Windows Kits/10/bin/*/x64/midl.exe"
)
list(SORT MIDL_CANDIDATES COMPARE NATURAL ORDER DESCENDING)
list(GET MIDL_CANDIDATES 0 MIDL_EXECUTABLE)

if(NOT MIDL_EXECUTABLE)
    message(FATAL_ERROR "Unable to locate midl.exe in the Windows SDK.")
endif()

if(CMAKE_SIZEOF_VOID_P EQUAL 8)
    set(MIDL_ENV x64)
else()
    set(MIDL_ENV win32)
endif()

get_filename_component(MSVC_BIN_DIR "${CMAKE_C_COMPILER}" DIRECTORY)
file(TO_NATIVE_PATH "${MSVC_BIN_DIR}" MSVC_BIN_DIR_NATIVE)
file(TO_NATIVE_PATH "${MIDL_EXECUTABLE}" MIDL_EXECUTABLE_NATIVE)
file(TO_NATIVE_PATH "${MIDL_STAGE_DIR}" MIDL_STAGE_DIR_NATIVE)
file(TO_NATIVE_PATH "${MIDL_STAGE_INPUT}" MIDL_STAGE_INPUT_NATIVE)

set(MIDL_WRAPPER "${CMAKE_CURRENT_BINARY_DIR}/run_midl.bat")
file(WRITE "${MIDL_WRAPPER}" "@echo off\r\n")
file(APPEND "${MIDL_WRAPPER}" "setlocal\r\n")
file(APPEND "${MIDL_WRAPPER}" "set \"PATH=${MSVC_BIN_DIR_NATIVE};%PATH%\"\r\n")
file(APPEND "${MIDL_WRAPPER}" "\"${MIDL_EXECUTABLE_NATIVE}\" /nologo /app_config /env ${MIDL_ENV} /no_cpp /notlb /out \"${MIDL_STAGE_DIR_NATIVE}\" /header antivirus_rpc.h /cstub antivirus_rpc_c.c /sstub antivirus_rpc_s.c \"${MIDL_STAGE_INPUT_NATIVE}\"\r\n")

add_custom_command(
    OUTPUT
        "${RPC_HEADER}"
        "${RPC_CLIENT_STUB}"
        "${RPC_SERVER_STUB}"
    COMMAND "${CMAKE_COMMAND}" -E make_directory "${RPC_GEN_DIR}"
    COMMAND "${CMAKE_COMMAND}" -E make_directory "${MIDL_STAGE_DIR}"
    COMMAND "${CMAKE_COMMAND}" -E copy_if_different "${RPC_IDL}" "${MIDL_STAGE_INPUT}"
    COMMAND "${MIDL_WRAPPER}"
    COMMAND "${CMAKE_COMMAND}" -E copy_if_different "${MIDL_STAGE_HEADER}" "${RPC_HEADER}"
    COMMAND "${CMAKE_COMMAND}" -E copy_if_different "${MIDL_STAGE_CLIENT_STUB}" "${RPC_CLIENT_STUB}"
    COMMAND "${CMAKE_COMMAND}" -E copy_if_different "${MIDL_STAGE_SERVER_STUB}" "${RPC_SERVER_STUB}"
    DEPENDS "${RPC_IDL}"
    VERBATIM
)

add_executable(antivirus WIN32
    antivirus.cpp
    rpc_client.cpp
    "${RPC_CLIENT_STUB}"
)
target_include_directories(antivirus PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}"
    "${RPC_GEN_DIR}"
)
target_link_libraries(antivirus PRIVATE
    advapi32
    rpcrt4
    shell32
    user32
)

add_executable(antivirus_service
    service.cpp
    rpc_client.cpp
    ziopvo_client.cpp
    "${RPC_CLIENT_STUB}"
    "${RPC_SERVER_STUB}"
)
set_source_files_properties("${RPC_SERVER_STUB}" PROPERTIES
    COMPILE_DEFINITIONS "RequestServiceStop=ServiceRequestServiceStop;GetAuthenticationState=ServiceGetAuthenticationState;LoginUser=ServiceLoginUser;LogoutUser=ServiceLogoutUser;GetLicenseState=ServiceGetLicenseState;ActivateProduct=ServiceActivateProduct"
)
target_include_directories(antivirus_service PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}"
    "${RPC_GEN_DIR}"
)
target_link_libraries(antivirus_service PRIVATE
    advapi32
    crypt32
    iphlpapi
    rpcrt4
    user32
    userenv
    winhttp
    wtsapi32
)
