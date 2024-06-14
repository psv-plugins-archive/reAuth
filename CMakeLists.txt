#
#   Copyright (C) 2021 Reiko Asakura. All Rights Reserved.
#
#   reAuth
#

cmake_minimum_required(VERSION 3.19)

set(CMAKE_TOOLCHAIN_FILE "$ENV{SCE_PSP2_SDK_DIR}/host_tools/build/cmake/psp2-snc-toolchain.cmake")

project(reAuth LANGUAGES C)

include(VitaDevelopmentSuite)
enable_language(EMD)
set(CMAKE_C_STANDARD 99)

add_compile_options(
  -Xdiag=2 -Xquit=2
)

add_link_options(
  --prx-no-runtime-support
  --strip-duplicates
  --strip-unused-data
)

link_directories(
  ${VDSUITE_LIBRARY_DIRECTORIES}
)

add_compile_definitions(
  SCE_DBG_LOGGING_ENABLED=$<IF:$<CONFIG:Release,MinSizeRel>,0,1>
)

# Kernel module

add_library(reAuth MODULE
  reauth.c
  reauth.emd
  module.c
  patch.c
)

target_link_libraries(reAuth
  taihenForKernel_stub
  taihenModuleUtils_stub
  SceIofilemgrForDriver_stub
  SceModulemgrForDriver_stub
  SceSysclibForDriver_stub
  SceSysmemForDriver_stub
  SceSysrootForDriver_stub
  SceThreadmgrForDriver_stub
  $<$<NOT:$<CONFIG:Release,MinSizeRel>>:SceDbgForKernel_stub>
)

target_include_directories(reAuth SYSTEM
  PRIVATE
    ${VDSUITE_KERNEL_INCLUDE_DIRECTORIES}
)

target_compile_definitions(reAuth
  PRIVATE
    TAIHEN_KERNEL=1
    SCE_DBG_LOG_COMPONENT="\\033[0;31;1mreAuth\\033[0m"
)

VDSuiteSignElf(reAuth.skprx reAuth)

# User module

add_library(reAuthUser MODULE
  reauth-user.c
  reauth-user.emd
  patch.c
)

target_link_libraries(reAuthUser
  taihen_stub
  SceKernel_stub
  $<$<NOT:$<CONFIG:Release,MinSizeRel>>:SceDbg_stub>
)

target_include_directories(reAuthUser SYSTEM
  PRIVATE
    ${VDSUITE_USER_INCLUDE_DIRECTORIES}
)

target_compile_definitions(reAuthUser
  PRIVATE
    SCE_DBG_LOG_COMPONENT="\\033[0;33;1mreAuth\\033[0m"
)

VDSuiteSignElf(reAuth.suprx reAuthUser)
