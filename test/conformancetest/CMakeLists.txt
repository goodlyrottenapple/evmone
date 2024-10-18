# evmone: Fast Ethereum Virtual Machine implementation
# Copyright 2022 The evmone Authors.
# SPDX-License-Identifier: Apache-2.0

# include(CableBuildInfo)
# cable_add_buildinfo_library(PROJECT_NAME evmone)

add_executable(evmone-conformancetest)
target_link_libraries(evmone-conformancetest PRIVATE evmone::state evmc::evmc evmc::loader)
target_link_libraries(evmone-conformancetest PRIVATE evmone evmone-buildinfo)
target_sources(evmone-conformancetest PRIVATE main.cpp)

