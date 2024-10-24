# evmone: Fast Ethereum Virtual Machine implementation
# Copyright 2022 The evmone Authors.
# SPDX-License-Identifier: Apache-2.0

add_executable(evm-devtools)
target_link_libraries(evm-devtools PRIVATE evmone::state evmc::evmc evmc::loader)
target_link_libraries(evm-devtools PRIVATE evmone evmone-buildinfo)
target_sources(evm-devtools PRIVATE main.cpp)

