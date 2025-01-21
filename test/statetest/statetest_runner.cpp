// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2022 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#include "../state/mpt_hash.hpp"
#include "../state/rlp.hpp"
#include "statetest.hpp"
#include <gtest/gtest.h>
#include <evmone/vm.hpp>

namespace evmone::test
{
void run_state_test(const StateTransitionTest& test, evmc::VM& vm, bool trace_summary, bool symbolic)
{
    if (symbolic) ((evmone::VM<true>*)vm.get_raw_pointer())->reset();
            
    SCOPED_TRACE(test.name);
    for (const auto& [rev, cases] : test.cases)
    {
        validate_state(test.pre_state, rev);
        for (size_t case_index = 0; case_index != cases.size(); ++case_index)
        {
            SCOPED_TRACE(std::string{evmc::to_string(rev)} + '/' + std::to_string(case_index));
            // if (rev != EVMC_FRONTIER)
            //     continue;
            // if (case_index != 3)
            //     continue;


            

            const auto& expected = cases[case_index];
            const auto tx = test.multi_tx.get(expected.indexes);
            auto state = test.pre_state.to_intra_state();

            const auto res = state::transition(state, test.block, tx, rev, vm, test.block.gas_limit,
                state::BlockInfo::MAX_BLOB_GAS_PER_BLOCK);

            // Finalize block with reward 0.
            state::finalize(state, rev, test.block.coinbase, 0, {}, {});

            const auto state_root = state::mpt_hash(TestState{state});

            if (trace_summary)
            {
                std::clog << '{';
                if (holds_alternative<state::TransactionReceipt>(res))  // if tx valid
                {
                    const auto& r = get<state::TransactionReceipt>(res);
                    if (r.status == EVMC_SUCCESS)
                        std::clog << R"("pass":true)";
                    else
                        std::clog << R"("pass":false,"error":")" << r.status << '"';
                    std::clog << R"(,"gasUsed":"0x)" << std::hex << r.gas_used << R"(",)";
                }
                std::clog << R"("stateRoot":"0x)" << hex(state_root) << "\"}\n";
            }

            if (expected.exception)
            {
                ASSERT_FALSE(holds_alternative<state::TransactionReceipt>(res))
                    << "unexpected valid transaction";
                EXPECT_EQ(logs_hash(std::vector<state::Log>()), expected.logs_hash);
            }
            else
            {
                ASSERT_TRUE(holds_alternative<state::TransactionReceipt>(res))
                    << "unexpected invalid transaction: " << get<std::error_code>(res).message();
                EXPECT_EQ(logs_hash(get<state::TransactionReceipt>(res).logs), expected.logs_hash);
            }

            EXPECT_EQ(state_root, expected.state_hash);
            if (symbolic && !expected.exception && get<state::TransactionReceipt>(res).status == EVMC_SUCCESS)
            {
                auto* sym_vm = (evmone::VM<true>*)vm.get_raw_pointer();
                if (!sym_vm->get_arena()->symbolic_analysys_threshold_exceeded())
                {
                    auto state_from_symbolic = test.pre_state.to_intra_state();
                    std::unordered_set<evmc::address> touched_addresses;
                    auto valid = sym_vm->compute_symbolic(
                        [&touched_addresses, &state_from_symbolic](auto& addr, auto& key) 
                        {
                            touched_addresses.insert(addr);
                            const auto& acc = state_from_symbolic.get_or_insert(addr, {});
                            if (const auto it = acc.storage.find(key); it != acc.storage.end())
                                return it->second.current;
                            return bytes32{};
                        },
                        [&touched_addresses, &state_from_symbolic](auto& addr, auto& k, evmc::bytes32 v) 
                        {
                            touched_addresses.insert(addr);
                            if (v) state_from_symbolic.get_or_insert(addr, {}).storage[k].current = v; 
                            else state_from_symbolic.get_or_insert(addr, {}).storage.erase(k); 
                        }
                    );
                    ASSERT_TRUE(valid);
                    for (auto& addr : touched_addresses)
                    {
                        if (auto acc = state.find(addr); acc)
                            for (auto& it : acc->storage)
                            {
                                EXPECT_EQ(it.second.current, state_from_symbolic.get(addr).storage[it.first].current);
                            }
                    }
                }
                // else std::cerr << "disabling symbolic analysis...\n";

            }
        }
    }
}
}  // namespace evmone::test
