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
            auto state = test.pre_state;


            const auto res = test::transition(state, test.block, tx, rev, vm, test.block.gas_limit,
                state::BlockInfo::MAX_BLOB_GAS_PER_BLOCK);

            // Finalize block with reward 0.
            test::finalize(state, rev, test.block.coinbase, 0, {}, {});

            const auto state_root = state::mpt_hash(state);

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
                auto state_from_symbolic = test.pre_state;
                auto valid = ((evmone::VM<true>*)vm.get_raw_pointer())->compute_symbolic(
                    [&state_from_symbolic](auto& addr, auto& k) { return state_from_symbolic.get_storage(addr, k); },
                    [&state_from_symbolic](auto& addr, auto& k, evmc::bytes32 v) { if (v) state_from_symbolic[addr].storage.insert_or_assign(k, v); else state_from_symbolic[addr].storage.erase(k); }
                );
                ASSERT_TRUE(valid);
                for (auto& modified : get<state::TransactionReceipt>(res).state_diff.modified_accounts)
                {
                    auto& addr = modified.addr;
                    for (auto& it : state[addr].storage)
                    {
                        EXPECT_EQ(it.second, state_from_symbolic[addr].storage[it.first]);
                    }
                }
            }
        }
    }
}
}  // namespace evmone::test
