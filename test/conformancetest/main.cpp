// EVMC: Ethereum Client-VM Connector API.
// Copyright 2019 The EVMC Authors.
// Licensed under the Apache License, Version 2.0.

#include "../state/test_state.hpp"
#include "../state/block.hpp"
#include "../state/transaction.hpp"
#include "../state/state_diff.hpp"

#include <CLI/CLI.hpp>
#include <evmc/hex.hpp>
#include <evmc/loader.h>
#include <evmc/tooling.hpp>
// #include "../state/rlp.hpp"

#include <fstream>


namespace
{
/// If the argument starts with @ returns the hex-decoded contents of the file
/// at the path following the @. Otherwise, returns the argument.
/// @todo The file content is expected to be a hex string but not validated.
evmc::bytes load_from_hex(const std::string& str)
{
    if (str[0] == '@')  // The argument is file path.
    {
        const auto path = str.substr(1);
        std::ifstream file{path};
        auto out = evmc::from_spaced_hex(std::istreambuf_iterator<char>{file},
                                         std::istreambuf_iterator<char>{});
        if (!out)
            throw std::invalid_argument{"invalid hex in " + path};
        return out.value();
    }

    return evmc::from_hex(str).value();  // Should be validated already.
}

struct HexOrFileValidator : public CLI::Validator
{
    HexOrFileValidator() : CLI::Validator{"HEX|@FILE"}
    {
        func_ = [](const std::string& str) -> std::string {
            if (!str.empty() && str[0] == '@')
                return CLI::ExistingFile(str.substr(1));
            if (!evmc::validate_hex(str))
                return "invalid hex";
            return {};
        };
    }
};
}  // namespace

int main(int argc, const char** argv) noexcept
{
    using namespace evmc;

    try
    {
        const HexOrFileValidator HexOrFile;

        std::string vm_config, vm_config2;
        std::string code_arg;
        int64_t gas = 1000000;
        auto rev = EVMC_LATEST_STABLE_REVISION;
        std::string input_arg;
        auto create = false;

        CLI::App app{"EVMC tool"};
        const auto& version_flag = *app.add_flag("--version", "Print version information and exit");
        const auto& vm_option =
            *app.add_option("--vm", vm_config, "EVMC VM module")->envname("EVMC_VM");
        const auto& vm2_option =
            *app.add_option("--vm2", vm_config2, "EVMC VM module")->envname("EVMC_VM2");

        auto& run_cmd = *app.add_subcommand("run", "Execute EVM bytecode")->fallthrough();
        run_cmd.add_option("code", code_arg, "Bytecode")->required()->check(HexOrFile);
        run_cmd.add_option("--gas", gas, "Execution gas limit")
            ->capture_default_str()
            ->check(CLI::Range(0, 1000000000));
        run_cmd.add_option("--rev", rev, "EVM revision")->capture_default_str();
        run_cmd.add_option("--input", input_arg, "Input bytes")->check(HexOrFile);
        run_cmd.add_flag(
            "--create", create,
            "Create new contract out of the code and then execute this contract with the input");

        try
        {
            app.parse(argc, argv);

            evmc::VM vm;
            if (vm_option.count() != 0)
            {
                evmc_loader_error_code ec = EVMC_LOADER_UNSPECIFIED_ERROR;
                vm = VM{evmc_load_and_configure(vm_config.c_str(), &ec)};
                if (ec != EVMC_LOADER_SUCCESS)
                {
                    const auto error = evmc_last_error_msg();
                    if (error != nullptr)
                        std::cerr << error << "\n";
                    else
                        std::cerr << "Loading error " << ec << "\n";
                    return static_cast<int>(ec);
                }
            }

            // Handle the --version flag first and exit when present.
            if (version_flag)
            {
                if (vm)
                    std::cout << vm.name() << " " << vm.version() << " (" << vm_config << ")\n";

                std::cout << "EVMC ";
                if (argc >= 1)
                    std::cout << " (" << argv[0] << ")";
                std::cout << "\n";
                return 0;
            }

            if (run_cmd)
            {
                // For run command the --vm is required.
                if (vm_option.count() == 0)
                    throw CLI::RequiredError{vm_option.get_name()};

                std::cout << "Config: " << vm_config << "\n";

                // If code_arg or input_arg contains invalid hex string an exception is thrown.
                const auto code = load_from_hex(code_arg);
                const auto input = load_from_hex(input_arg);

                auto some_address = evmc::from_hex<address>("0xf00baaf00baaf00baaf00baaf00baaf00baaf000").value();
                evmone::test::TestState state;
                state[some_address] = {
                    .nonce = 0,
                    .balance = 0,
                    .code = code};
                evmone::state::BlockInfo block;
                evmone::state::Transaction tx;
                tx.data = input;
                tx.gas_limit = gas;
                tx.to = std::optional<evmc::address>{ some_address };

                const auto res = evmone::test::transition(state, block, tx, rev, vm, gas,
                    evmone::state::BlockInfo::MAX_BLOB_GAS_PER_BLOCK);

                if (std::holds_alternative<evmone::state::TransactionReceipt>(res))
                {
                    const auto& r = get<evmone::state::TransactionReceipt>(res);
                    std::clog << "gas used: " << r.gas_used;
                    if (r.status == EVMC_SUCCESS) {
                        std::clog << "\nmodified state:";
                        for (auto& e : r.state_diff.modified_accounts) {
                            if (e.modified_storage.size() > 0) {
                                std::clog  << "\n  " << e.addr << ":";
                                for (auto& s : e.modified_storage) {
                                    std::clog << "\n    " << s.first << " -> " << s.second;
                                }
                            }
                        }




                        if(vm2_option.count() == 1) {
                            evmc_loader_error_code ec2 = EVMC_LOADER_UNSPECIFIED_ERROR;
                            evmc::VM vm2 {evmc_load_and_configure(vm_config2.c_str(), &ec2)};
                            if (ec2 != EVMC_LOADER_SUCCESS)
                            {
                                const auto error = evmc_last_error_msg();
                                if (error != nullptr)
                                    std::cerr << error << "\n";
                                else
                                    std::cerr << "Loading error " << ec2 << "\n";
                                return static_cast<int>(ec2);
                            }


                            evmone::test::TestState state2;
                            state2[some_address] = {
                                .nonce = 0,
                                .balance = 0,
                                .code = code};
                            evmone::state::BlockInfo block2;
                            evmone::state::Transaction tx2;
                            tx2.data = input;
                            tx2.gas_limit = gas;
                            tx2.to = std::optional<evmc::address>{ some_address };

                            const auto res2 = evmone::test::transition(state2, block2, tx2, rev, vm2, gas,
                                evmone::state::BlockInfo::MAX_BLOB_GAS_PER_BLOCK);


                            if (std::holds_alternative<evmone::state::TransactionReceipt>(res2))
                            {
                                const auto& r2 = get<evmone::state::TransactionReceipt>(res);
                                std::clog << "\ngas used: " << r2.gas_used;
                                if (r2.status == EVMC_SUCCESS) {
                                    std::map<evmc::address, evmone::state::StateDiff::Entry>modified_accounts_map;
                                    for(auto& ma : r2.state_diff.modified_accounts){
                                        modified_accounts_map[ma.addr] = ma;
                                    }

                                    bool equivalent = true;

                                    for(auto& ma : r.state_diff.modified_accounts){
                                        auto got = modified_accounts_map.find(ma.addr);
                                        if ( got == modified_accounts_map.end() )
                                            equivalent = false;
                                        else {
                                            std::set<std::pair<bytes32, bytes32>> modified_storage_set(ma.modified_storage.begin(),
                                                ma.modified_storage.end());
                                            std::set<std::pair<bytes32, bytes32>> modified_storage_set2(got->second.modified_storage.begin(),
                                                got->second.modified_storage.end());

                                            equivalent = modified_storage_set.size() == modified_storage_set2.size()
                                                && std::equal(modified_storage_set.begin(), modified_storage_set.end(), modified_storage_set2.begin());
                                            
                                        }
                                    }

                                    if(equivalent) {
                                        std::clog << "\nequivalent runs";
                                    }
                                    else {
                                        std::clog << "\nNOT equivalent runs";
                                    }
                                }
                            }

                        }
                    }
                    else
                        std::clog << "error" << r.status;
                }
                std::clog << "\n";

            }

            return 0;
        }
        catch (const CLI::ParseError& e)
        {
            return app.exit(e);
        }
    }
    catch (const std::exception& e)
    {
        std::cerr << "Error: " << e.what() << "\n";
        return -1;
    }
    catch (...)
    {
        return -2;
    }
}
