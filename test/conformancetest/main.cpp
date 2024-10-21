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

inline const std::error_category& evmc_loader_category() noexcept
{
    struct Category : std::error_category
    {
        [[nodiscard]] const char* name() const noexcept final { return "evmc_loader"; }

        [[nodiscard]] std::string message(int ev) const noexcept final
        {
            switch (ev)
            {
            case EVMC_LOADER_SUCCESS:
                return "";
            case EVMC_LOADER_CANNOT_OPEN:
                return "cannot open the given file name";
            case EVMC_LOADER_SYMBOL_NOT_FOUND:
                return "VM create function not found";
            case EVMC_LOADER_INVALID_ARGUMENT:
                return "invalid argument value provided";
            case EVMC_LOADER_VM_CREATION_FAILURE:
                return "creation of a VM instance has failed";
            case EVMC_LOADER_ABI_VERSION_MISMATCH:
                return "ABI version of the VM instance is mismatched";
            case EVMC_LOADER_INVALID_OPTION_NAME:
                return "VM option is invalid";
            case EVMC_LOADER_INVALID_OPTION_VALUE:
                return "VM option value is invalid";
            case EVMC_LOADER_UNSPECIFIED_ERROR:
                return "Unknown error";
            default:
                assert(false);
                return "Wrong error code";
            }
        }
    };

    static const Category category_instance;
    return category_instance;
}

std::variant<evmone::state::TransactionReceipt, std::error_code> run_vm(std::string& vm_config,
        evmc_revision rev,
        int64_t gas,
        const evmc::bytes& code,
        const evmc::bytes& input)
{
    using namespace evmc;
    using namespace evmone;

    evmc::VM vm;
    evmc_loader_error_code ec = EVMC_LOADER_UNSPECIFIED_ERROR;
    vm = VM{evmc_load_and_configure(vm_config.c_str(), &ec)};
    if (ec != EVMC_LOADER_SUCCESS)
    {
        const auto error = evmc_last_error_msg();
        if (error != nullptr)
            std::cerr << error << "\n";
        else
            std::cerr << "Loading error " << ec << "\n";
        return std::error_code {ec, evmc_loader_category()};
    }
    auto some_address = evmc::from_hex<address>("0xf00baaf00baaf00baaf00baaf00baaf00baaf000").value();
    test::TestState state;
    state[some_address] = test::TestAccount {
        .nonce = 0,
        .balance = 0,
        .code = code
    };
    state::BlockInfo block;
    state::Transaction tx;
    tx.data = input;
    tx.gas_limit = gas;
    tx.to = std::optional<address>{ some_address };

    return test::transition(state, block, tx, rev, vm, gas,
        state::BlockInfo::MAX_BLOB_GAS_PER_BLOCK);
}

void print_modified_accounts(const std::vector<evmone::state::StateDiff::Entry>& accounts, const std::string& padding) {
    for (auto& e : accounts) {
        if (e.modified_storage.size() > 0) {
            std::clog  << "\n" << padding << e.addr << ":";
            for (auto& s : e.modified_storage) {
                std::clog << "\n  " << padding << s.first << " -> " << s.second;
            }
        }
    }
}

}  // namespace

int main(int argc, const char** argv) noexcept
{
    using namespace evmc;

    try
    {
        const HexOrFileValidator HexOrFile;

        std::vector<std::string> vm_config;
        std::string code_arg;
        int64_t gas = 1000000;
        auto rev = EVMC_LATEST_STABLE_REVISION;
        std::string input_arg;
        auto create = false;

        CLI::App app{"EVMC tool"};
        const auto& vm_option =
            *app.add_option("--vm", vm_config, "EVMC VM module")->expected(1,2)->envname("EVMC_VM");
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

            if (run_cmd)
            {
                // For run command the --vm is required.
                if (vm_option.count() == 0)
                    throw CLI::RequiredError{vm_option.get_name()};

                // If code_arg or input_arg contains invalid hex string an exception is thrown.
                const auto code = load_from_hex(code_arg);
                const auto input = load_from_hex(input_arg);
                std::vector<std::pair<std::string,evmone::state::TransactionReceipt>> successful_results;

                for (auto& config : vm_config) {
                    const auto result_or_error = run_vm(config, rev, gas, code, input);
                
                    if (const auto result = std::get_if<evmone::state::TransactionReceipt>(&result_or_error))
                    {
                        if (result->status == EVMC_SUCCESS) successful_results.emplace_back(config,*result);
                        else std::cerr << "error" << config << ": " << result->status;
                    }
                }
                if (successful_results.size() > 0){
                    bool equivalent_gas = true;
                    for (auto& result : successful_results) {
                        equivalent_gas = equivalent_gas && successful_results[0].second.gas_used == result.second.gas_used;
                    }
                    std::clog << "gas used:";
                    if (equivalent_gas) std::clog << " " << successful_results[0].second.gas_used;
                    else
                        for (auto& result : successful_results) {
                            std::clog << "\n  " << result.first << ": " << result.second.gas_used;
                        }

                    bool equivalent_storage = true;
                    if (successful_results.size() == 2){
                        std::map<evmc::address, evmone::state::StateDiff::Entry>modified_accounts_map;
                        for(auto& ma : successful_results[1].second.state_diff.modified_accounts){
                            modified_accounts_map[ma.addr] = ma;
                        }

                        for(auto& ma : successful_results[0].second.state_diff.modified_accounts){
                            auto got = modified_accounts_map.find(ma.addr);
                            if ( got == modified_accounts_map.end() )
                                equivalent_storage = false;
                            else {
                                std::set<std::pair<bytes32, bytes32>> modified_storage_set(
                                    ma.modified_storage.begin(),
                                    ma.modified_storage.end());
                                std::set<std::pair<bytes32, bytes32>> modified_storage_set2(
                                    got->second.modified_storage.begin(),
                                    got->second.modified_storage.end());

                                equivalent_storage = equivalent_storage
                                    && modified_storage_set.size() == modified_storage_set2.size()
                                    && std::equal(modified_storage_set.begin(), modified_storage_set.end(), modified_storage_set2.begin());
                                
                            }
                        }
                    }
                    std::clog << "\nmodified state:";
                    if (equivalent_storage) print_modified_accounts(successful_results[0].second.state_diff.modified_accounts, "  ");
                    else
                        for (auto& result : successful_results) {
                            std::clog << "\n  " << result.first << ":";
                            print_modified_accounts(result.second.state_diff.modified_accounts, "    ");
                        }
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
