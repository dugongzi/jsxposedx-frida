#ifndef ZYGISKFRIDA_CONFIG_H
#define ZYGISKFRIDA_CONFIG_H

#include <cstdint>
#include <string>
#include <vector>
#include <optional>

enum class process_scope {
    main_only,
    main_and_child,
};

struct child_gating_config {
    bool enabled = false;
    std::string mode = "freeze";
    std::vector<std::string> injected_libraries;
};

struct gadget_config {
    bool enabled = true;
    std::string source_path;
    std::string js_path;
    std::string script_dir;
    std::string frida_config_json;
};

struct target_config {
    bool enabled = true;
    std::string app_name;
    std::string process_name;
    process_scope scope = process_scope::main_and_child;
    uint64_t start_up_delay_ms = 0;
    std::vector<std::string> injected_libraries;
    child_gating_config child_gating;
    gadget_config gadget;
};

std::optional<target_config> load_config(std::string const& module_dir, std::string const& app_name);

#endif  // ZYGISKFRIDA_CONFIG_H
