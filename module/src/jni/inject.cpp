#include "inject.h"

#include <unistd.h>

#include <algorithm>
#include <chrono>
#include <cinttypes>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include "child_gating.h"
#include "config.h"
#include "log.h"
#include "rapidjson/document.h"
#include "rapidjson/error/en.h"
#include "rapidjson/stringbuffer.h"
#include "rapidjson/writer.h"
#include "remapper.h"
#include "xdl.h"

static constexpr const char *kModuleDir = "/data/local/tmp/JsxposedXSo";
static constexpr int kDefaultMainListenPort = 27042;
static constexpr int kDefaultChildListenPort = 27043;

static std::string get_process_name() {
    auto path = "/proc/self/cmdline";

    std::ifstream file(path);
    std::stringstream buffer;

    buffer << file.rdbuf();
    return buffer.str();
}

static void wait_for_init(const std::string &process_name) {
    LOGI("Wait for process to complete init");

    // wait until the process is renamed to the configured process name
    while (get_process_name().find(process_name) == std::string::npos) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }

    // additional tolerance for the init to complete after process rename
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    LOGI("Process init completed");
}

static void delay_start_up(uint64_t start_up_delay_ms) {
    if (start_up_delay_ms <= 0) {
        return;
    }

    LOGI("Waiting for configured start up delay %" PRIu64"ms", start_up_delay_ms);

    int countdown = 0;
    uint64_t delay = start_up_delay_ms;

    for (int i = 0; i < 10 && delay > 1000; i++) {
        delay -= 1000;
        countdown++;
    }

    std::this_thread::sleep_for(std::chrono::milliseconds(delay));

    for (int i = countdown; i > 0; i--) {
        LOGI("Injecting libs in %d seconds", i);
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }
}

void inject_lib(const std::string &lib_path, const std::string &logContext) {
    auto *handle = xdl_open(lib_path.c_str(), XDL_TRY_FORCE_LOAD);
    if (handle) {
        LOGI("%sInjected %s with handle %p", logContext.c_str(), lib_path.c_str(), handle);
        remap_lib(lib_path);
        return;
    }

    auto xdl_err = dlerror();

    handle = dlopen(lib_path.c_str(), RTLD_NOW);
    if (handle) {
        LOGI("%sInjected %s with handle %p (dlopen)", logContext.c_str(), lib_path.c_str(), handle);
        remap_lib(lib_path);
        return;
    }

    auto dl_err = dlerror();

    LOGE("%sFailed to inject %s (xdl_open): %s", logContext.c_str(), lib_path.c_str(), xdl_err);
    LOGE("%sFailed to inject %s (dlopen): %s", logContext.c_str(), lib_path.c_str(), dl_err);
}

static std::string sanitize_process_key(const std::string &process_name) {
    std::string result;
    result.reserve(process_name.size() + 8);

    for (char ch : process_name) {
        if (ch == ':') {
            result += "__";
            continue;
        }

        // Keep runtime path safe and deterministic.
        if (ch == '/' || ch == '\\' || ch == ' ') {
            result.push_back('_');
            continue;
        }

        result.push_back(ch);
    }

    if (result.empty()) {
        return "unknown";
    }

    return result;
}

static bool copy_file_contents(const std::string &src, const std::string &dst) {
    std::ifstream source(src, std::ios::binary);
    if (!source.is_open()) {
        return false;
    }

    std::ofstream target(dst, std::ios::binary | std::ios::trunc);
    if (!target.is_open()) {
        return false;
    }

    target << source.rdbuf();
    target.flush();
    return target.good();
}

static bool write_file_contents(const std::string &path, const std::string &content) {
    std::ofstream file(path, std::ios::out | std::ios::trunc);
    if (!file.is_open()) {
        return false;
    }
    file << content;
    file.flush();
    return file.good();
}

static std::string serialize_json(const rapidjson::Document &doc) {
    rapidjson::StringBuffer buffer;
    rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
    doc.Accept(writer);
    return std::string(buffer.GetString(), buffer.GetSize());
}

static void set_or_replace_string(rapidjson::Value &obj,
                                  const char *name,
                                  const char *value,
                                  rapidjson::Document::AllocatorType &allocator) {
    rapidjson::Value key(name, allocator);
    rapidjson::Value val(value, allocator);
    if (obj.HasMember(name)) {
        obj[name] = val;
        return;
    }
    obj.AddMember(key, val, allocator);
}

static void set_or_replace_int(rapidjson::Value &obj,
                               const char *name,
                               int value,
                               rapidjson::Document::AllocatorType &allocator) {
    rapidjson::Value key(name, allocator);
    if (obj.HasMember(name)) {
        obj[name] = value;
        return;
    }
    obj.AddMember(key, value, allocator);
}

static std::string default_gadget_config_json(const gadget_config &cfg, bool is_child) {
    rapidjson::Document doc;
    doc.SetObject();
    auto &allocator = doc.GetAllocator();

    rapidjson::Value interaction(rapidjson::kObjectType);
    if (!cfg.js_path.empty()) {
        interaction.AddMember("type", rapidjson::Value("script", allocator), allocator);
        interaction.AddMember("path", rapidjson::Value(cfg.js_path.c_str(), allocator), allocator);
        interaction.AddMember("on_change", rapidjson::Value("reload", allocator), allocator);
    } else if (!cfg.script_dir.empty()) {
        interaction.AddMember("type", rapidjson::Value("script-directory", allocator), allocator);
        interaction.AddMember("path", rapidjson::Value(cfg.script_dir.c_str(), allocator), allocator);
        interaction.AddMember("on_change", rapidjson::Value("rescan", allocator), allocator);
    } else {
        interaction.AddMember("type", rapidjson::Value("listen", allocator), allocator);
        interaction.AddMember("address", rapidjson::Value("127.0.0.1", allocator), allocator);
        interaction.AddMember("port", is_child ? kDefaultChildListenPort : kDefaultMainListenPort, allocator);
        interaction.AddMember("on_load", rapidjson::Value("wait", allocator), allocator);
        if (is_child) {
            interaction.AddMember("on_port_conflict", rapidjson::Value("pick-next", allocator), allocator);
        }
    }

    doc.AddMember("interaction", interaction, allocator);
    return serialize_json(doc);
}

static std::string build_gadget_config_json(const gadget_config &cfg, bool is_child) {
    if (cfg.frida_config_json.empty()) {
        return default_gadget_config_json(cfg, is_child);
    }

    rapidjson::Document doc;
    doc.Parse(cfg.frida_config_json.c_str());
    if (doc.HasParseError() || !doc.IsObject()) {
        LOGE("invalid gadget.frida_config json: %s",
             doc.HasParseError() ? GetParseError_En(doc.GetParseError()) : "root must be object");
        return default_gadget_config_json(cfg, is_child);
    }

    if (!is_child) {
        return serialize_json(doc);
    }

    auto &allocator = doc.GetAllocator();
    if (!doc.HasMember("interaction") || !doc["interaction"].IsObject()) {
        rapidjson::Value interaction(rapidjson::kObjectType);
        interaction.AddMember("type", rapidjson::Value("listen", allocator), allocator);
        interaction.AddMember("address", rapidjson::Value("127.0.0.1", allocator), allocator);
        interaction.AddMember("port", kDefaultChildListenPort, allocator);
        interaction.AddMember("on_load", rapidjson::Value("wait", allocator), allocator);
        interaction.AddMember("on_port_conflict", rapidjson::Value("pick-next", allocator), allocator);
        doc.AddMember("interaction", interaction, allocator);
        return serialize_json(doc);
    }

    auto &interaction = doc["interaction"];
    if (!interaction.HasMember("type") || !interaction["type"].IsString()) {
        set_or_replace_string(interaction, "type", "listen", allocator);
    }

    auto type = std::string(interaction["type"].GetString());
    if (type == "listen") {
        if (!interaction.HasMember("address") || !interaction["address"].IsString()) {
            set_or_replace_string(interaction, "address", "127.0.0.1", allocator);
        }
        if (!interaction.HasMember("port") || !interaction["port"].IsInt()) {
            set_or_replace_int(interaction, "port", kDefaultChildListenPort, allocator);
        }
        if (!interaction.HasMember("on_load") || !interaction["on_load"].IsString()) {
            set_or_replace_string(interaction, "on_load", "wait", allocator);
        }
        set_or_replace_string(interaction, "on_port_conflict", "pick-next", allocator);
    }

    return serialize_json(doc);
}

static std::optional<std::string> prepare_runtime_gadget(const target_config &cfg, bool is_child) {
    if (!cfg.gadget.enabled) {
        return std::nullopt;
    }

    if (cfg.gadget.source_path.empty()) {
        LOGE("gadget.source_path is empty for %s", cfg.process_name.c_str());
        return std::nullopt;
    }

    auto process_name = cfg.process_name.empty() ? cfg.app_name : cfg.process_name;
    auto runtime_dir = std::string(kModuleDir) + "/runtime/" + sanitize_process_key(process_name);
    std::error_code error;
    std::filesystem::create_directories(runtime_dir, error);
    if (error) {
        LOGE("failed to create runtime dir %s: %s", runtime_dir.c_str(), error.message().c_str());
        return std::nullopt;
    }

    auto runtime_gadget_name = is_child ? "libgadget-child.so" : "libgadget.so";
    auto runtime_config_name = is_child ? "libgadget-child.config.so" : "libgadget.config.so";
    auto runtime_gadget_path = runtime_dir + "/" + runtime_gadget_name;
    auto runtime_config_path = runtime_dir + "/" + runtime_config_name;

    if (!copy_file_contents(cfg.gadget.source_path, runtime_gadget_path)) {
        LOGE("failed to copy gadget source %s to %s",
             cfg.gadget.source_path.c_str(),
             runtime_gadget_path.c_str());
        return std::nullopt;
    }

    auto gadget_config_json = build_gadget_config_json(cfg.gadget, is_child);
    if (!write_file_contents(runtime_config_path, gadget_config_json)) {
        LOGE("failed to write runtime gadget config %s", runtime_config_path.c_str());
        return std::nullopt;
    }

    LOGI("Prepared %s runtime gadget for %s at %s",
         is_child ? "child" : "main",
         process_name.c_str(),
         runtime_gadget_path.c_str());
    return runtime_gadget_path;
}

static void append_unique(std::vector<std::string> &libs, const std::string &lib) {
    if (lib.empty()) {
        return;
    }
    if (std::find(libs.begin(), libs.end(), lib) != libs.end()) {
        return;
    }
    libs.push_back(lib);
}

static void inject_libs(const target_config &cfg) {
    auto process_name = cfg.process_name.empty() ? cfg.app_name : cfg.process_name;

    // We need to wait for process initialization to complete.
    // Loading the gadget before that will freeze the process
    // before the init has completed. This make the process
    // undiscoverable or otherwise cause issue attaching.
    wait_for_init(process_name);

    std::vector<std::string> libs_to_inject;
    auto runtime_gadget = prepare_runtime_gadget(cfg, false);
    if (cfg.gadget.enabled && !runtime_gadget.has_value()) {
        LOGE("gadget enabled but runtime gadget preparation failed for %s", process_name.c_str());
        return;
    }
    if (runtime_gadget.has_value()) {
        append_unique(libs_to_inject, runtime_gadget.value());
    }

    for (const auto &lib_path : cfg.injected_libraries) {
        append_unique(libs_to_inject, lib_path);
    }

    auto child_cfg = cfg.child_gating;
    if (child_cfg.enabled && child_cfg.mode == "inject" && child_cfg.injected_libraries.empty()) {
        auto child_runtime_gadget = prepare_runtime_gadget(cfg, true);
        if (child_runtime_gadget.has_value()) {
            child_cfg.injected_libraries.push_back(child_runtime_gadget.value());
            LOGI("Auto-generated child gadget for %s: %s",
                 process_name.c_str(),
                 child_runtime_gadget.value().c_str());
        } else {
            LOGE("child_gating inject requested but failed to prepare child runtime gadget for %s",
                 process_name.c_str());
        }
    }

    if (child_cfg.enabled) {
        enable_child_gating(child_cfg);
    }

    delay_start_up(cfg.start_up_delay_ms);

    for (const auto &lib_path : libs_to_inject) {
        LOGI("Injecting %s", lib_path.c_str());
        inject_lib(lib_path, "");
    }
}

bool check_and_inject(const std::string &app_name) {
    std::string module_dir = std::string(kModuleDir);

    std::optional<target_config> cfg = load_config(module_dir, app_name);
    if (!cfg.has_value()) {
        return false;
    }

    LOGI("App detected: %s", app_name.c_str());
    LOGI("PID: %d", getpid());
    LOGI("Matched target: %s", cfg.value().app_name.c_str());

    auto target = cfg.value();
    if (!target.enabled) {
        LOGI("Injection disabled for %s", app_name.c_str());
        return false;
    }

    std::thread inject_thread(inject_libs, target);
    inject_thread.detach();

    return true;
}
