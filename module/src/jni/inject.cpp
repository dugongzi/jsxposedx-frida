#include "inject.h"

#include <unistd.h>

#include <algorithm>
#include <chrono>
#include <cinttypes>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <limits>
#include <mutex>
#include <optional>
#include <sstream>
#include <string>
#include <thread>
#include <unordered_map>
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

struct prepared_injection {
    std::string process_name;
    uint64_t start_up_delay_ms = 0;
    child_gating_config child_cfg;
    std::vector<std::string> libs_to_inject;
};

static std::mutex g_prepared_injections_lock;
static std::unordered_map<std::string, prepared_injection> g_prepared_injections;

static std::string get_process_name() {
    auto path = "/proc/self/cmdline";

    std::ifstream file(path);
    std::stringstream buffer;

    buffer << file.rdbuf();
    return buffer.str();
}

static void wait_for_init(const std::string &process_name) {
    LOGI("[INJECT] wait for process to complete init");

    // wait until the process is renamed to the configured process name
    while (get_process_name().find(process_name) == std::string::npos) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }

    // additional tolerance for the init to complete after process rename
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    LOGI("[INJECT] process init completed");
}

static void delay_start_up(uint64_t start_up_delay_ms) {
    if (start_up_delay_ms <= 0) {
        return;
    }

    LOGI("[INJECT] waiting for configured start up delay %" PRIu64"ms", start_up_delay_ms);

    int countdown = 0;
    uint64_t delay = start_up_delay_ms;

    for (int i = 0; i < 10 && delay > 1000; i++) {
        delay -= 1000;
        countdown++;
    }

    std::this_thread::sleep_for(std::chrono::milliseconds(delay));

    for (int i = countdown; i > 0; i--) {
        LOGI("[INJECT] injecting libs in %d seconds", i);
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
        LOGE("[PREPARE] invalid gadget.frida_config json: %s",
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
        LOGE("[PREPARE] gadget.source_path is empty for %s", cfg.process_name.c_str());
        return std::nullopt;
    }

    auto process_name = cfg.process_name.empty() ? cfg.app_name : cfg.process_name;
    auto runtime_dir = std::string(kModuleDir) + "/runtime/" + sanitize_process_key(process_name);
    std::error_code error;
    std::filesystem::create_directories(runtime_dir, error);
    if (error) {
        LOGE("[PREPARE] failed to create runtime dir %s: %s",
             runtime_dir.c_str(),
             error.message().c_str());
        return std::nullopt;
    }

    auto runtime_gadget_name = is_child ? "libgadget-child.so" : "libgadget.so";
    auto runtime_config_name = is_child ? "libgadget-child.config.so" : "libgadget.config.so";
    auto runtime_gadget_path = runtime_dir + "/" + runtime_gadget_name;
    auto runtime_config_path = runtime_dir + "/" + runtime_config_name;

    if (!copy_file_contents(cfg.gadget.source_path, runtime_gadget_path)) {
        LOGE("[PREPARE] failed to copy gadget source %s to %s",
             cfg.gadget.source_path.c_str(),
             runtime_gadget_path.c_str());
        return std::nullopt;
    }

    auto gadget_config_json = build_gadget_config_json(cfg.gadget, is_child);
    if (!write_file_contents(runtime_config_path, gadget_config_json)) {
        LOGE("[PREPARE] failed to write runtime gadget config %s", runtime_config_path.c_str());
        return std::nullopt;
    }

    LOGI("[PREPARE] prepared %s runtime gadget for %s at %s",
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

static bool write_all(int fd, const void *data, size_t size) {
    const auto *buf = static_cast<const uint8_t *>(data);
    size_t remaining = size;

    while (remaining > 0) {
        auto written = write(fd, buf, remaining);
        if (written <= 0) {
            return false;
        }
        buf += written;
        remaining -= static_cast<size_t>(written);
    }

    return true;
}

static bool read_all(int fd, void *data, size_t size) {
    auto *buf = static_cast<uint8_t *>(data);
    size_t remaining = size;

    while (remaining > 0) {
        auto read_bytes = read(fd, buf, remaining);
        if (read_bytes <= 0) {
            return false;
        }
        buf += read_bytes;
        remaining -= static_cast<size_t>(read_bytes);
    }

    return true;
}

static bool write_u32(int fd, uint32_t value) {
    return write_all(fd, &value, sizeof(value));
}

static bool write_u64(int fd, uint64_t value) {
    return write_all(fd, &value, sizeof(value));
}

static bool read_u32(int fd, uint32_t *value) {
    return read_all(fd, value, sizeof(*value));
}

static bool read_u64(int fd, uint64_t *value) {
    return read_all(fd, value, sizeof(*value));
}

static bool write_string(int fd, const std::string &value) {
    if (value.size() > std::numeric_limits<uint32_t>::max()) {
        return false;
    }
    auto size = static_cast<uint32_t>(value.size());
    if (!write_u32(fd, size)) {
        return false;
    }
    return size == 0 || write_all(fd, value.data(), size);
}

static bool read_string(int fd, std::string *value) {
    constexpr uint32_t kMaxIpcStringSize = 1024 * 1024;

    uint32_t size = 0;
    if (!read_u32(fd, &size)) {
        return false;
    }
    if (size > kMaxIpcStringSize) {
        return false;
    }

    value->assign(size, '\0');
    if (size == 0) {
        return true;
    }
    return read_all(fd, value->data(), size);
}

static bool write_string_vector(int fd, const std::vector<std::string> &values) {
    if (values.size() > std::numeric_limits<uint32_t>::max()) {
        return false;
    }
    auto count = static_cast<uint32_t>(values.size());
    if (!write_u32(fd, count)) {
        return false;
    }
    for (const auto &value : values) {
        if (!write_string(fd, value)) {
            return false;
        }
    }
    return true;
}

static bool read_string_vector(int fd, std::vector<std::string> *values) {
    constexpr uint32_t kMaxIpcVectorSize = 512;

    uint32_t count = 0;
    if (!read_u32(fd, &count)) {
        return false;
    }
    if (count > kMaxIpcVectorSize) {
        return false;
    }

    values->clear();
    values->reserve(count);
    for (uint32_t i = 0; i < count; i++) {
        std::string value;
        if (!read_string(fd, &value)) {
            return false;
        }
        values->push_back(std::move(value));
    }
    return true;
}

static bool write_prepared_injection(int fd, const prepared_injection &prepared) {
    if (!write_string(fd, prepared.process_name)) {
        return false;
    }
    if (!write_u64(fd, prepared.start_up_delay_ms)) {
        return false;
    }
    if (!write_u32(fd, prepared.child_cfg.enabled ? 1U : 0U)) {
        return false;
    }
    if (!write_string(fd, prepared.child_cfg.mode)) {
        return false;
    }
    if (!write_string_vector(fd, prepared.child_cfg.injected_libraries)) {
        return false;
    }
    return write_string_vector(fd, prepared.libs_to_inject);
}

static bool read_prepared_injection(int fd, prepared_injection *prepared) {
    uint32_t child_enabled = 0;

    if (!read_string(fd, &prepared->process_name)) {
        return false;
    }
    if (!read_u64(fd, &prepared->start_up_delay_ms)) {
        return false;
    }
    if (!read_u32(fd, &child_enabled)) {
        return false;
    }
    prepared->child_cfg.enabled = (child_enabled != 0U);
    if (!read_string(fd, &prepared->child_cfg.mode)) {
        return false;
    }
    if (!read_string_vector(fd, &prepared->child_cfg.injected_libraries)) {
        return false;
    }
    return read_string_vector(fd, &prepared->libs_to_inject);
}

static std::optional<prepared_injection> build_prepared_injection(const target_config &cfg) {
    auto process_name = cfg.process_name.empty() ? cfg.app_name : cfg.process_name;

    prepared_injection prepared = {};
    prepared.process_name = process_name;
    prepared.start_up_delay_ms = cfg.start_up_delay_ms;
    prepared.child_cfg = cfg.child_gating;

    auto runtime_gadget = prepare_runtime_gadget(cfg, false);
    if (cfg.gadget.enabled && !runtime_gadget.has_value()) {
        LOGE("[PREPARE] gadget enabled but runtime gadget preparation failed for %s",
             process_name.c_str());
        return std::nullopt;
    }
    if (runtime_gadget.has_value()) {
        append_unique(prepared.libs_to_inject, runtime_gadget.value());
    }

    for (const auto &lib_path : cfg.injected_libraries) {
        append_unique(prepared.libs_to_inject, lib_path);
    }

    if (prepared.child_cfg.enabled && prepared.child_cfg.mode == "inject" &&
        prepared.child_cfg.injected_libraries.empty()) {
        auto child_runtime_gadget = prepare_runtime_gadget(cfg, true);
        if (child_runtime_gadget.has_value()) {
            prepared.child_cfg.injected_libraries.push_back(child_runtime_gadget.value());
            LOGI("[PREPARE] auto-generated child gadget for %s: %s",
                 process_name.c_str(),
                 child_runtime_gadget.value().c_str());
        } else {
            LOGE("[PREPARE] child_gating inject requested but failed to prepare child runtime gadget "
                 "for %s",
                 process_name.c_str());
        }
    }

    return prepared;
}

static void inject_prepared_libs(prepared_injection prepared) {
    auto process_name = prepared.process_name;

    // We need to wait for process initialization to complete.
    // Loading the gadget before that will freeze the process
    // before the init has completed. This make the process
    // undiscoverable or otherwise cause issue attaching.
    wait_for_init(process_name);

    if (prepared.child_cfg.enabled) {
        LOGI("[INJECT] enabling child gating for %s (mode=%s)",
             process_name.c_str(),
             prepared.child_cfg.mode.c_str());
        enable_child_gating(prepared.child_cfg);
    }

    delay_start_up(prepared.start_up_delay_ms);

    for (const auto &lib_path : prepared.libs_to_inject) {
        LOGI("[INJECT] injecting %s", lib_path.c_str());
        inject_lib(lib_path, "[INJECT] ");
    }
}

static std::optional<prepared_injection> prepare_injection_plan_for_process(const std::string &app_name) {
    LOGI("[PREPARE] evaluate process: %s", app_name.c_str());

    const auto module_dir = std::string(kModuleDir);
    auto cfg = load_config(module_dir, app_name);
    if (!cfg.has_value()) {
        LOGI("[PREPARE] no config matched for process: %s", app_name.c_str());
        return std::nullopt;
    }

    auto target = cfg.value();
    auto process_name = target.process_name.empty() ? target.app_name : target.process_name;

    LOGI("[PREPARE] app detected: %s", app_name.c_str());
    LOGI("[PREPARE] pid: %d", getpid());
    LOGI("[PREPARE] matched target: %s", target.app_name.c_str());

    if (!target.enabled) {
        LOGI("[PREPARE] injection disabled for %s", process_name.c_str());
        return std::nullopt;
    }

    auto prepared = build_prepared_injection(target);
    if (!prepared.has_value()) {
        LOGE("[PREPARE] failed to build injection plan for %s", process_name.c_str());
        return std::nullopt;
    }

    LOGI("[PREPARE] ready for %s (%zu libs)",
         process_name.c_str(),
         prepared.value().libs_to_inject.size());

    return prepared;
}

bool prepare_for_process(const std::string &app_name) {
    auto prepared = prepare_injection_plan_for_process(app_name);
    if (!prepared.has_value()) {
        return false;
    }

    {
        std::lock_guard<std::mutex> lock(g_prepared_injections_lock);
        auto [it, inserted] = g_prepared_injections.insert_or_assign(app_name, std::move(prepared.value()));
        if (!inserted) {
            LOGI("[PREPARE] replaced stale prepared state for %s", it->first.c_str());
        }
    }

    return true;
}

bool prepare_for_process_with_companion(const std::string &app_name, int companion_fd) {
    if (companion_fd < 0) {
        LOGE("[PREPARE] invalid companion fd for %s", app_name.c_str());
        return false;
    }

    if (!write_string(companion_fd, app_name)) {
        LOGE("[PREPARE] failed to send process name to companion for %s", app_name.c_str());
        return false;
    }

    uint32_t success = 0;
    if (!read_u32(companion_fd, &success)) {
        LOGE("[PREPARE] failed to read companion status for %s", app_name.c_str());
        return false;
    }
    if (success == 0) {
        LOGI("[PREPARE] companion returned no plan for %s", app_name.c_str());
        return false;
    }

    prepared_injection prepared = {};
    if (!read_prepared_injection(companion_fd, &prepared)) {
        LOGE("[PREPARE] failed to read companion plan for %s", app_name.c_str());
        return false;
    }

    {
        std::lock_guard<std::mutex> lock(g_prepared_injections_lock);
        auto [it, inserted] = g_prepared_injections.insert_or_assign(app_name, std::move(prepared));
        if (!inserted) {
            LOGI("[PREPARE] replaced stale prepared state for %s", it->first.c_str());
        }
    }

    LOGI("[PREPARE] companion prepared plan for %s", app_name.c_str());
    return true;
}

void handle_prepare_companion_request(int client_fd) {
    std::string app_name;
    if (!read_string(client_fd, &app_name)) {
        LOGE("[PREPARE] companion failed to read process name request");
        return;
    }

    auto prepared = prepare_injection_plan_for_process(app_name);
    const uint32_t success = prepared.has_value() ? 1U : 0U;
    if (!write_u32(client_fd, success)) {
        LOGE("[PREPARE] companion failed to write status for %s", app_name.c_str());
        return;
    }

    if (!prepared.has_value()) {
        return;
    }

    if (!write_prepared_injection(client_fd, prepared.value())) {
        LOGE("[PREPARE] companion failed to write plan for %s", app_name.c_str());
    }
}

bool inject_prepared(const std::string &app_name) {
    std::optional<prepared_injection> prepared = std::nullopt;
    {
        std::lock_guard<std::mutex> lock(g_prepared_injections_lock);
        auto it = g_prepared_injections.find(app_name);
        if (it == g_prepared_injections.end()) {
            LOGI("[INJECT] no prepared plan for %s", app_name.c_str());
            return false;
        }
        prepared = std::move(it->second);
        g_prepared_injections.erase(it);
    }

    std::thread inject_thread(inject_prepared_libs, std::move(prepared.value()));
    inject_thread.detach();
    LOGI("[INJECT] scheduled injection thread for %s", app_name.c_str());
    return true;
}

bool check_and_inject(const std::string &app_name) {
    if (!prepare_for_process(app_name)) {
        return false;
    }
    return inject_prepared(app_name);
}
