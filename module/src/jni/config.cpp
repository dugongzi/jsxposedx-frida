#include "config.h"

#include <cerrno>
#include <fstream>
#include <optional>
#include <string>
#include <cstring>

#include "log.h"
#include "rapidjson/document.h"
#include "rapidjson/error/en.h"
#include "rapidjson/istreamwrapper.h"
#include "rapidjson/stringbuffer.h"
#include "rapidjson/writer.h"

// This must work in a non-exception environment as the libcxx we use don't have support for exception.
// Should avoid any libraries aborting on parse error as this will run on every app start and
// might otherwise cause issues for any app starting if misconfigured.

static std::optional<std::vector<std::string>> deserialize_libraries(
    const rapidjson::Value &doc, const std::string &context) {
    if (!doc.IsArray()) {
        LOGE("%s invalid config: expected injected_libraries to be an array", context.c_str());
        return std::nullopt;
    }

    std::vector<std::string> result;

    for (rapidjson::SizeType i = 0; i < doc.Size(); i++) {
        const auto &library = doc[i];
        if (!library.IsObject()) {
            LOGE("%s invalid config: expected injected_libraries[%u] to be an object",
                 context.c_str(), i);
            return std::nullopt;
        }

        if (!library.HasMember("path")) {
            LOGE("%s invalid config: expected injected_libraries[%u].path", context.c_str(), i);
            return std::nullopt;
        }

        const auto &path = library["path"];
        if (!path.IsString()) {
            LOGE("%s invalid config: expected injected_libraries[%u].path to be a string",
                 context.c_str(), i);
            return std::nullopt;
        }

        auto value = std::string(path.GetString());
        if (value.empty()) {
            LOGE("%s invalid config: expected injected_libraries[%u].path to be non-empty",
                 context.c_str(), i);
            return std::nullopt;
        }

        result.emplace_back(value);
    }

    return result;
}

static std::optional<process_scope> deserialize_process_scope(const rapidjson::Value &doc,
                                                              const std::string &context) {
    if (!doc.IsString()) {
        LOGE("%s invalid config: expected process_scope to be a string", context.c_str());
        return std::nullopt;
    }

    auto value = std::string(doc.GetString());
    if (value == "main_only") {
        return process_scope::main_only;
    }
    if (value == "main_and_child") {
        return process_scope::main_and_child;
    }

    LOGE("%s invalid config: unknown process_scope %s", context.c_str(), value.c_str());
    return std::nullopt;
}

static std::optional<std::string> serialize_json(const rapidjson::Value &doc) {
    rapidjson::StringBuffer buffer;
    rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
    if (!doc.Accept(writer)) {
        return std::nullopt;
    }
    return std::string(buffer.GetString(), buffer.GetSize());
}

static bool apply_child_gating_overrides(const rapidjson::Value &doc,
                                         child_gating_config &cfg,
                                         const std::string &context) {
    if (!doc.IsObject()) {
        LOGE("%s invalid config: expected child_gating to be an object", context.c_str());
        return false;
    }

    if (doc.HasMember("enabled")) {
        const auto &enabled = doc["enabled"];
        if (!enabled.IsBool()) {
            LOGE("%s invalid config: expected child_gating.enabled to be a bool",
                 context.c_str());
            return false;
        }
        cfg.enabled = enabled.GetBool();
    }

    if (doc.HasMember("mode")) {
        const auto &mode = doc["mode"];
        if (!mode.IsString()) {
            LOGE("%s invalid config: expected child_gating.mode to be a string", context.c_str());
            return false;
        }
        cfg.mode = mode.GetString();
    }

    if (doc.HasMember("injected_libraries")) {
        auto injected_libraries = deserialize_libraries(doc["injected_libraries"], context);
        if (!injected_libraries.has_value()) {
            return false;
        }
        cfg.injected_libraries = injected_libraries.value();
    }

    if (cfg.mode.empty()) {
        LOGE("%s invalid config: child_gating.mode must be non-empty", context.c_str());
        return false;
    }

    return true;
}

static bool apply_gadget_overrides(const rapidjson::Value &doc,
                                   gadget_config &cfg,
                                   const std::string &context) {
    if (!doc.IsObject()) {
        LOGE("%s invalid config: expected gadget to be an object", context.c_str());
        return false;
    }

    int selector_count = 0;
    selector_count += doc.HasMember("js_path") ? 1 : 0;
    selector_count += doc.HasMember("script_dir") ? 1 : 0;
    selector_count += doc.HasMember("frida_config") ? 1 : 0;
    if (selector_count > 1) {
        LOGE("%s invalid config: gadget.js_path, gadget.script_dir and gadget.frida_config are "
             "mutually exclusive", context.c_str());
        return false;
    }

    if (doc.HasMember("enabled")) {
        const auto &enabled = doc["enabled"];
        if (!enabled.IsBool()) {
            LOGE("%s invalid config: expected gadget.enabled to be a bool", context.c_str());
            return false;
        }
        cfg.enabled = enabled.GetBool();
    }

    if (doc.HasMember("source_path")) {
        const auto &source_path = doc["source_path"];
        if (!source_path.IsString()) {
            LOGE("%s invalid config: expected gadget.source_path to be a string",
                 context.c_str());
            return false;
        }
        cfg.source_path = source_path.GetString();
    }

    if (doc.HasMember("js_path")) {
        const auto &js_path = doc["js_path"];
        if (!js_path.IsString()) {
            LOGE("%s invalid config: expected gadget.js_path to be a string", context.c_str());
            return false;
        }
        cfg.js_path = js_path.GetString();
        cfg.script_dir.clear();
        cfg.frida_config_json.clear();
    }

    if (doc.HasMember("script_dir")) {
        const auto &script_dir = doc["script_dir"];
        if (!script_dir.IsString()) {
            LOGE("%s invalid config: expected gadget.script_dir to be a string", context.c_str());
            return false;
        }
        cfg.script_dir = script_dir.GetString();
        cfg.js_path.clear();
        cfg.frida_config_json.clear();
    }

    if (doc.HasMember("frida_config")) {
        auto serialized = serialize_json(doc["frida_config"]);
        if (!serialized.has_value()) {
            LOGE("%s invalid config: unable to serialize gadget.frida_config", context.c_str());
            return false;
        }
        cfg.frida_config_json = serialized.value();
        cfg.js_path.clear();
        cfg.script_dir.clear();
    }

    if (cfg.enabled && cfg.source_path.empty()) {
        LOGE("%s invalid config: gadget.source_path must be non-empty when gadget.enabled=true",
             context.c_str());
        return false;
    }

    return true;
}

static target_config build_defaults(const std::string &module_dir) {
    target_config cfg = {};
    cfg.enabled = true;
    cfg.scope = process_scope::main_and_child;
    cfg.start_up_delay_ms = 0;
    cfg.child_gating.enabled = false;
    cfg.child_gating.mode = "freeze";
    cfg.gadget.enabled = true;
    cfg.gadget.source_path = module_dir + "/libgadget.so";
    return cfg;
}

static bool apply_target_overrides(const rapidjson::Value &doc,
                                   target_config &cfg,
                                   const std::string &context,
                                   bool require_app_name) {
    if (!doc.IsObject()) {
        LOGE("%s invalid config: expected target object", context.c_str());
        return false;
    }

    if (require_app_name) {
        if (!doc.HasMember("app_name")) {
            LOGE("%s invalid config: expected app_name", context.c_str());
            return false;
        }

        const auto &app_name = doc["app_name"];
        if (!app_name.IsString()) {
            LOGE("%s invalid config: expected app_name to be a string", context.c_str());
            return false;
        }

        cfg.app_name = app_name.GetString();
        if (cfg.app_name.empty()) {
            LOGE("%s invalid config: app_name must be non-empty", context.c_str());
            return false;
        }
    }

    if (doc.HasMember("enabled")) {
        const auto &enabled = doc["enabled"];
        if (!enabled.IsBool()) {
            LOGE("%s invalid config: expected enabled to be a bool", context.c_str());
            return false;
        }
        cfg.enabled = enabled.GetBool();
    }

    if (doc.HasMember("start_up_delay_ms")) {
        const auto &start_up_delay_ms = doc["start_up_delay_ms"];
        if (!start_up_delay_ms.IsUint64()) {
            LOGE("%s invalid config: expected start_up_delay_ms to be uint64", context.c_str());
            return false;
        }
        cfg.start_up_delay_ms = start_up_delay_ms.GetUint64();
    }

    if (doc.HasMember("process_scope")) {
        auto scope = deserialize_process_scope(doc["process_scope"], context);
        if (!scope.has_value()) {
            return false;
        }
        cfg.scope = scope.value();
    }

    if (doc.HasMember("injected_libraries")) {
        auto deserialized_libraries = deserialize_libraries(doc["injected_libraries"], context);
        if (!deserialized_libraries.has_value()) {
            return false;
        }
        cfg.injected_libraries = deserialized_libraries.value();
    }

    if (doc.HasMember("child_gating")) {
        if (!apply_child_gating_overrides(doc["child_gating"], cfg.child_gating, context)) {
            return false;
        }
    }

    if (doc.HasMember("gadget")) {
        if (!apply_gadget_overrides(doc["gadget"], cfg.gadget, context)) {
            return false;
        }
    }

    return true;
}

static bool matches_process(const target_config &cfg, const std::string &process_name) {
    if (cfg.scope == process_scope::main_only) {
        return process_name == cfg.app_name;
    }

    if (process_name == cfg.app_name) {
        return true;
    }

    auto prefix = cfg.app_name + ":";
    return process_name.rfind(prefix, 0) == 0;
}

static std::optional<target_config> load_advanced_config(const std::string &module_dir,
                                                         const std::string &process_name) {
    auto config_path = module_dir + "/config.json";
    std::ifstream config_file(config_path);
    if (!config_file.is_open()) {
        LOGE("failed to open config: %s errno=%d (%s)",
             config_path.c_str(),
             errno,
             std::strerror(errno));
        return std::nullopt;
    }

    rapidjson::IStreamWrapper config_stream{config_file};

    rapidjson::Document doc;
    doc.ParseStream(config_stream);
    config_file.close();

    if (doc.HasParseError()) {
        LOGE("config is not a valid json file offset %u: %s",
             static_cast<unsigned>(doc.GetErrorOffset()),
             GetParseError_En(doc.GetParseError()));
        return std::nullopt;
    }

    if (!doc.IsObject()) {
        LOGE("config expected a json root object");
        return std::nullopt;
    }

    if (doc.HasMember("version")) {
        bool valid = false;
        const auto &version = doc["version"];
        if (version.IsUint()) {
            valid = (version.GetUint() == 1U);
        } else if (version.IsString()) {
            auto str = std::string(version.GetString());
            valid = (str == "1" || str == "v1");
        }

        if (!valid) {
            LOGE("invalid config: expected version to be 1");
            return std::nullopt;
        }
    }

    auto defaults = build_defaults(module_dir);
    if (doc.HasMember("defaults")) {
        if (!apply_target_overrides(doc["defaults"], defaults, "defaults", false)) {
            return std::nullopt;
        }
    }

    if (!doc.HasMember("targets")) {
        LOGE("expected config.targets");
        return std::nullopt;
    }

    const auto &targets = doc["targets"];
    if (!targets.IsArray()) {
        LOGE("expected config targets to be an array");
        return std::nullopt;
    }

    std::optional<target_config> selected_target;
    int skipped_targets = 0;

    for (rapidjson::SizeType i = 0; i < targets.Size(); i++) {
        auto context = "targets[" + std::to_string(i) + "]";
        const auto &target_doc = targets[i];

        target_config candidate = defaults;
        if (!apply_target_overrides(target_doc, candidate, context, true)) {
            skipped_targets++;
            continue;
        }

        if (!matches_process(candidate, process_name)) {
            continue;
        }

        if (!selected_target.has_value()) {
            candidate.process_name = process_name;
            selected_target = candidate;
            continue;
        }

        LOGI("multiple targets matched process %s, keeping first match %s and ignoring %s",
             process_name.c_str(),
             selected_target.value().app_name.c_str(),
             candidate.app_name.c_str());
    }

    if (skipped_targets > 0) {
        LOGE("skipped %d invalid target(s) while parsing config", skipped_targets);
    }

    if (!selected_target.has_value()) {
        LOGI("no target matched process %s", process_name.c_str());
    }

    return selected_target;
}

std::optional<target_config> load_config(const std::string &module_dir, const std::string &app_name) {
    return load_advanced_config(module_dir, app_name);
}
