#include <string>
#include <unistd.h>

#include "inject.h"
#include "log.h"
#include "zygisk.h"

using zygisk::Api;
using zygisk::AppSpecializeArgs;
using zygisk::ServerSpecializeArgs;

class MyModule : public zygisk::ModuleBase {
 public:
    void onLoad(Api *api, JNIEnv *env) override {
        this->api = api;
        this->env = env;
    }

    void preAppSpecialize(AppSpecializeArgs *args) override {
        const char *raw_app_name = env->GetStringUTFChars(args->nice_name, nullptr);
        this->app_name = std::string(raw_app_name);
        this->env->ReleaseStringUTFChars(args->nice_name, raw_app_name);

        auto companion_fd = this->api->connectCompanion();
        if (companion_fd >= 0) {
            this->prepared = prepare_for_process_with_companion(this->app_name, companion_fd);
            close(companion_fd);
            LOGI("[PREPARE] companion prepare result for %s: %s",
                 this->app_name.c_str(),
                 this->prepared ? "ok" : "failed");
            return;
        }

        LOGE("[PREPARE] failed to connect companion for %s, falling back to local prepare",
             this->app_name.c_str());
        this->prepared = prepare_for_process(this->app_name);
    }

    void postAppSpecialize(const AppSpecializeArgs *args) override {
        (void) args;
        LOGI("[INJECT] postAppSpecialize for %s (prepared=%s)",
             this->app_name.c_str(),
             this->prepared ? "true" : "false");

        if (!this->prepared || !inject_prepared(this->app_name)) {
            this->api->setOption(zygisk::Option::DLCLOSE_MODULE_LIBRARY);
        }
    }

 private:
    Api *api;
    JNIEnv *env;
    std::string app_name;
    bool prepared = false;
};

static void companion_handler(int client) {
    handle_prepare_companion_request(client);
}

REGISTER_ZYGISK_COMPANION(companion_handler)
REGISTER_ZYGISK_MODULE(MyModule)
