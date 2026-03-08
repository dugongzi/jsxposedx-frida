#include <string>

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

        this->prepared = prepare_for_process(this->app_name);
    }

    void postAppSpecialize(const AppSpecializeArgs *args) override {
        (void) args;

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

REGISTER_ZYGISK_MODULE(MyModule)
