#ifndef ZYGISKFRIDA_INJECT_H
#define ZYGISKFRIDA_INJECT_H

#include <string>

void inject_lib(std::string const& lib_path, std::string const& logContext);
bool prepare_for_process(std::string const& app_name);
bool prepare_for_process_with_companion(std::string const& app_name, int companion_fd);
bool inject_prepared(std::string const& app_name);
void handle_prepare_companion_request(int client_fd);
bool check_and_inject(std::string const& app_name);

#endif  // ZYGISKFRIDA_INJECT_H
