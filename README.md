# ZygiskFrida

[中文说明 / Chinese documentation](./README_zh.md)

This repository is a fork of [`lico-n/ZygiskFrida`](https://github.com/lico-n/ZygiskFrida). The current branch builds a Magisk module named `JsxposedxFrida` with module ID `jsxposedx-frida`.

Its purpose is to inject Frida Gadget and additional native libraries into target apps through Zygisk or Riru, using a structured `config.json v1` instead of the legacy plain-text configuration files.

## What This Fork Changes

- Uses `config.json v1` as the only supported configuration entrypoint.
- Removes the legacy `target_packages` and `injected_libraries` file-based mode.
- Generates runtime gadget files per matched process under `/data/local/tmp/JsxposedXSo/runtime/`.
- Uses Zygisk companion preparation when available to avoid app-side access issues for `/data/local/tmp`.
- Supports `gadget.js_path`, `gadget.script_dir`, and `gadget.frida_config`.
- Supports `child_gating` with `freeze`, `kill`, and `inject` modes.
- Auto-generates a child gadget when `child_gating.mode=inject` and no child libraries are explicitly provided.
- Keeps runtime remap disabled for stability on some ROMs.

## Features

- Two build flavors:
  - `Zygisk`
  - `Riru`
- Four ABIs:
  - `armeabi-v7a`
  - `arm64-v8a`
  - `x86`
  - `x86_64`
- Automatically downloads and packages Frida Gadget during build.
- Installs runtime assets into `/data/local/tmp/JsxposedXSo`.
- Builds per-process runtime gadget config files.

## Project Layout

```text
.
├── module/                    Native module implementation
│   └── src/jni/               Zygisk / Riru / injection / config parsing
├── template/magisk_module/    Magisk packaging template and install scripts
├── gadget/                    Downloaded Frida Gadget archives
├── docs/                      Supplemental configuration notes
├── out/                       Built zip outputs and expanded module trees
├── config.json                Default config template
└── module.gradle              Module metadata and Frida version
```

## Build Requirements

- JDK 17
- Android SDK
- Android NDK `25.2.9519653`
- A rooted device using:
  - Zygisk
  - or Riru

Current build constants in this repository:

- `minSdkVersion = 23`
- `targetSdkVersion = 32`
- `fridaVersion = 16.7.19`
- `moduleVersion = v2.0.0`

## Build

Make sure `local.properties` points to your Android SDK.

Build the Zygisk release package:

```bash
./gradlew :module:assembleZygiskRelease
```

Build the Riru release package:

```bash
./gradlew :module:assembleRiruRelease
```

You can also invoke the zip tasks directly:

```bash
./gradlew :module:zipZygiskRelease
./gradlew :module:zipRiruRelease
```

Generated artifacts are written to `out/`, for example:

```text
out/JsxposedxFrida-v2.0.0-zygisk-release.zip
out/JsxposedxFrida-v2.0.0-riru-release.zip
```

## Device Runtime Layout

After installation, the module prepares:

```text
/data/local/tmp/JsxposedXSo
├── config.json
├── libgadget.so
├── libgadget32.so
└── runtime/
```

Notes:

- `config.json` is the runtime configuration file.
- `libgadget.so` is the default gadget source used for runtime copies.
- `runtime/` is created and populated when matching target processes start.

## Configuration Entry Point

The current implementation only reads:

```text
/data/local/tmp/JsxposedXSo/config.json
```

The default template in this repository is [config.json](./config.json).

These legacy files are no longer supported:

- `/data/local/tmp/JsxposedXSo/target_packages`
- `/data/local/tmp/JsxposedXSo/injected_libraries`

## `config.json v1` Example

```json
{
  "version": 1,
  "defaults": {
    "enabled": true,
    "process_scope": "main_and_child",
    "start_up_delay_ms": 0,
    "injected_libraries": [],
    "child_gating": {
      "enabled": false,
      "mode": "freeze",
      "injected_libraries": []
    },
    "gadget": {
      "enabled": true,
      "source_path": "/data/local/tmp/JsxposedXSo/libgadget.so"
    }
  },
  "targets": [
    {
      "app_name": "com.example.app",
      "gadget": {
        "js_path": "/data/local/tmp/JsxposedX/com.example.app/hook.js"
      }
    }
  ]
}
```

## Configuration Rules

Root fields:

- `version`
- `defaults`
- `targets`

Each target requires:

- `app_name`

Optional target fields:

- `enabled`
- `process_scope`
- `start_up_delay_ms`
- `injected_libraries`
- `child_gating`
- `gadget`

Process matching:

- `main_only`: exact match to `app_name`
- `main_and_child`: matches `app_name` and `app_name:*`

`injected_libraries` must be an object array:

```json
"injected_libraries": [
  {
    "path": "/data/local/tmp/libextra.so"
  }
]
```

Supported `gadget` fields:

- `enabled`
- `source_path`
- `js_path`
- `script_dir`
- `frida_config`

Rules:

- `js_path`, `script_dir`, and `frida_config` are mutually exclusive.
- `source_path` must be non-empty when `gadget.enabled=true`.
- `js_path` generates a `script` interaction config.
- `script_dir` generates a `script-directory` interaction config.
- `frida_config` is serialized as the final Gadget config object.
- If none of the three selectors is specified, the module generates a default `listen` config on `127.0.0.1:27042`.

Supported `child_gating` fields:

- `enabled`
- `mode`
- `injected_libraries`

Supported modes:

- `freeze`
- `kill`
- `inject`

If all of the following are true:

- `child_gating.enabled = true`
- `child_gating.mode = "inject"`
- `child_gating.injected_libraries = []`

the module auto-generates:

```text
/data/local/tmp/JsxposedXSo/runtime/<process_key>/
├── libgadget-child.so
└── libgadget-child.config.so
```

The default child listen port is `27043`, and child listen configs force `on_port_conflict=pick-next`.

## Runtime Flow

The current implementation uses a two-stage flow.

### 1. PREPARE

Before app specialization:

- Parse `config.json`
- Match the target process
- Create `runtime/<process_key>/`
- Copy the gadget source
- Write `libgadget.config.so`
- Build an in-memory injection plan

### 2. INJECT

After app specialization:

- Wait for process initialization
- Enable `child_gating` if configured
- Apply `start_up_delay_ms`
- Inject the runtime gadget first
- Inject extra native libraries afterwards

On Zygisk, the module prefers companion-based preparation. On Riru, preparation happens in the regular process flow.

## Runtime Example

If the real process name is `com.example.app:remote`, the runtime files will be generated under:

```text
/data/local/tmp/JsxposedXSo/runtime/com.example.app__remote/
├── libgadget.so
├── libgadget.config.so
├── libgadget-child.so
└── libgadget-child.config.so
```

The `:` character is replaced with `__`.

## Debugging Commands

View logs:

```bash
adb logcat -s ZygiskFrida Frida
```

Inspect runtime directories:

```bash
adb shell su -c 'ls -la /data/local/tmp/JsxposedXSo/runtime'
```

Inspect a generated Gadget config:

```bash
adb shell su -c 'cat /data/local/tmp/JsxposedXSo/runtime/com.example.app/libgadget.config.so'
```

Restart a target app:

```bash
adb shell su -c 'am force-stop com.example.app'
adb shell su -c 'monkey -p com.example.app -c android.intent.category.LAUNCHER 1'
```

## Troubleshooting

If runtime files are not generated, check:

- whether `config.json` is placed at `/data/local/tmp/JsxposedXSo/config.json`
- whether `targets` is an array of objects
- whether `app_name` matches the actual process name
- whether `gadget.source_path` exists on device
- whether logs contain `[PREPARE]` errors

If runtime files exist but your script does not run, check:

- whether the generated `libgadget.config.so` points to the correct script path
- whether the script file really exists and is readable
- whether you accidentally rely on the default `listen` mode
- whether the script itself works

If injection logs exist but hooks still do not take effect, the problem is usually in the script or target timing rather than in the injector itself.

## Additional Documents

- [docs/advanced_config.md](./docs/advanced_config.md)
- [docs/simple_config.md](./docs/simple_config.md)
- [docs/AI_RUNTIME_USAGE_V1.md](./docs/AI_RUNTIME_USAGE_V1.md)

For normal usage, this README plus `advanced_config.md` should be enough.

## Credits

- Upstream project: [`lico-n/ZygiskFrida`](https://github.com/lico-n/ZygiskFrida)
- Frida
- Magisk / Zygisk
- Riru
- Dobby
- xDL

## License

This project follows the repository [LICENSE](./LICENSE).
