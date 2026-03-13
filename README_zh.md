# ZygiskFrida

[English README](./README.md)

这是一个基于上游 [`lico-n/ZygiskFrida`](https://github.com/lico-n/ZygiskFrida) 的二开版本，当前仓库产出的模块名为 `JsxposedxFrida`，模块 ID 为 `jsxposedx-frida`。

项目目标是在 Zygisk / Riru 环境下，将 Frida Gadget 和额外 native so 按进程规则注入到目标应用，并通过结构化的 `config.json v1` 完成配置管理。

## 当前分支的重点改动

- 仅保留 `config.json v1` 配置入口。
- 移除了旧的 `target_packages` / `injected_libraries` 文件配置方式。
- 为每个命中的进程生成独立的 runtime gadget 和配置文件。
- Zygisk 路径优先通过 companion 进程做预处理，减少应用进程访问 `/data/local/tmp` 的权限问题。
- 支持 `gadget.js_path`、`gadget.script_dir`、`gadget.frida_config`。
- 支持 `child_gating` 的 `freeze`、`kill`、`inject` 模式。
- 当 `child_gating.mode=inject` 且未显式提供子进程库列表时，可自动生成子进程 gadget。
- 当前为了稳定性关闭了运行时 remap。

## 功能概览

- 支持两种 flavor：
  - `Zygisk`
  - `Riru`
- 支持四种 ABI：
  - `armeabi-v7a`
  - `arm64-v8a`
  - `x86`
  - `x86_64`
- 构建时自动下载并打包 Frida Gadget。
- 安装后会将运行时资源解压到 `/data/local/tmp/JsxposedXSo`。
- 可按进程生成独立的 runtime gadget 配置。

## 项目结构

```text
.
├── module/                    Native 模块实现
│   └── src/jni/               Zygisk / Riru / 注入 / 配置解析
├── template/magisk_module/    Magisk 打包模板和安装脚本
├── gadget/                    构建时下载的 Frida Gadget 压缩包
├── docs/                      配置和运行逻辑补充文档
├── out/                       zip 产物和展开目录
├── config.json                默认配置模板
└── module.gradle              模块元信息和 Frida 版本
```

## 构建环境

- JDK 17
- Android SDK
- Android NDK `25.2.9519653`
- 已 Root 的设备
- 目标环境为：
  - Zygisk
  - 或 Riru

当前仓库中的关键构建参数：

- `minSdkVersion = 23`
- `targetSdkVersion = 32`
- `fridaVersion = 16.7.19`
- `moduleVersion = v2.0.0`

## 构建

确保 `local.properties` 已正确指向 Android SDK。

构建 `Zygisk release`：

```bash
./gradlew :module:assembleZygiskRelease
```

构建 `Riru release`：

```bash
./gradlew :module:assembleRiruRelease
```

也可以直接执行打包任务：

```bash
./gradlew :module:zipZygiskRelease
./gradlew :module:zipRiruRelease
```

产物输出到 `out/`，例如：

```text
out/JsxposedxFrida-v2.0.0-zygisk-release.zip
out/JsxposedxFrida-v2.0.0-riru-release.zip
```

## 设备端运行目录

模块安装后会准备：

```text
/data/local/tmp/JsxposedXSo
├── config.json
├── libgadget.so
├── libgadget32.so
└── runtime/
```

说明：

- `config.json` 是运行时配置文件。
- `libgadget.so` 是默认 gadget 母体文件。
- `runtime/` 会在匹配目标进程启动时自动创建并填充。

## 配置入口

当前实现只读取：

```text
/data/local/tmp/JsxposedXSo/config.json
```

仓库中的默认模板见 [config.json](./config.json)。

以下旧文件已不再支持：

- `/data/local/tmp/JsxposedXSo/target_packages`
- `/data/local/tmp/JsxposedXSo/injected_libraries`

## `config.json v1` 示例

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

## 配置规则

根字段：

- `version`
- `defaults`
- `targets`

每个 target 必填：

- `app_name`

可选字段：

- `enabled`
- `process_scope`
- `start_up_delay_ms`
- `injected_libraries`
- `child_gating`
- `gadget`

进程匹配规则：

- `main_only`：只匹配主进程，必须等于 `app_name`
- `main_and_child`：匹配 `app_name` 以及 `app_name:*`

`injected_libraries` 必须是对象数组：

```json
"injected_libraries": [
  {
    "path": "/data/local/tmp/libextra.so"
  }
]
```

`gadget` 支持字段：

- `enabled`
- `source_path`
- `js_path`
- `script_dir`
- `frida_config`

规则：

- `js_path`、`script_dir`、`frida_config` 三者互斥。
- 当 `gadget.enabled=true` 时，`source_path` 不能为空。
- `js_path` 会生成 `script` 类型 interaction 配置。
- `script_dir` 会生成 `script-directory` 类型 interaction 配置。
- `frida_config` 会直接序列化为最终 Gadget 配置对象。
- 如果三者都不写，则自动生成默认 `listen` 配置，监听 `127.0.0.1:27042`。

`child_gating` 支持字段：

- `enabled`
- `mode`
- `injected_libraries`

支持模式：

- `freeze`
- `kill`
- `inject`

当同时满足以下条件时：

- `child_gating.enabled = true`
- `child_gating.mode = "inject"`
- `child_gating.injected_libraries = []`

模块会自动生成：

```text
/data/local/tmp/JsxposedXSo/runtime/<process_key>/
├── libgadget-child.so
└── libgadget-child.config.so
```

子进程默认监听端口为 `27043`，并强制补上 `on_port_conflict=pick-next`。

## 运行机制

当前实现采用两段式流程。

### 1. PREPARE

在应用进程特化前：

- 解析 `config.json`
- 匹配目标进程
- 创建 `runtime/<process_key>/`
- 复制 gadget 母体
- 写入 `libgadget.config.so`
- 构建内存中的待注入计划

### 2. INJECT

在应用进程特化后：

- 等待进程初始化
- 按配置启用 `child_gating`
- 执行 `start_up_delay_ms`
- 先注入 runtime gadget
- 再注入额外 native so

Zygisk 路径优先走 companion prepare，Riru 路径则在常规流程中完成 prepare。

## Runtime 示例

如果真实进程名是 `com.example.app:remote`，则会生成：

```text
/data/local/tmp/JsxposedXSo/runtime/com.example.app__remote/
├── libgadget.so
├── libgadget.config.so
├── libgadget-child.so
└── libgadget-child.config.so
```

其中 `:` 会被替换为 `__`。

## 常用调试命令

查看日志：

```bash
adb logcat -s ZygiskFrida Frida
```

查看 runtime 目录：

```bash
adb shell su -c 'ls -la /data/local/tmp/JsxposedXSo/runtime'
```

查看生成的 Gadget 配置：

```bash
adb shell su -c 'cat /data/local/tmp/JsxposedXSo/runtime/com.example.app/libgadget.config.so'
```

重启目标应用：

```bash
adb shell su -c 'am force-stop com.example.app'
adb shell su -c 'monkey -p com.example.app -c android.intent.category.LAUNCHER 1'
```

## 常见问题

如果 runtime 文件没有生成，优先检查：

- `config.json` 是否位于 `/data/local/tmp/JsxposedXSo/config.json`
- `targets` 是否为对象数组
- `app_name` 是否匹配真实进程名
- `gadget.source_path` 是否存在
- 日志中是否出现 `[PREPARE]` 错误

如果 runtime 文件生成了但脚本没有执行，优先检查：

- `libgadget.config.so` 是否指向正确脚本路径
- 脚本文件是否真实存在且可读
- 是否误用了默认 `listen` 模式
- 脚本本身是否正常

如果有注入日志但 Hook 仍未生效，通常问题在脚本本身或注入时机，而不是注入器本体。

## 相关文档

- [docs/advanced_config.md](./docs/advanced_config.md)
- [docs/simple_config.md](./docs/simple_config.md)
- [docs/AI_RUNTIME_USAGE_V1.md](./docs/AI_RUNTIME_USAGE_V1.md)

日常使用看本文和 `advanced_config.md` 一般就够了。

## 致谢

- 上游项目：[`lico-n/ZygiskFrida`](https://github.com/lico-n/ZygiskFrida)
- Frida
- Magisk / Zygisk
- Riru
- Dobby
- xDL

## License

本项目遵循仓库中的 [LICENSE](./LICENSE)。
