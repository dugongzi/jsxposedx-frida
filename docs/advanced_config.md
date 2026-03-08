# Advanced Config (v1)

This module only supports `config.json` (v1).  
Legacy `target_packages` / `injected_libraries` files are removed.

## 1. Config Path

Runtime config path:

`/data/local/tmp/JsxposedXSo/config.json`

## 2. v1 Schema Overview

Root fields:

- `version`: must be `1`
- `defaults`: shared defaults for all targets
- `targets`: per-app entries, `app_name` is required

## 3. Full Example

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
      "app_name": "com.example.a",
      "gadget": {
        "js_path": "/data/local/tmp/JsxposedXSo/scripts/a.js"
      }
    },
    {
      "app_name": "com.example.b",
      "start_up_delay_ms": 5000,
      "gadget": {
        "script_dir": "/data/local/tmp/JsxposedXSo/scripts/b"
      }
    }
  ]
}
```

## 4. Merge Rules (`defaults` -> `targets[i]`)

- `targets[i]` overrides same field from `defaults`.
- `injected_libraries` is replaced as a whole when present in target.
- `gadget.js_path`, `gadget.script_dir`, `gadget.frida_config` are mutually exclusive.
- Invalid targets are skipped and do not block valid targets.

## 5. Process Matching

`process_scope` options:

- `main_only`: match exact process name only.
- `main_and_child`: match `com.app` and `com.app:*` (default).

## 6. Gadget Runtime Isolation

When gadget is enabled, module auto-generates runtime files per process:

```text
/data/local/tmp/JsxposedXSo/runtime/<process_key>/
├── libgadget.so
└── libgadget.config.so
```

`<process_key>` is the real process name with `:` replaced by `__`.

When `child_gating.mode=inject` and `child_gating.injected_libraries` is empty,
module also auto-generates child gadget files:

```text
/data/local/tmp/JsxposedXSo/runtime/<process_key>/
├── libgadget-child.so
└── libgadget-child.config.so
```

For child listen config, module enforces `on_port_conflict=pick-next`.

## 7. Gadget Config Sources

Inside `gadget`:

- `frida_config`: use this object as final gadget config.
- `js_path`: auto-generate `interaction.type=script`.
- `script_dir`: auto-generate `interaction.type=script-directory`.
- none of above: auto-generate default listen config (`127.0.0.1:27042`, `on_load=wait`).

## 8. Add a New Target (installed module workflow)

1. Edit `/data/local/tmp/JsxposedXSo/config.json` and append one target object.
2. Restart target app process.
3. Check runtime files:
   - `adb shell su -c 'ls -la /data/local/tmp/JsxposedXSo/runtime'`
4. Check logs:
   - `adb logcat -s ZygiskFrida Frida`

## 9. Child Auto Inject Example

```json
{
  "app_name": "com.example.a",
  "child_gating": {
    "enabled": true,
    "mode": "inject",
    "injected_libraries": []
  }
}
```

With `injected_libraries: []`, module will auto-generate and inject child gadget runtime files.
