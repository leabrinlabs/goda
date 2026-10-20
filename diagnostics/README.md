# Passive diagnostics

The resident Goda ELF writes a rolling runtime log. The optional reader forwards existing logs to a private PC collector; it does not launch games or mount game folders.

Prepare a private kit (this does not connect to the console):

```sh
python3 diagnostics/prepare_live_logs.py --sdk /path/to/ps5-payload-sdk \
  --collector-ip PC_IP --console-ip PS5_IP --output dist/private-live-kit
python3 diagnostics/record_live_logs.py --config dist/private-live-kit/config.json \
  --output dist/private-capture
```

Use real private IPv4 addresses in place of `PC_IP` and `PS5_IP`. Keep generated configs, reader ELFs and captures private: they contain session credentials or device data. Transport is not encrypted; use a trusted local network. Do not start a second reader when a session is already active. Session metadata can point `diagnostics/runtime_state.py` at an existing capture; state reads stay local and never deploy a helper ELF.
