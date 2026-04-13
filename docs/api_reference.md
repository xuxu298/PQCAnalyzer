# API Reference

The REST API is available in the **Enterprise Edition** only.

For enterprise licensing, contact: **support@vradar.io**

## Community Edition

The Community Edition provides full functionality via CLI:

```bash
# Scan
pqc-analyzer scan tls example.com
pqc-analyzer scan ssh /etc/ssh/sshd_config
pqc-analyzer scan vpn /etc/openvpn/server.conf
pqc-analyzer scan code ./src
pqc-analyzer scan config /etc/nginx/nginx.conf

# Benchmark
pqc-analyzer benchmark kem --iterations 1000
pqc-analyzer benchmark sign --iterations 1000
pqc-analyzer benchmark all
pqc-analyzer benchmark hardware

# Roadmap
pqc-analyzer roadmap generate --findings results.json

# Export JSON
pqc-analyzer scan tls example.com -o results.json
```

All commands support `--output` / `-o` for JSON export and `--language` / `-l` for bilingual output (en/vi).

---

**Developed by:** [Nguyen Dong](https://www.linkedin.com/in/dongnx/) — Founder of [vradar.io](https://vradar.io)
