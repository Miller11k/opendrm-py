# OpenDRM-Py  
**A Modular, End-to-End Digital Rights Management (DRM) Framework with Certificate Authorities, Media Encryption, and Watermarking**

OpenDRM-Py is a fully extensible DRM research framework built around a multi-tier certificate authority (CA) hierarchy, authenticated encryption, license issuance, and optional image/video watermarking.  
It is designed for experimentation, reproducibility, and clear separation of concerns across cryptographic components.

This repository includes:

- A full **certificate server** with root + intermediate CAs
- A **license server** that issues and validates DRM licenses
- A **media encryption pipeline** supporting symmetric encryption, CA-based key wrapping, and integrity protection
- **Watermarking modules** for images and video
- **Client emulation** and **attack scenarios** for adversarial testing
- **Extensive test suites** (unit + integration + E2E)
- **Examples, sample workflows, and notebooks**

---

## Repository Structure

```
opendrm-py/
├── data/
│   ├── ca/                # Root + intermediate CA state
│   ├── exports/           # Exported server state bundles
│   ├── licenses/          # Generated DRM licenses
│   ├── logs/              # Runtime logs
│   └── registry/          # License + cert registry DBs
│
├── docs/                  # Project documentation
│   ├── architecture.md
│   ├── usage.md
│   ├── testing.md
│   └── references.md
│
├── examples/
│   ├── demo_notebooks/    # Walkthrough Jupyter notebooks
│   ├── example_workflows/ # End-to-end DRM examples
│   └── sample_media/      # Example files for testing
│
├── sample-cert-server/    # Full example certificate server instance
│   ├── ca/                # Root + intermediates, certs, CRL, keys
│   ├── ctlog/             # Certificate Transparency log DB + keys
│   ├── db/                # Audit + registry databases
│   ├── keystores/         # OCSP signer + server certs
│   └── logs/
│
├── scripts/               # Utility scripts
│   ├── setup.sh
│   ├── run_tests.sh
│   ├── export_state.py
│   └── import_state.py
│
├── src/
│   ├── cert_server/       # Certificate server components
│   │   ├── initialize_server.py
│   │   ├── import_server.py
│   │   ├── export_server.py
│   │   └── verify_server.py
│   │
│   └── drm/
│       ├── ca/            # CA manager, CT log, OpenSSL helpers
│       ├── encryption/    # AES-GCM, key wrap, ciphers
│       ├── license_server/# License schema, registry, server
│       ├── client/        # Client emulator + attack scenarios
│       ├── watermarking/  # Image + video watermarking
│       ├── utils/         # Config, IO, logging, crypto helpers
│       └── main.py        # CLI entrypoint
│
├── tests/
│   ├── unit/
│   ├── integration/
│   └── conftest.py
│
├── Dockerfile
├── Makefile
├── pyproject.toml
├── README.md
├── LICENSE
└── example_media.key
```

---

## Features

### Multi-Layer Certificate Authority
- Root + intermediate CAs  
- Policy-driven issuance  
- CT log, CRL, OCSP support  

### Media Encryption
- AES-GCM  
- Wrapped keys via CA  
- Signed metadata  

### License Server
- JSON-schema validated licenses  
- Registry + audit logs  
- Policy enforcement  

### Watermarking
- Image + video watermarking  

### Testing
- Unit + integration + E2E  

---

## Getting Started

```bash
pip install -e .
```

### Initialize CA
```bash
python -m drm.main init-ca
```

### Encrypt media
```bash
python -m drm.main encrypt --input sample.mp4 --output sample.mp4.opdrm
```

### Issue a license
```bash
bash examples/example_workflows/issue_license.sh
```

---

## Documentation

- Architecture → docs/architecture.md  
- Usage → docs/usage.md  
- Testing → docs/testing.md  

---

## License
MIT
