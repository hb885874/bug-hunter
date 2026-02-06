# Installation

## Python dependencies

Install the Python dependencies with:

```bash
pip install -r requirements.txt
```

## External tools (binaries)

Some scanners used by the agent are distributed as standalone binaries (Go projects). They must be installed separately and available on your `PATH`.

Common install methods:

- Using Go (requires Go installed and `GOBIN` or `GOPATH/bin` on PATH):

```bash
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/owasp-amass/amass/v3/...@latest
go install github.com/projectdiscovery/katana/cmd/katana@latest
```

- Or download prebuilt binaries from the projects' GitHub releases pages and place them on your `PATH`.

If a tool is not present the agent will skip it and record a note in `artifacts/raw/`.

## Notes

- `httpx` also has a Python CLI distributed via pip (`httpx[cli]`). The `requirements.txt` contains `httpx[cli]` to support the HTTP probing functionality when a pip-installed variant is preferred.
- For Windows, install Go from https://go.dev/dl/ and ensure `%GOPATH%\\bin` or `%GOBIN%` is in your PATH.
