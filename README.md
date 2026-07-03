# xppb (cross-platform python bundler)

-----

v1.0.0

-----

xppb is a fast(when compared to PyInstaller and Nuitka) and cross-platform binary bundler designed to compile, de-bloat, and bundle Python programmes for Linux, Winslop and macOS.

Unlike traditional bundlers that are severely limited by their host operating system, xppb supports **cross-compilation** out of the box. By temporarily spoofing the Python interpreter's global state and relying on standard archives, a developer on Linux can easily build a signed Windows `.exe` and a fully notarized macOS `.app` bundle simultaneously in a single execution in a matter of seconds(takes a lot configuration and 20-30 min in Nuitka for reference).

---

While tools like PyInstaller, Nuitka, and cx_Freeze are industry standards, xppb bypasses their historical limitations through an aggressive architecture:

* **Single-Host Cross-Compilation**: PyInstaller and Nuitka require you to build Windows binaries on a Windows host. xppb utilizes a `mock_target_environment` context manager to trick the host Python environment and `modulegraph` into evaluating code paths as if they were running natively on the target operating system.


* **Aggressive "Default-Deny" Bloat Wiping**: Traditional bundlers pull in massive directories based on exclusion lists. xppb uses a strict whitelist, deleting every file in `site-packages` and the standard library that is not explicitly resolved by the dependency graph. It safely preserves only the structural `__init__.py` files, compiled extensions, and active metadata blocks (like `.dist-info`).


* **Host-Agnostic Apple Code-Signing**: You no longer need an Xcode-equipped Mac to notarize macOS software. xppb automatically fetches Indygreg’s cross-platform `rcodesign` tool to cryptographically sign bundles and submit them directly to the Apple Notary API from Linux or Windows environments.


* **Fast Dependency Resolution**: xppb searches the host for Astral's `uv` binary. If found, it routes dependency installation through `uv`, utilizing its `--platform` and `--abi` flags to download platform-specific wheels in a fraction of the time standard `pip` would take.


* **Zero-Flash Windows Launchers**: Instead of relying solely on slow script wrappers, xppb scans the host for native C compilers (`gcc`, `cl`, etc.) and dynamically templates and compiles a C-based executable (`launcher_stub.c`) to launch the application silently without console flashes.



---

## Features

### 1. The Environment Spoofer (`mock_target_environment`)

To trace platform-specific dependencies (like `winreg` on Windows or `termios` on Linux) without crashing the host machine, xppb temporarily intercepts and rewrites Python's core system identifiers.

```python
# Modifies global state thread-safely before ModuleGraph execution
if "windows" in target_os:
    sys.platform = "win32"
    os.name = "nt"
    sys.builtin_module_names = tuple(set(orig_builtins) | {"winreg", "msvcrt", "_winapi", "nt"})

```

### 2. C-Extension Binary Rescuer

Compiled modules (`.so` / `.pyd`) often hide dynamic imports in their C code that standard AST tracers miss. xppb sweeps compiled extensions, reading them as binary data and matching valid ASCII strings against available system modules to rescue hidden dependencies.

```python
with open(file_path, "rb") as f:
    data = f.read()
for s in data.split(b'\0'):
    # Look for strings that match the active environment file map
    if 2 < len(s) < 50 and s.replace(b'.', b'').replace(b'_', b'').isalnum():
        # ...rescues missing modules...

```

### 3. Persistent Runtime Caching

To save bandwidth across frequent builds, xppb downloads massive standard standard-library `.tar.gz` runtimes into a persistent user-level directory (`~/.core_bundler_cache/runtimes`). Subsequent cross-compilations pull locally from the cache instantly.

---

## On Using It

## Through uv:
```
uv pip install xppb
```

## Through pip:
just remove the uv from the above command.

## Git Clone:
```
git clone https://github.com/nulsie/xppb.git
cd xppb
```

### Prerequisites

* Python 3.11+
* `pip install modulegraph`

* *(Optional but Recommended)*: Install `uv` for absurdly accelerated wheel downloads.



### Configuration (`projconf.toml`)

Like others, a build in xppb is governed by a config file(TOML is supported because it is pre-packaged with Python). Create a file named `projconf.toml` in your project root. Here is a complete reference of the required layout:

```toml
[project]
name = "MyAwesomeApp"
version = "1.0.0"
python_version = "3.11"
entry_point = "main.py"
source_files = ["main.py", "assets/"]
dependencies = ["requests", "rich", "numpy"]
hidden_imports = ["pkg_resources.extern"]
collect_all = []
preserve_extensions = [".png", ".ico"]
launch_command = "{ENTRY_POINT}"

[runtimes]
# URLs pointing to standalone python standard libraries (.tar.gz)
windows-x64 = "https://example.com/python-3.11-win64.tar.gz"
macos-arm64 = "https://example.com/python-3.11-macos-arm64.tar.gz"
linux-x64 = "https://example.com/python-3.11-linux64.tar.gz"

[windows]
hide_console = true
pfx_certificate = "certs/win_cert.pfx"
pfx_password = "SuperSecretPassword123"
hidden_imports = ["winreg"]

[macos]
p12_certificate = "certs/mac_cert.p12"
p12_password = "SuperSecretPassword123"
api_key_path = "certs/AuthKey_ABCD123.p8"
api_issuer_id = "xxxxxx-xxxx-xxxx-xxxx-xxxxxxxx"
api_key_id = "ABCD123"

```

### Usage

Once your `projconf.toml` is configured, simply run `xppb` in your working directory and execute it:

```bash
xppb

```

xppb utilizes a `ProcessPoolExecutor` to spin up a concurrent build thread for every OS target defined in your `[runtimes]` configuration block.

* Build artifacts are processed temporarily in a `build/` directory.

* Final, compressed distribution assets (ready to be uploaded) are deposited into `dist/`.

-----

**Author:** nulsie **License:** MIT 

-----

*Note: the pip package version will always be one minor version ahead of others because i had forgot to add the license file in the first build so had to do it again.*
