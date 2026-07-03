# xppb (cross-platform python bundler)

-----

v1.0.0

-----

xppb is a fast(when compared to PyInstaller and Nuitka) and cross-platform binary bundler designed to compile, prune, and bundle Python programmes for Linux, Winslop and macOS. Unlike traditional bundlers that are severely limited by their host operating system, xppb supports **cross-compilation** out of the box. By temporarily spoofing the Python interpreter's global state and relying on standard archives, a developer on Linux can easily build a signed Windows `.exe` and a fully notarized macOS `.app` bundle simultaneously in a single execution from a single machine in a matter of seconds(takes a lot configuration and 20-30 min in Nuitka for reference).

The build size in this tool is also very minimal(kinda on par with Nuitka's build sizes), by using a strict 'default-deny' whitelist approach, deleting every file in `site-packages` and the standard library that is not explicitly resolved by the dependency graph. It safely preserves only the structural `__init__.py` files, compiled extensions, and active metadata blocks (like `.dist-info`).

xppb also have built-in features of code signing for Mac and Winslop, hence letting the user straightforwardly sign or notarize a program for macOS or Winslop from other OSes(eg, Linux) or machines.

It also checks if the user is having `uv` and if so, will resort to installation with it, as `uv` provides an absurdly fast deps resolution than the standard `pip`.

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