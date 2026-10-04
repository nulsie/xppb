import tomllib
import os
import sys
import shutil
import urllib.request
import tarfile
import zipfile
import subprocess
import platform
import concurrent.futures
import tempfile
import contextlib
import compileall
import re
from pathlib import Path

@contextlib.contextmanager
def mock_target_environment(platform_name):
    orig_platform = sys.platform
    orig_os = os.name
    orig_builtins = sys.builtin_module_names
    target_os = platform_name.lower()
    if 'windows' in target_os:
        sys.platform = 'win32'
        os.name = 'nt'
        sys.builtin_module_names = tuple(set(orig_builtins) | {'winreg', 'msvcrt', '_winapi', 'nt'})
    elif 'macos' in target_os:
        sys.platform = 'darwin'
        os.name = 'posix'
        sys.builtin_module_names = tuple(set(orig_builtins) | {'posix'})
    elif 'linux' in target_os:
        sys.platform = 'linux'
        os.name = 'posix'
        sys.builtin_module_names = tuple(set(orig_builtins) | {'posix'})
    try:
        yield
    finally:
        sys.platform = orig_platform
        os.name = orig_os
        sys.builtin_module_names = orig_builtins
try:
    from modulegraph.modulegraph import ModuleGraph
except ImportError:
    print("[-] Error: 'modulegraph' is required for advanced dependency analysis.")
    print('    Install it via: pip install modulegraph')
    sys.exit(1)

# (v1.1.0) add: func for zipping the pure-python std lib
def zip_stdlib(stdlib_path, site_packages_path, python_version):
    print(" -> Compressing pure-Python standard library into pythonXX.zip...")
    stdlib_path = Path(stdlib_path).resolve()
    site_packages_path = Path(site_packages_path).resolve()
    
    # formats '3.11' -> '311' (like python311.zip)
    ver_nodot = python_version.replace('.', '')
    zip_filename = f"python{ver_nodot}.zip"
    
    # place pythonXX.zip alongside stdlib/site-packages where cpython expects it
    zip_path = stdlib_path.parent / zip_filename

    with zipfile.ZipFile(zip_path, 'w', compression=zipfile.ZIP_DEFLATED, compresslevel=9) as zipf:
        for file_path in list(stdlib_path.rglob('*')):
            if not file_path.is_file():
                continue
                
            # skip anything inside site-packages
            if site_packages_path in file_path.parents or file_path == site_packages_path:
                continue
            
            # c-extensions cannot be loaded directly from inside zip files
            # only package pure Python files (.py, .pyc)
            if file_path.suffix.lower() in {'.pyc', '.py'}:
                arcname = file_path.relative_to(stdlib_path)
                zipf.write(file_path, arcname)
                try:
                    file_path.unlink()
                except OSError:
                    pass

    # clean up empty subdirs left behind in stdlib (excluding site-pkgs)
    for dir_path in sorted(stdlib_path.rglob('*'), key=lambda x: len(x.parts), reverse=True):
        if dir_path.is_dir() and dir_path != site_packages_path and site_packages_path not in dir_path.parents:
            if not any(dir_path.iterdir()):
                try:
                    dir_path.rmdir()
                except OSError:
                    pass

# (v1.1.0) add: bytecode optim and src stripping using compileall
def optimize_python_sources(target_dir):
    print(" -> Compiling bytecode (-O2) and removing raw .py files...")
    
    # legacy=True outputs foo.pyc right next to foo.py instead of __pycache__/foo.cpython-311.pyc
    compileall.compile_dir(target_dir, optimize=2, force=True, quiet=1, legacy=True)
    
    # remove the raw py files now dat it have the optimized .pyc files
    for py_file in Path(target_dir).rglob('*.py'):
        try:
            py_file.unlink()
        except OSError:
            pass

# (v1.1.0) add: both of these methodes are part of binary symbol stripping & upx compression
def strip_binaries(target_dir, platform_name):
    if 'macos' in platform_name.lower():
        return
        
    strip_bin = shutil.which('strip')
    if not strip_bin:
        print("    [-] 'strip' utility not found on host path. Skipping symbol stripping.")
        return
        
    print(" -> Stripping debug symbols from native C-extensions and executables...")
    binary_extensions = {'.so', '.pyd', '.dylib', '.dll', '.exe'}
    
    for binary in Path(target_dir).rglob('*'):
        if binary.is_file() and binary.suffix.lower() in binary_extensions:
            try:
                # --strip-unneeded is generally safe for dynamic libraries
                subprocess.run(
                    [strip_bin, '--strip-unneeded', str(binary)], 
                    stdout=subprocess.DEVNULL, 
                    stderr=subprocess.DEVNULL,
                    check=True
                )
            except subprocess.CalledProcessError:
                # some binaries (like digitally signed DLLs) may reject stripping
                pass

def upx_compress(target_dir, platform_name, exclude_list=None):
    if exclude_list is None:
        exclude_list = []
        
    if 'macos' in platform_name.lower():
        return
        
    upx_bin = shutil.which('upx')
    if not upx_bin:
        print("    [-] 'upx' utility not found on host path. Skipping UPX compression.")
        return
        
    print(f" -> Executing UPX binary compression (--best --lzma)...")
    binary_extensions = {'.so', '.pyd', '.dll', '.exe'}
    
    for binary in Path(target_dir).rglob('*'):
        if binary.is_file() and binary.suffix.lower() in binary_extensions:
            # check if the binary name matches any exclusion string
            if any(exclude.lower() in binary.name.lower() for exclude in exclude_list):
                continue
                
            try:
                subprocess.run(
                    [upx_bin, '--best', '--lzma', str(binary)], 
                    stdout=subprocess.DEVNULL, 
                    stderr=subprocess.DEVNULL,
                    check=True
                )
            except subprocess.CalledProcessError:
                pass

def generate_runtime_whitelist(entry_point_path, site_packages_path, stdlib_path, platform_name, hidden_imports=None, collect_all=None):
    if hidden_imports is None:
        hidden_imports = []
    if collect_all is None:
        collect_all = []
    print(f' -> Tracing application dependencies via ModuleGraph (Targeting: {platform_name})...')
    target_paths = [str(site_packages_path), str(stdlib_path)]
    scripts_to_trace = [str(entry_point_path)]
    temp_script_path = None  # (v1.0.1)fix: init prior to try/block
    
    if hidden_imports:
        print(f'    [*] Resolving {len(hidden_imports)} hidden imports...')
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as temp_script:
            for mod in hidden_imports:
                temp_script.write(f'import {mod}\n')
            temp_script_path = temp_script.name
        scripts_to_trace.append(temp_script_path)
            
    try:
        with mock_target_environment(platform_name):
            graph = ModuleGraph(path=target_paths)
            for script in scripts_to_trace:
                graph.run_script(script)
    finally:
        # (v1.0.1)fix: safely check if temp_script_path was assigned
        if temp_script_path and os.path.exists(temp_script_path):
            os.remove(temp_script_path)
    whitelist = set()
    missing_modules = set()
    base_paths = [Path(site_packages_path).resolve(), Path(stdlib_path).resolve()]

    def smart_whitelist_add(p):
        p = Path(p).resolve()
        if p.is_dir():
            for sub_p in p.rglob('*'):
                if sub_p.is_file():
                    smart_whitelist_add(sub_p)
            return
        whitelist.add(p)
        parent = p.parent
        while parent:
            if not any((base in parent.parents or parent == base for base in base_paths)):
                break
            for init_name in ['__init__.py', '__init__.pyc']:
                init_file = parent / init_name
                if init_file.exists():
                    whitelist.add(init_file.resolve())
            parent = parent.parent
    for node in graph.nodes():
        if hasattr(node, 'filename') and node.filename:
            smart_whitelist_add(node.filename)
        if hasattr(node, 'packagepath') and node.packagepath:
            for pkg_dir in node.packagepath:
                if pkg_dir:
                    smart_whitelist_add(pkg_dir)
        if type(node).__name__ == 'MissingModule':
            missing_modules.add(node.identifier)
    essential_modules = ['site.py', 'os.py', 'stat.py', 'genericpath.py', 'encodings', 'codecs.py', 'io.py', 'abc.py', '_collections_abc.py', 'sitecustomize.py', 'importlib']
    target_os = platform_name.lower()
    if 'windows' in target_os:
        essential_modules.extend(['ntpath.py', 'nt.py', '_winapi', 'msvcrt', 'winreg', 'socket.py', '_socket'])
    else:
        essential_modules.extend(['posixpath.py', 'posix.py', 'fcntl', 'termios', 'socket.py', '_socket'])
    for essential in essential_modules:
        for p in Path(stdlib_path).rglob(essential):
            smart_whitelist_add(p)
    print('    [*] Scanning compiled C-extensions for implicit dynamic imports...')
    target_files = {}
    for search_dir in base_paths:
        for p in search_dir.rglob('*.py'):
            # (v1.0.1)tix: map fully qualified dotted paths alongside base stems
            try:
                rel_path = p.relative_to(search_dir)
                dotted_name = str(rel_path.with_suffix('')).replace(os.sep, '.').replace('/', '.')
                target_files[dotted_name] = p
            except ValueError:
                pass
            target_files[p.stem] = p
    
    rescued_binary_deps = 0
    valid_mod_pattern = re.compile(r'^[a-zA-Z_][a-zA-Z0-9_]*(\.[a-zA-Z_][a-zA-Z0-9_]*)*$')
        
    # add a blocklist of common internal C-extension strings to prevent false positives
    ignored_c_strings = {
        'version', 'init', 'update', 'value', 'string', 'self', 'args', 
        'kwargs', 'name', 'type', 'format', 'module', 'dict', 'list', 'tuple'
    }
            
    for file_path in list(whitelist):
        if file_path.suffix.lower() in {'.so', '.pyd'}:
            try:
                with open(file_path, 'rb') as f:
                    data = f.read()
                for s in data.split(b'\x00'):
                    if 2 < len(s) < 100:
                        try:
                            mod_string = s.decode('ascii')
                            # ensure the string is valid and not a generic term
                            if valid_mod_pattern.match(mod_string) and mod_string.lower() not in ignored_c_strings:
                                if mod_string in target_files and target_files[mod_string] not in whitelist:
                                    smart_whitelist_add(target_files[mod_string])
                                    rescued_binary_deps += 1
                                else:
                                    base_name = mod_string.split('.')[-1]
                                    if base_name in target_files and target_files[base_name] not in whitelist:
                                        smart_whitelist_add(target_files[base_name])
                                        rescued_binary_deps += 1
                        except UnicodeDecodeError:
                            pass
            except OSError:
                pass
                    
    if rescued_binary_deps > 0:
        print(f'    [+] Binary scanner uncovered {rescued_binary_deps} hidden C-extension dependencies.')
    if missing_modules:
        print(f'    [*] Cross-compilation check: Attempting to rescue {len(missing_modules)} unresolved modules from target runtime...')
        target_files = {}
        for search_dir in base_paths:
            for p in search_dir.rglob('*'):
                if p.is_file():
                    target_files[p.stem] = p
        rescued_count = 0
        for bad_mod in missing_modules:
            base_name = bad_mod.split('.')[-1]
            if base_name in target_files:
                smart_whitelist_add(target_files[base_name])
                rescued_count += 1
        if rescued_count > 0:
            print(f'    [+] Rescued {rescued_count} platform-specific modules from the cutting room floor.')
    if collect_all:
        print(f"    [*] Applying 'collect_all' override for {len(collect_all)} dynamic packages...")
        for pkg_name in collect_all:
            pkg_path = Path(site_packages_path) / pkg_name
            if pkg_path.exists() and pkg_path.is_dir():
                smart_whitelist_add(pkg_path)
                for metadata_dir in Path(site_packages_path).glob(f'{pkg_name}-*.*-info'):
                    smart_whitelist_add(metadata_dir)
            else:
                print(f"    [!] Warning: collect_all package '{pkg_name}' not found. Did you forget to list it in DEPENDENCIES?")
    return whitelist

# (v1.1.0) add: i have refactored this to tighten extension preservation, pruning large dirs etc,
def wipe_runtime_bloat_strict(runtime_path, whitelist, site_packages_path, stdlib_path, extra_extensions=None):
    print(' -> Executing whitelisting (Strict wipe with Asset & Metadata Rescue)...')
    runtime_path = Path(runtime_path)
    bytes_saved = 0
    
    # 1. tightened extns.: removed default bloat triggers like .tcl and .tk
    preserve_extensions = {'.so', '.pyd', '.dylib', '.dll', '.pem', '.crt', '.json', '.yaml', '.yml'}
    
    if extra_extensions:
        preserve_extensions.update((ext.lower() if ext.startswith('.') else f'.{ext.lower()}' for ext in extra_extensions))
        
    target_zones = [Path(site_packages_path).resolve(), Path(stdlib_path).resolve()]
    active_package_dirs = {p.parent.resolve() for p in whitelist}
    active_module_names = set()
    
    for p in whitelist:
        if p.parent in target_zones:
            active_module_names.add(p.stem.lower().replace('_', ''))
        else:
            for parent in p.parents:
                if parent.parent in target_zones:
                    active_module_names.add(parent.name.lower().replace('_', ''))
                    break
                    
    for zone in target_zones:
        if not zone.exists():
            continue
        for file_path in list(zone.rglob('*')):
            if not file_path.is_file() and (not file_path.is_symlink()):
                continue
            resolved_file = file_path.resolve()
            if resolved_file in whitelist:
                continue
            if resolved_file.suffix.lower() in preserve_extensions:
                is_active_asset = False
                parent = resolved_file.parent
                while parent and parent != zone and (parent != parent.parent):
                    if parent in active_package_dirs:
                        is_active_asset = True
                        break
                    parent = parent.parent
                if is_active_asset:
                    whitelist.add(resolved_file)
                    continue
            is_metadata_file = False
            for parent in resolved_file.parents:
                if parent == zone:
                    break
                if parent.name.endswith('.dist-info') or parent.name.endswith('.egg-info'):
                    critical_meta_files = {'METADATA', 'entry_points.txt', 'top_level.txt', 'PKG-INFO'}
                    if resolved_file.name in critical_meta_files:
                        meta_base_name = parent.name.split('-')[0].lower().replace('_', '')
                        if meta_base_name in active_module_names:
                            is_metadata_file = True
                            whitelist.add(resolved_file)
                    break
            if is_metadata_file:
                continue
            try:
                bytes_saved += file_path.stat().st_size
                file_path.unlink()
            except OSError:
                pass
                
    # 2. pruning large dirs: target known bloat folders and leftover caches
    bloat_dir_names = {'test', 'tests', 'testing', 'idlelib', 'tkinter', 'tcl', 'tk8.6', 'pydoc_data', '__pycache__'}
        
    for dir_path in sorted(runtime_path.rglob('*'), key=lambda x: len(x.parts), reverse=True):
        if dir_path.is_dir():
            if dir_path.name.lower() in bloat_dir_names:
                # makesure no explicitly whitelisted file lives inside this directory
                if not any(w_path.is_relative_to(dir_path) for w_path in whitelist):
                    try:
                        shutil.rmtree(dir_path, ignore_errors=True)
                    except OSError:
                        pass
            elif not any(dir_path.iterdir()):
                try:
                    dir_path.rmdir()
                except OSError:
                    pass
                    
    print(f'    [+] Wipe complete. Reclaimed ~{bytes_saved / (1024 * 1024):.1f} MB (plus massive directory pruning savings).')

def load_configuration(config_filename='projconf.toml'):
    config_path = Path(config_filename)
    if not config_path.exists():
        print(f"[-] Error: Configuration file '{config_filename}' not found in the current working directory.")
        sys.exit(1)
    print(f'Loading environment manifest: {config_filename}')
    with open(config_path, 'rb') as f:
        try:
            toml_data = tomllib.load(f)
            return {
                'PROJECT_NAME': toml_data['project']['name'], 
                'VERSION': toml_data['project']['version'], 
                'PYTHON_VERSION': toml_data['project'].get('python_version', '3.11'), 
                'SOURCE_FILES': toml_data['project'].get('source_files', []), 
                'ENTRY_POINT': toml_data['project']['entry_point'], 
                'DEPENDENCIES': toml_data['project'].get('dependencies', []), 
                'HIDDEN_IMPORTS': toml_data['project'].get('hidden_imports', []), 
                'COLLECT_ALL': toml_data['project'].get('collect_all', []), 
                'LAUNCH_COMMAND': toml_data['project']['launch_command'], 
                'PRESERVE_EXTENSIONS': toml_data['project'].get('preserve_extensions', []), 
                'UPX_EXCLUDE': toml_data['project'].get('upx_exclude', []), # <-- ADDED THIS LINE
                'RUNTIMES': toml_data['runtimes'], 
                'WINDOWS_CONFIG': toml_data.get('windows', {}), 
                'MACOS_CONFIG': toml_data.get('macos', {}), 
                'LINUX_CONFIG': toml_data.get('linux', {})
            }
        except KeyError as e:
            print(f'[-] Configuration Error: Missing required TOML key definition {e}')
            sys.exit(1)
        except Exception as e:
            print(f'[-] Syntax Error parsing TOML file: {e}')
            sys.exit(1)

def find_site_packages(base_path):
    for root, dirs, _ in os.walk(base_path):
        if os.path.basename(root) == 'site-packages':
            return root
    return None

def download_runtime(url, dest_path):
    CACHE_DIR = Path.home() / '.core_bundler_cache' / 'runtimes'
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    filename = url.split('/')[-1]
    cached_file = CACHE_DIR / filename
    if cached_file.exists():
        print(f'    [+] Cache hit! Using local runtime archive: {filename}')
        shutil.copy2(cached_file, dest_path)
        return
    print(f'    [~] Downloading runtime to cache from {url}...')
    try:
        urllib.request.urlretrieve(url, cached_file)
        print(f'    [+] Download complete. Cached permanently at {CACHE_DIR}')
        shutil.copy2(cached_file, dest_path)
    except Exception as e:
        print(f'    [!] Failed to download runtime: {e}')
        if cached_file.exists():
            cached_file.unlink()
        sys.exit(1)

def extract_runtime(archive_path, extract_to):
    print(f' -> Unpacking engine files securely...')
    extract_to_path = Path(extract_to).resolve()
    with tarfile.open(archive_path, 'r:gz') as tar:
        if hasattr(tarfile, 'data_filter'):
            try:
                tar.extractall(path=extract_to_path, filter='data')
                return
            except (TypeError, ValueError):
                pass
        safe_members = []
        for member in tar.getmembers():
            target_path = Path(os.path.abspath(os.path.join(extract_to_path, member.name)))
            if extract_to_path not in target_path.parents and target_path != extract_to_path:
                print(f"[-] Malicious Archive Detected: Refusing to extract '{member.name}' (outside boundary).")
                sys.exit(1)
            safe_members.append(member)
        tar.extractall(path=extract_to_path, members=safe_members)

def download_and_extract_deps(deps, target_site_packages, temp_dir, platform_key, python_version):
    if not deps:
        return
    platform_map = {'windows-x64': {'platform': 'win_amd64', 'abi': f"cp{python_version.replace('.', '')}"}, 'windows': {'platform': 'win_amd64', 'abi': f"cp{python_version.replace('.', '')}"}, 'linux-x64': {'platform': 'manylinux2014_x86_64', 'abi': f"cp{python_version.replace('.', '')}"}, 'linux': {'platform': 'manylinux2014_x86_64', 'abi': f"cp{python_version.replace('.', '')}"}, 'macos-x64': {'platform': 'macosx_10_9_x86_64', 'abi': f"cp{python_version.replace('.', '')}"}, 'macos-arm64': {'platform': 'macosx_11_0_arm64', 'abi': f"cp{python_version.replace('.', '')}"}}
    lookup_key = platform_key.lower()
    plat_info = platform_map.get(lookup_key)
    print(f" -> Syncing dependencies for {platform_key} (Targeting Python {python_version}): {', '.join(deps)}...")
    uv_bin = shutil.which('uv')
    if uv_bin:
        print("    [*] Acceleration Engaged: Routing dependency resolution through 'uv'...")
        cmd = [uv_bin, 'pip', 'install', '--target', str(target_site_packages), '--only-binary=:all:']
    else:
        cmd = [sys.executable, '-m', 'pip', 'install', '--target', str(target_site_packages), '--only-binary=:all:', '--no-warn-script-location']
    if plat_info:
        cmd.extend(['--platform', plat_info['platform'], '--abi', plat_info['abi'], '--python-version', python_version, '--implementation', 'cp'])
    cmd.extend(deps)
    try:
        subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
    except subprocess.CalledProcessError:
        installer = 'uv' if uv_bin else 'pip'
        print(f"    [!] Error: {installer} failed to resolve or install target variants for: {', '.join(deps)}")
        raise RuntimeError(f'Dependency resolution failed via {installer}.')

def generate_info_plist(dest_path, project_name, version):
    plist_content = f'<?xml version="1.0" encoding="UTF-8"?>\n<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n<plist version="1.0">\n<dict>\n    <key>CFBundlePackageType</key>\n    <string>APPL</string>\n    <key>CFBundleInfoDictionaryVersion</key>\n    <string>6.0</string>\n    <key>CFBundleName</key>\n    <string>{project_name}</string>\n    <key>CFBundleExecutable</key>\n    <string>{project_name}</string>\n    <key>CFBundleIdentifier</key>\n    <string>com.standalone.{project_name.lower()}</string>\n    <key>CFBundleShortVersionString</key>\n    <string>{version}</string>\n    <key>CFBundleVersion</key>\n    <string>{version}</string>\n    <key>LSMinimumSystemVersion</key>\n    <string>10.13</string>\n</dict>\n</plist>\n'
    dest_path.write_text(plist_content)

def find_windows_compiler():
    for compiler in ['gcc', 'x86_64-w64-mingw32-gcc', 'cl']:
        if shutil.which(compiler):
            return compiler
    return None

def find_signtool():
    if shutil.which('signtool'):
        return 'signtool'
    possible_roots = [Path('C:/Program Files (x86)/Windows Kits/10/bin'), Path('C:/Program Files/Windows Kits/10/bin'), Path('C:/Program Files (x86)/Microsoft SDKs/ClickOnce/SignTool')]
    for root in possible_roots:
        if not root.exists():
            continue
        if root.name == 'SignTool':
            exe = root / 'signtool.exe'
            if exe.exists():
                return str(exe)
        else:
            for sub in root.iterdir():
                if sub.is_dir():
                    for arch in ['x64', 'x86']:
                        exe = sub / arch / 'signtool.exe'
                        if exe.exists():
                            return str(exe)
    return None

def sign_windows_executable(target_file, win_config):
    cert_path = win_config.get('pfx_certificate')
    cert_password = win_config.get('pfx_password')
    if not cert_path or not cert_password:
        return
    signtool_bin = find_signtool()
    if not signtool_bin:
        print('    [!] Warning: signtool.exe missing from common paths. Skipping signature routine.')
        return
    print(f' -> Code signing target binary: {target_file.name}...')
    cmd = [signtool_bin, 'sign', '/f', str(cert_path), '/p', cert_password, '/tr', 'http://timestamp.digicert.com', '/td', 'sha256', '/fd', 'sha256', str(target_file)]
    try:
        subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        print('[+] Code signature successfully embedded.')
    except subprocess.CalledProcessError:
        print('    [!] Error: SignTool invocation failed. Verify certificate properties.')

# (v1.1.0) change: the new method for using the new nim implementation of the stub file
# this method also uses a new technique for this, using EOF (End-of-File) payload appending
def generate_windows_launcher(platform_dir, project_name, entry_point, win_config):
    hide_console = win_config.get('hide_console', False)
    launcher_exe = platform_dir / f'{project_name}.exe'
    
    entry_point_normalized = entry_point.replace('\\', '/')
    entry_point_fixed = entry_point_normalized.replace('/', '\\\\')
    python_exe = 'pythonw.exe' if hide_console else 'python.exe'
    
    stub_exe_path = Path(__file__).parent / "launcher_stub.exe"
    
    if stub_exe_path.exists():
        print(f" -> Injecting payload into pre-compiled Nim stub launcher...")
        try:
            # 1. copy the generic, pre-compiled Nim executable
            shutil.copy2(stub_exe_path, launcher_exe)
            
            # 2. format the configuration payload
            hide_flag = '1' if hide_console else '0'
            payload = f"[XPPB_CONFIG]{python_exe}|{entry_point_fixed}|{hide_flag}"
            
            # 3. append the payload directly to the executable's raw bytes
            with open(launcher_exe, 'ab') as f:
                f.write(payload.encode('utf-8'))
                
            return launcher_exe
        except Exception as e:
            print(f"    [!] Error performing binary injection: {e}. Reverting to fallback scripts...")
            if launcher_exe.exists():
                launcher_exe.unlink()
    else:
        print("    [!] Warning: Pre-compiled 'launcher_stub.exe' missing. Reverting to structural fallback scripts...")

    # fallback if the stub is missing
    print(' -> Constructing basic script wrapper (No native stub available)...')
    launcher_bat = platform_dir / f'{project_name}.bat'
    
    if hide_console:
        bat_content = f'@echo off\nsetlocal\npowershell -WindowStyle Hidden -Command "& \'%~dp0python\\{python_exe}\' \'%~dp0{entry_point}\' $args"\nendlocal\n'
    else:
        bat_content = f'@echo off\nsetlocal\n"%~dp0python\\{python_exe}" "%~dp0{entry_point}" %*\nendlocal\n'
        
    launcher_bat.write_text(bat_content)
    return launcher_bat

def ensure_rcodesign():
    system_path = shutil.which('rcodesign')
    if system_path:
        return system_path
    tools_dir = Path('build/tools')
    tools_dir.mkdir(parents=True, exist_ok=True)
    host_sys = sys.platform
    version = '0.29.0'
    base_url = f'https://github.com/indygreg/apple-platform-rs/releases/download/apple-codesign%2F{version}/'
    if host_sys == 'win32':
        asset_name = f'apple-codesign-{version}-x86_64-pc-windows-msvc.zip'
        binary_name = 'rcodesign.exe'
    elif host_sys == 'darwin':
        asset_name = f'apple-codesign-{version}-macos-universal.tar.gz'
        binary_name = 'rcodesign'
    else:
        asset_name = f'apple-codesign-{version}-x86_64-unknown-linux-musl.tar.gz'
        binary_name = 'rcodesign'
    local_binary = tools_dir / binary_name
    if local_binary.exists():
        return str(local_binary)
    print(f' -> Apple tools missing. Auto-fetching cross-platform rcodesign v{version} for host pipeline...')
    archive_dest = tools_dir / asset_name
    try:
        req = urllib.request.Request(base_url + asset_name, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req) as response, open(archive_dest, 'wb') as out_file:
            shutil.copyfileobj(response, out_file)
        if asset_name.endswith('.zip'):
            with zipfile.ZipFile(archive_dest, 'r') as zip_ref:
                zip_ref.extractall(tools_dir)
        else:
            with tarfile.open(archive_dest, 'r:gz') as tar:
                if hasattr(tarfile, 'data_filter'):
                    tar.extractall(path=tools_dir, filter='data')
                else:
                    safe_members = []
                    for member in tar.getmembers():
                        target_path = Path(os.path.abspath(os.path.join(tools_dir, member.name)))
                        if tools_dir.resolve() in target_path.parents or target_path == tools_dir.resolve():
                            safe_members.append(member)
                    tar.extractall(path=tools_dir, members=safe_members)
        for root, _, files in os.walk(tools_dir):
            if binary_name in files:
                target = Path(root) / binary_name
                if target != local_binary:
                    shutil.move(str(target), str(local_binary))
                break
        if local_binary.exists():
            os.chmod(local_binary, 493)
            if archive_dest.exists():
                archive_dest.unlink()
            return str(local_binary)
    except Exception as e:
        print(f'    [!] Failed to download cross-platform signing dependency: {e}')
        sys.exit(1)

def sign_macos_bundle_cross_platform(app_path, mac_config, rcodesign_bin):
    p12_cert = mac_config.get('p12_certificate')
    p12_pass = mac_config.get('p12_password')
    if not p12_cert:
        print('    [-] Skipping macOS signing engine: No .p12 certificate file defined.')
        return
    print(f' -> Cryptographically signing macOS application framework: {app_path.name}...')
    cmd = [rcodesign_bin, 'sign', '--p12-file', str(p12_cert), '--p12-password', str(p12_pass), '--code-signature-flags', 'runtime', str(app_path)]
    try:
        subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
        print('    [+] Apple Developer signature successfully validated and compiled.')
    except subprocess.CalledProcessError as e:
        print(f'    [!] Error: rcodesign execution error:\n{e.stderr}')
        sys.exit(1)

def notarize_macos_bundle_cross_platform(app_path, mac_config, rcodesign_bin):
    api_key = mac_config.get('api_key_path')
    api_issuer = mac_config.get('api_issuer_id')
    api_key_id = mac_config.get('api_key_id')
    if not all([api_key, api_issuer, api_key_id]):
        print('    [-] Skipping Apple Notarization: ASC API Keys are incomplete.')
        return
    print(f' -> Submitting bundle to Apple Notary API servers (Cross-Platform Connection)...')
    cmd = [rcodesign_bin, 'notary-submit', '--api-key-path', str(api_key), '--api-issuer', str(api_issuer), '--api-key', str(api_key_id), '--staple', str(app_path)]
    try:
        subprocess.run(cmd, check=True)
        print('    [+] Notarization ticket acquired and stapled into app bundle.')
    except subprocess.CalledProcessError:
        print('    [!] Error: Apple Notary Service API transaction failed.')
        sys.exit(1)

def bundle_platform(platform_name, url, build_dir, dist_dir, base_temp_dir, CONFIG):
    print(f'\n[Target Platform: {platform_name}] Process started...')
    platform_dir = build_dir / platform_name
    platform_dir.mkdir(parents=True, exist_ok=True)
    archive_path = build_dir / f'engine_{platform_name}.tar.gz'
    temp_dir = base_temp_dir / platform_name
    temp_dir.mkdir(parents=True, exist_ok=True)
    is_macos = 'macos' in platform_name.lower()
    if is_macos:
        app_bundle = platform_dir / f"{CONFIG['PROJECT_NAME']}.app"
        contents_dir = app_bundle / 'Contents'
        macos_dir = contents_dir / 'MacOS'
        resources_dir = contents_dir / 'Resources'
        macos_dir.mkdir(parents=True, exist_ok=True)
        resources_dir.mkdir(parents=True, exist_ok=True)
        runtime_extract_target = resources_dir
        source_dest_parent = resources_dir
    else:
        runtime_extract_target = platform_dir
        source_dest_parent = platform_dir
    download_runtime(url, archive_path)
    extract_runtime(archive_path, runtime_extract_target)
    site_packages = find_site_packages(runtime_extract_target)
    if not site_packages:
        print(f'    [!] Error: Failed to pinpoint target environment layout for {platform_name}!')
        return
    download_and_extract_deps(CONFIG['DEPENDENCIES'], site_packages, temp_dir, platform_name, python_version=CONFIG['PYTHON_VERSION'])
    stdlib_path = Path(site_packages).parent
    active_hidden = list(CONFIG.get('HIDDEN_IMPORTS', []))
    active_collect = list(CONFIG.get('COLLECT_ALL', []))
    plat_lower = platform_name.lower()
    if 'windows' in plat_lower:
        active_hidden.extend(CONFIG['WINDOWS_CONFIG'].get('hidden_imports', []))
        active_collect.extend(CONFIG['WINDOWS_CONFIG'].get('collect_all', []))
    elif 'macos' in plat_lower:
        active_hidden.extend(CONFIG['MACOS_CONFIG'].get('hidden_imports', []))
        active_collect.extend(CONFIG['MACOS_CONFIG'].get('collect_all', []))
    elif 'linux' in plat_lower:
        active_hidden.extend(CONFIG['LINUX_CONFIG'].get('hidden_imports', []))
        active_collect.extend(CONFIG['LINUX_CONFIG'].get('collect_all', []))
    whitelist = generate_runtime_whitelist(entry_point_path=Path(CONFIG['ENTRY_POINT']), site_packages_path=Path(site_packages), stdlib_path=stdlib_path, platform_name=platform_name, hidden_imports=active_hidden, collect_all=active_collect)
    wipe_runtime_bloat_strict(runtime_path=runtime_extract_target, whitelist=whitelist, site_packages_path=site_packages, stdlib_path=stdlib_path, extra_extensions=CONFIG.get('PRESERVE_EXTENSIONS', []))
    optimize_python_sources(runtime_extract_target)
    zip_stdlib(stdlib_path=stdlib_path, site_packages_path=site_packages, python_version=CONFIG['PYTHON_VERSION'])
    strip_binaries(platform_dir, platform_name)
    upx_compress(platform_dir, platform_name)
    print(f' -> [{platform_name}] Packaging custom source layers...')
    for src in CONFIG['SOURCE_FILES']:
        src_path = Path(src)
        if not src_path.exists():
            print(f"    [!] Missing source path ignored: '{src}'")
            continue
        dest_path = source_dest_parent / src_path.name
        if src_path.is_dir():
            shutil.copytree(src_path, dest_path)
        else:
            shutil.copy2(src_path, dest_path)
    print(f' -> [{platform_name}] Constructing isolated binary wrappers...')
    if 'windows' in platform_name:
        launcher_path = generate_windows_launcher(platform_dir, CONFIG['PROJECT_NAME'], CONFIG['ENTRY_POINT'], CONFIG['WINDOWS_CONFIG'])
        sign_windows_executable(launcher_path, CONFIG['WINDOWS_CONFIG'])
    elif is_macos:
        launcher_path = macos_dir / CONFIG['PROJECT_NAME']
        launch_cmd = CONFIG['LAUNCH_COMMAND'].format(ENTRY_POINT=f'"$SCRIPT_DIR/../Resources/{CONFIG[\'ENTRY_POINT\']}"')
        sh_content = f'#!/usr/bin/env bash\nSCRIPT_DIR="$(cd "$(dirname "${{BASH_SOURCE[0]}}")" && pwd)"\n"$SCRIPT_DIR/../Resources/python/bin/python3" {launch_cmd} "$@"\n'
        launcher_path.write_text(sh_content)
        generate_info_plist(contents_dir / 'Info.plist', CONFIG['PROJECT_NAME'], CONFIG['VERSION'])
        os.chmod(launcher_path, 493)
        python_bin = resources_dir / 'python' / 'bin' / 'python3'
        if python_bin.exists():
            os.chmod(python_bin, 493)
        rcodesign_bin = ensure_rcodesign()
        sign_macos_bundle_cross_platform(app_bundle, CONFIG['MACOS_CONFIG'], rcodesign_bin)
        notarize_macos_bundle_cross_platform(app_bundle, CONFIG['MACOS_CONFIG'], rcodesign_bin)
    else:
        launcher_path = platform_dir / CONFIG['PROJECT_NAME']
        launch_cmd = CONFIG['LAUNCH_COMMAND'].format(ENTRY_POINT=f'"$SCRIPT_DIR/{CONFIG[\'ENTRY_POINT\']}"')
        sh_content = f'#!/usr/bin/env bash\nSCRIPT_DIR="$(cd "$(dirname "${{BASH_SOURCE[0]}}")" && pwd)"\n"$SCRIPT_DIR/python/bin/python3" {launch_cmd} "$@"\n'
        launcher_path.write_text(sh_content)
        os.chmod(launcher_path, 493)
        python_bin = platform_dir / 'python' / 'bin' / 'python3'
        if python_bin.exists():
            os.chmod(python_bin, 493)
    # (v1.1.0) add: i have changed the final archive compression to use lzma/xz instead of gz and deflate
    print(f' -> [{platform_name}] Sealing compressed release asset (tar.xz)...')
    dist_file = dist_dir / f"{CONFIG['PROJECT_NAME']}-{CONFIG['VERSION']}-{platform_name}.tar.xz"
        
    # use preset=9 for maximum lzma compression
    with tarfile.open(dist_file, 'w:xz', preset=9) as tar:
        # arcname wraps the contents in a cleanly named root folder when extracted
        tar.add(platform_dir, arcname=CONFIG['PROJECT_NAME'])
            
    print(f'    [+] Archive ready: {dist_file}')
    if archive_path.exists():
        archive_path.unlink()

def main():
    CONFIG = load_configuration()
    build_dir = Path('build')
    dist_dir = Path('dist')
    base_temp_dir = Path('build/temp_deps')
    
    if build_dir.exists():
        shutil.rmtree(build_dir)
    if dist_dir.exists():
        shutil.rmtree(dist_dir)
        
    build_dir.mkdir(parents=True, exist_ok=True)
    dist_dir.mkdir(parents=True, exist_ok=True)
    base_temp_dir.mkdir(parents=True, exist_ok=True)
    
    print(f'\n=== xppb v1.1.0')
    print(f"\n=== Bundling Sequence Started: {CONFIG['PROJECT_NAME']} v{CONFIG['VERSION']} ===")

    # (v1.0.1)fix: pre-fetch all runtime archives sequentially to populate the cache safely
    print(" -> Pre-fetching runtime archives to cache...")
    for platform_name, url in CONFIG['RUNTIMES'].items():
        archive_path = build_dir / f'engine_{platform_name}.tar.gz'
        download_runtime(url, archive_path)

    # (v1.0.1)fix: also pre-fetch cross-platform signing tools if any macos target exists
    if any('macos' in p.lower() for p in CONFIG['RUNTIMES'].keys()):
        ensure_rcodesign()

    with concurrent.futures.ProcessPoolExecutor() as executor:
        futures = []
        for platform_name, url in CONFIG['RUNTIMES'].items():
            futures.append(executor.submit(bundle_platform, platform_name, url, build_dir, dist_dir, base_temp_dir, CONFIG))
        for future in concurrent.futures.as_completed(futures):
            try:
                future.result()
            except Exception as e:
                print(f'\n[!] A thread encountered a fatal error during compilation: {e}')
                
    if base_temp_dir.exists():
        shutil.rmtree(base_temp_dir)
        
    print('\n========================================================================')
    print(f'Success! Standalone bundles have been compiled inside: {dist_dir.resolve()}')
    print('========================================================================')
if __name__ == '__main__':
    main()
