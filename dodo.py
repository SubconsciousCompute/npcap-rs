#!/usr/bin/env python3

import os
import tempfile
import shutil
import subprocess
import platform
import zipfile
from pathlib import Path

# Set CARGO_HOME and RUSTUP_HOME to make sure that rustup and cargo are
# installed in proper place.
CARGO_HOME = Path.home() / ".cargo"
os.environ["CARGO_HOME"] = str(CARGO_HOME)
os.environ["RUSTUP_HOME"] = str(CARGO_HOME)
os.environ["PATH"] = str(CARGO_HOME / "bin") + os.pathsep + os.environ["PATH"]

CARGO = shutil.which("cargo")

IS_WINDOWS = any(platform.win32_ver())


def which_rustup():
    return shutil.which("rustup")


def which_cargo():
    return shutil.which("cargo")


def install_npcap_windows():
    import urllib.request

    print('Installing npcap')
    setupfile = Path(tempfile.gettempdir()) / "npcap-1.70.exe"

    # If setupfile already exists then we assume that npcap is already
    # installed. It may not be true but true-enough for CICD pipelines.
    if setupfile.exists():
        print(f'>> {setupfile} already exists. I assume that you have installed it.')
        return True

    # else download and install.
    urllib.request.urlretrieve("https://npcap.com/dist/npcap-1.70.exe", setupfile)
    return dict(action=f"Invoke-Command -ScriptBlock {{ {setupfile} /silent }}")

def install_npcap_sdk_windows():
    import urllib.request

    print('Installing npcap sdk')
    setupfile = Path(tempfile.gettempdir()) / "npcap-sdk-1.13.zip"

    # If setupfile already exists then we assume that npcap is already
    # installed. It may not be true but true-enough for CICD pipelines.
    if setupfile.exists():
        print(f'>> {setupfile} already exists. I assume that you have installed it.')
        return True

    extract_at = Path(tempfile.gettempdir()) / "npcapped"

    # else download and install.
    urllib.request.urlretrieve("https://npcap.com/dist/npcap-sdk-1.13.zip", setupfile)

    if not os.path.exists(extract_at):
        os.mkdir(extract_at)

    with zipfile.ZipFile(setupfile, "r") as ref:
        ref.extractall(extract_at)

    return dict(action="")

def task_bootstrap():
    """Bootstrap Windows"""

    if IS_WINDOWS:
        actions = ["choco.exe install -y rustup.install"]
        actions += [install_npcap_windows(), install_npcap_sdk_windows()]
    else:
        actions = ["curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh"]

    return dict(
        actions=actions,
        uptodate=[which_rustup],
    )


def task_setup_rust():
    return dict(actions=["rustup.exe -v default stable"], task_dep=["bootstrap"])


def task_build():
    """Bootstrap Windows"""
    global CARGO
    CARGO = which_cargo()
    assert CARGO is not None

    # setup the dir where the lib is
    setupfile = Path(Path(tempfile.gettempdir()) / "npcapped\\Lib\\x64").__str__()
    os.environ["NPCAP_RS_LIB_DIR"] = setupfile

    return dict(
            actions=[f"{CARGO} check", f"{CARGO} build --all-targets --features http-parse"],
        task_dep=["setup_rust"],
    )


def task_test():
    global CARGO
    return dict(actions=[f"{CARGO} test --features http-parse"], task_dep=["build"])


def task_doc():
    global CARGO
    return dict(actions=[f"{CARGO} doc --no-deps"])


if __name__ == "__main__":
    import doit

    doit.run(globals())
