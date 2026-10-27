import os.path
import re
import shutil
import subprocess

from app.cmd import (
    create_dir_if_not_exists,
    delete_file_if_exists,
    delete_dir_if_exists,
)

LIBXRAY_MOD_NAME = "github.com/xtls/libxray"
# >= 1.26.3: older 1.26.x probe futex_time64 on 32-bit Linux and rely on -ENOSYS,
# but the seccomp filter on Android 8-10 (API 26-29) kills the process instead,
# so :vpn died with SIGSYS on every armeabi-v7a/x86 device of that age (#152).
LIBXRAY_GO_VERSION = "1.26.10"
# Build against our Xray-core fork, taken from the TheLoopKit submodule
# (submodules/Xray-core) — the same checkout the Windows kit builds from
# (windows_build.bat), so every platform ships the core the submodule pointer names.
# The fork keeps the module path github.com/xtls/xray-core, so a replace directive
# pointing at the checkout resolves. Until 2026-10-27 this was a hash pin on GitHub
# (last 91e0adc9) that lagged behind the submodule; bump the core by moving the
# submodule pointer now, nothing here.
#
# chromeQUICPostQuantumKeyShare is TRUE in the core, i.e. the upstream default —
# the QUIC ClientHello carries X25519MLKEM768 and the Initial flight is two
# datagrams, byte-faithful to shipping Chrome. An earlier revision of this comment
# said the opposite, that true was fatal on our path; that was a misdiagnosis and is
# corrected here, because the symptom is easy to misread the same way twice.
#
# The symptom was real: from Vladivostok (AS12389) against the production node the
# two-datagram flight never completed while the single-datagram one connected in
# ~0.2s. But the variable was the SNI, not this flag. Same binary, same node, same
# day, two-datagram flight throughout, only serverName differing — amazon.co.jp
# 10/10, s3/ec2.ap-northeast-1.amazonaws.com 4/4, www.gosuslugi.ru 11/11,
# www.nintendo.co.jp and yandex.ru 3/3, against amazon.com 0/15 and
# www.google.com / www.microsoft.com / www.apple.com / www.cloudflare.com /
# www.tiktok.com / vk.com 0/3 each. Real Chrome 150 forced onto QUIC sends the same
# two-datagram ML-KEM Initial to that node and passes, and replaying our own blocked
# pair byte-for-byte from a foreign host arrives 2/2 — so the drop sits on the
# Russian path and removes the packet that completes the ClientHello. Upstream's
# 60/60 was never in conflict with ours; it used a different destination and SNI.
#
# ⚠️ What actually has to be watched is the SNI, not this flag: production
# hwc_server_name is amazon.co.jp, and it must not be set to a famous domain — the
# censor tracks the real addresses of exactly those, so presenting one on an address
# that is not theirs is what trips the rule.
#
# The core also carries datagram fragmentation on both carriers and the udp_demux fan-out fix
# (one inner UDP socket -> up to maxUDPBranches destinations). 0c2dabe1 splits that
# fan-out cap by platform (iOS 64 / other 200). a2a31cb6 is the ACTUAL iOS-memory
# fix: it clamps the QUIC receive windows on iOS (4 MiB conn / 2 MiB stream vs
# Chrome's 15/6) in applyChromeQUICConfig. The window is the memory we must buffer
# (live, GOMEMLIMIT can't reclaim it); Chrome's 15 MiB conn window alone blew the
# NE's ~50MB jetsam budget on a single download (~19->44 MB, then killed). Off iOS
# the clamp is a MaxUint64 no-op.
#
# Upstream's Go 1.27 and ChromeParrot are still NOT taken (see the toolchain note in
# pub-vpn/docker/v2ray/Dockerfile), so the QUIC wire fingerprint of existing profiles
# does not move with the core.
XRAY_CORE_MOD = "github.com/xtls/xray-core"
# Relative to the libXray module (init_go_env runs there). XRAY_CORE_LOCAL points the
# build at another checkout, e.g. a worktree under test; HWC_XRAY_LOCAL is its old name.
XRAY_CORE_LOCAL = (
    os.environ.get("XRAY_CORE_LOCAL", "").strip()
    or os.environ.get("HWC_XRAY_LOCAL", "").strip()
    or "../Xray-core"
)
# Blackout fallback carrier, co-bound into THIS framework (via wbypass_wrapper.go)
# so xray + wbypass share ONE Go runtime — two gomobile runtimes in the NE crash
# in runtime.load_g. init_go_env regenerates go.mod from scratch, so these local
# replaces must be injected here, not left in a committed go.mod (it gets wiped).
# whitelist-bypass/relay is pulled transitively by wbypass's vksfu carrier.
WBYPASS_MOD = "github.com/vinaes/wbypass"
WBYPASS_LOCAL = "../wbypass"
WLB_RELAY_MOD = "whitelist-bypass/relay"
WLB_RELAY_LOCAL = "../whitelist-bypass/relay"

APERNET_QUICGO_MOD = "github.com/apernet/quic-go"
# REALITY is patched the same way (third_party/reality, its own go.mod); without
# this replace the stock upstream REALITY gets linked silently.
REALITY_MOD = "github.com/xtls/reality"


def _xray_core_mod_edits() -> list[str]:
    # The core vendors a Chrome-shaped quic-go (the h3 carrier's QUIC fingerprint) and a
    # patched REALITY under third_party/, each with its own go.mod. Go ignores replace
    # directives inside dependencies, so they must be mirrored in this module; without
    # them stock apernet/quic-go and upstream REALITY get linked silently.
    return [
        f"-replace={XRAY_CORE_MOD}={XRAY_CORE_LOCAL}",
        f"-require={XRAY_CORE_MOD}@v0.0.0",
        f"-replace={APERNET_QUICGO_MOD}={XRAY_CORE_LOCAL}/third_party/quic-go",
        f"-replace={REALITY_MOD}={XRAY_CORE_LOCAL}/third_party/reality",
        f"-replace={WBYPASS_MOD}={WBYPASS_LOCAL}",
        f"-require={WBYPASS_MOD}@v0.0.0",
        f"-replace={WLB_RELAY_MOD}={WLB_RELAY_LOCAL}",
    ]


def _report_xray_core():
    # A submodule that was never checked out is an empty directory; fail here rather
    # than in go mod tidy with a confusing error.
    if not os.path.isfile(os.path.join(XRAY_CORE_LOCAL, "go.mod")):
        raise Exception(
            f"Xray-core not found at {XRAY_CORE_LOCAL}: "
            "run git submodule update --init submodules/Xray-core"
        )
    rev = subprocess.run(
        ["git", "-C", XRAY_CORE_LOCAL, "describe", "--always", "--dirty"],
        capture_output=True,
        text=True,
    ).stdout.strip()
    print(f"xray-core: {XRAY_CORE_LOCAL} @ {rev or 'unknown'}")


class Builder(object):
    def __init__(self, build_dir: str):
        self.build_dir = build_dir
        self.lib_dir = os.path.join(self.build_dir, "..")
        self.bin_file = "xray"

    def clean_lib_files(self, files: list[str]):
        for file in files:
            file_path = os.path.join(self.lib_dir, file)
            delete_file_if_exists(file_path)

    def clean_lib_dirs(self, dirs: list[str]):
        for dir_name in dirs:
            dir_path = os.path.join(self.lib_dir, dir_name)
            delete_dir_if_exists(dir_path)

    def init_go_env(self):
        os.chdir(self.lib_dir)
        self.clean_lib_files(["go.mod", "go.sum"])
        ret = subprocess.run(["go", "mod", "init", LIBXRAY_MOD_NAME])
        if ret.returncode != 0:
            raise Exception("go mod init failed")
        ret = subprocess.run(["go", "mod", "edit", f"-go={LIBXRAY_GO_VERSION}"])
        if ret.returncode != 0:
            raise Exception("go mod edit go version failed")
        # Redirect xray-core to the local fork checkout (the submodule by default).
        _report_xray_core()
        ret = subprocess.run(["go", "mod", "edit"] + _xray_core_mod_edits())
        if ret.returncode != 0:
            raise Exception("go mod edit replace xray-core fork failed")

        ret = subprocess.run(
            [
                "go",
                "mod",
                "tidy",
            ]
        )
        if ret.returncode != 0:
            raise Exception("go mod tidy failed")

    def download_geo(self):
        os.chdir(self.lib_dir)
        main_path = os.path.join("download_geo", "main.go")
        ret = subprocess.run(["go", "run", main_path])
        if ret.returncode != 0:
            raise Exception("download_geo failed")

    def prepare_gomobile(self):
        ret = subprocess.run(
            ["go", "install", "golang.org/x/mobile/cmd/gomobile@latest"]
        )
        if ret.returncode != 0:
            raise Exception("go install gomobile failed")
        ret = subprocess.run(["gomobile", "init"])
        if ret.returncode != 0:
            raise Exception("gomobile init failed")
        ret = subprocess.run(["go", "get", "golang.org/x/mobile/cmd/gomobile"])
        if ret.returncode != 0:
            raise Exception("gomobile update failed")
        ret = subprocess.run(["go", "get", "google.golang.org/genproto"])
        if ret.returncode != 0:
            raise Exception("gomobile install genproto failed")

    def prepare_static_lib(self):
        self.copy_template_file()
        self.fix_package_name()

    def copy_template_file(self):
        src_file = os.path.join(self.build_dir, "template", "main.gotemplate")
        dst_file = os.path.join(self.lib_dir, "main.go")
        shutil.copy(src_file, dst_file)

    def fix_package_name(self):
        files = os.listdir(self.lib_dir)
        for file in files:
            if file.endswith(".go"):
                self.replace_package_name(file)

    def replace_package_name(self, file_name: str):
        file_path = os.path.join(self.lib_dir, file_name)
        new_lines = []
        with open(file_path, "r") as f:
            lines = f.readlines()
            for line in lines:
                new_line = line
                if re.match(r"^package\s+libXray", line):
                    new_line = "package main\n"
                new_lines.append(new_line)
        with open(file_path, "w") as f:
            f.writelines(new_lines)

    def before_build(self):
        self.init_go_env()
        # geo .dat files are not needed for this app (routing does not use them),
        # and the upstream geo download is flaky — skip it so a dead geo source
        # can't fail the whole bind.
        # self.download_geo()

    def build(self):
        pass

    def after_build(self):
        pass

    def reset_files(self):
        self.clean_lib_files(["main.go"])
        files = os.listdir(self.lib_dir)
        for file in files:
            if file.endswith(".go"):
                self.reset_package_name(file)

    def reset_package_name(self, file_name: str):
        file_path = os.path.join(self.lib_dir, file_name)
        new_lines = []
        with open(file_path, "r") as f:
            lines = f.readlines()
            for line in lines:
                new_line = line
                if re.match(r"^package\s+main", line):
                    new_line = "package libXray\n"
                new_lines.append(new_line)
        with open(file_path, "w") as f:
            f.writelines(new_lines)

    def build_desktop_bin(self):
        bin_dir = os.path.join(self.lib_dir, "bin")
        create_dir_if_not_exists(bin_dir)
        output_file = os.path.join(bin_dir, self.bin_file)
        run_env = os.environ.copy()
        run_env["CGO_ENABLED"] = "0"

        cmd = [
            "go",
            "build",
            "-trimpath",
            "-ldflags",
            "-s -w",
            f"-o={output_file}",
            "./desktop_bin",
        ]
        os.chdir(self.lib_dir)
        print(cmd)
        ret = subprocess.run(cmd, env=run_env)
        if ret.returncode != 0:
            raise Exception(f"build_desktop_bin failed")

    def revert_go_env(self):
        os.chdir(self.lib_dir)
        self.clean_lib_files(["go.mod", "go.sum"])
        ret = subprocess.run(["go", "mod", "init", LIBXRAY_MOD_NAME])
        if ret.returncode != 0:
            raise Exception("go mod init failed")
        ret = subprocess.run(["go", "mod", "edit", f"-go={LIBXRAY_GO_VERSION}"])
        if ret.returncode != 0:
            raise Exception("go mod edit go version failed")
        # Redirect xray-core to the local fork checkout (the submodule by default).
        _report_xray_core()
        ret = subprocess.run(["go", "mod", "edit"] + _xray_core_mod_edits())
        if ret.returncode != 0:
            raise Exception("go mod edit replace xray-core fork failed")

        ret = subprocess.run(
            [
                "go",
                "mod",
                "tidy",
            ]
        )
        if ret.returncode != 0:
            raise Exception("go mod tidy failed")
