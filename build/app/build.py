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
LIBXRAY_GO_VERSION = "1.26.2"
# Build against the vinaes/Xray-core fork instead of upstream. The fork keeps the
# original module path github.com/xtls/xray-core, so a replace directive pointing
# at the fork repo resolves correctly. Pinned to the HWC line
# (hwc1-adopt @ 80924b5e): the detection-resist HWC transport (h2/h3 Chrome-shaped
# carrier) + the h2 conn-flow-window-credit leak fix + the co-bound cover companion
# + runtime-delivered signed profile_blob + per-user hwc account. This line
# supersedes the old 3b17dd9b pin (which itself carried the #6461 WireGuard-teardown
# fix; that is included transitively).
#
# chromeQUICPostQuantumKeyShare is TRUE on this pin, i.e. the upstream default —
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
# Also carries datagram fragmentation on both carriers and the udp_demux fan-out fix
# (one inner UDP socket -> up to 200 destinations). Keep this in sync
# with the submodules/Xray-core pointer. NOTE: this line VENDORS a Chrome-shaped
# quic-go fork under third_party/quic-go (the h3 carrier's QUIC fingerprint); the
# non-local build must replace apernet/quic-go at that subdir too (see below) — Go
# ignores replace directives inside dependencies, so it must live in this module.
XRAY_CORE_MOD = "github.com/xtls/xray-core"
XRAY_CORE_FORK = "github.com/vinaes/xray-core"
XRAY_CORE_VERSION = "80924b5e"
# Blackout fallback carrier, co-bound into THIS framework (via wbypass_wrapper.go)
# so xray + wbypass share ONE Go runtime — two gomobile runtimes in the NE crash
# in runtime.load_g. init_go_env regenerates go.mod from scratch, so these local
# replaces must be injected here, not left in a committed go.mod (it gets wiped).
# whitelist-bypass/relay is pulled transitively by wbypass's vksfu carrier.
WBYPASS_MOD = "github.com/vinaes/wbypass"
WBYPASS_LOCAL = "../wbypass"
WLB_RELAY_MOD = "whitelist-bypass/relay"
WLB_RELAY_LOCAL = "../whitelist-bypass/relay"

# Staging (HWC): when HWC_XRAY_LOCAL points at a local xray-core checkout that
# contains the HWC transport, redirect xray-core there instead of the pinned
# fork, and mirror that checkout's vendored quic-go replace — Go ignores replace
# directives inside dependencies, so it must live in this main module. Unset =>
# stock build against the pinned fork, unchanged.
HWC_XRAY_LOCAL = os.environ.get("HWC_XRAY_LOCAL", "").strip()
APERNET_QUICGO_MOD = "github.com/apernet/quic-go"

# The fork is consumed by commit hash and was never published to sum.golang.org,
# so `go mod tidy` fails verifying its go.mod against the public checksum DB
# (404, then a misleading "could not read Username for https://github.com" that
# comes from the sumdb's own fetch attempt, not from a missing credential — the
# repo is public). GOPRIVATE implies GONOSUMDB + GONOPROXY, so Go fetches the
# fork straight from the repo and skips verification. setdefault, so an explicit
# value from the environment still wins.
os.environ.setdefault("GOPRIVATE", "github.com/vinaes/*")


def _xray_core_mod_edits() -> list[str]:
    if HWC_XRAY_LOCAL:
        edits = [
            f"-replace={XRAY_CORE_MOD}={HWC_XRAY_LOCAL}",
            f"-require={XRAY_CORE_MOD}@v0.0.0",
            f"-replace={APERNET_QUICGO_MOD}={HWC_XRAY_LOCAL}/third_party/quic-go",
        ]
    else:
        # Non-local (CI/release) build against the pinned fork. The HWC line vendors a
        # Chrome-shaped quic-go under third_party/quic-go; consume it as a versioned
        # subdirectory module of the same fork at the same revision (verified: Go resolves
        # it and ChromeShapeConfig compiles, even though its go.mod keeps the upstream
        # module path). Without this the h3 carrier would link stock apernet/quic-go and
        # lose its QUIC fingerprint shaping (or fail to build on ChromeShape symbols).
        edits = [
            f"-replace={XRAY_CORE_MOD}={XRAY_CORE_FORK}@{XRAY_CORE_VERSION}",
            f"-require={XRAY_CORE_MOD}@v0.0.0",
            f"-replace={APERNET_QUICGO_MOD}={XRAY_CORE_FORK}/third_party/quic-go@{XRAY_CORE_VERSION}",
        ]
    return edits + [
        f"-replace={WBYPASS_MOD}={WBYPASS_LOCAL}",
        f"-require={WBYPASS_MOD}@v0.0.0",
        f"-replace={WLB_RELAY_MOD}={WLB_RELAY_LOCAL}",
    ]


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
        # Redirect xray-core to the vinaes fork at the pinned revision (or a
        # local HWC checkout when HWC_XRAY_LOCAL is set).
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
        # Redirect xray-core to the vinaes fork at the pinned revision (or a
        # local HWC checkout when HWC_XRAY_LOCAL is set).
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
