# app/android.py
import os
import subprocess

from app.build import Builder


class AndroidBuilder(Builder):

    def before_build(self):
        super().before_build()
        self.prepare_gomobile()

    def build(self):
        self.before_build()

        clean_files = ["libXray-sources.jar", "libXray.aar"]
        self.clean_lib_files(clean_files)
        os.chdir(self.lib_dir)
        # keep same with flutter
        ret = subprocess.run(
            [
                "gomobile",
                "bind",
                "-target",
                "android",
                "-androidapi",
                "21",
                # -checklinkname=0 lifts the go1.23+ //go:linkname clampdown that
                # wlynxg/anet trips (it linknames into net.zoneCache). Hits every
                # ABI, not just x86; without it the link fails with
                # "invalid reference to net.zoneCache". Unrelated to the carrier.
                "-ldflags=-checklinkname=0 -extldflags=-Wl,-z,max-page-size=16384",
            ]
        )
        if ret.returncode != 0:
            raise Exception("build failed")

        self.after_build()

        self.revert_go_env()
