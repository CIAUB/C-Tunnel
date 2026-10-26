"""Isolated behavioral checks: never run host sysctl/systemctl or change networking."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]

class Automation(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.d = Path(self.temp.name)
        self.bin = self.d / 'bin'
        self.bin.mkdir()
        self.env = dict(os.environ, PATH=str(self.bin)+':'+os.environ['PATH'])
    def tearDown(self):
        self.temp.cleanup()
    def tool(self, name, body):
        f = self.bin / name
        f.write_text('#!/bin/bash\nset -eu\n'+body+'\n')
        f.chmod(0o755)
    def optimize(self, fail=False, source=None):
        self.tool('modprobe', 'exit 1')
        self.tool('sysctl', '''if [[ "$*" == '-n net.ipv4.tcp_congestion_control' ]]; then echo cubic
elif [[ "$*" == '-n net.ipv4.tcp_available_congestion_control' ]]; then echo 'reno cubic'
elif [[ "$1" == '-n' ]]; then echo 1
else exit '''+ ('1' if fail else '0') + '\nfi')
        text = source or (ROOT/'scripts/ctunnel-kernel.sh').read_text()
        # Extract only the optimizer and its helper definitions, avoiding CLI root operations.
        text = text[:text.index('\ncase "${1:-}" in')]
        f=self.d/'optimizer.sh'
        f.write_text(text+'\ncmd_optimize\n')
        return subprocess.run(['bash', str(f)], env=dict(self.env, CT_SYSCTL=str(self.d/'sysctl.conf')),
                              capture_output=True, text=True)
    def test_supported_congestion_fallback_and_defaults(self):
        r=self.optimize()
        self.assertEqual(r.returncode, 0, r.stderr)
        text=(self.d/'sysctl.conf').read_text()
        self.assertIn('tcp_congestion_control = cubic', text)
        self.assertIn('rmem_default = 212992', text)
        self.assertNotIn('nf_conntrack_max', text)
    def test_sysctl_failure_is_not_success(self):
        self.assertNotEqual(self.optimize(True).returncode, 0)
    def test_release_checksums_reject_duplicates_and_corruption(self):
        import hashlib
        fixture=self.d/'fixture'; fixture.mkdir()
        work=self.d/'work'; work.mkdir()
        data=b'validated asset'
        (fixture/'binary').write_bytes(data)
        checksum=hashlib.sha256(data).hexdigest()+'  binary\n'
        script=(ROOT/'install.sh').read_text()
        fn=script[script.index('fetch_release() {'):script.index('\n# use_checkout')]
        self.tool('curl', 'while [[ "$1" != -o ]]; do shift; done; cp "$FIXTURE/${2##*/}" "$2"')
        env=dict(self.env, WORK=str(work),FIXTURE=str(fixture),VERSION='v1.0',REPO='CIAUB/C-Tunnel')
        code='set -euo pipefail\ndie() { echo "$*" >&2; exit 1; }\nASSETS=(binary)\n'+fn+'\nfetch_release\n'
        for content,expected in [(checksum,0),(checksum*2,1),('0'*64+'  binary\n',1),('',1)]:
            (fixture/'SHA256SUMS').write_text(content)
            r=subprocess.run(['bash','-c',code],env=env,capture_output=True,text=True)
            self.assertEqual(r.returncode,expected,r.stderr)
    def test_atomic_replace_preserves_running_inode(self):
        src=self.d/'new'; src.write_text('new version')
        dst=self.d/'target'; dst.write_text('old version')
        script=(ROOT/'install.sh').read_text()
        fn=script[script.index('atomic_binary() {'):script.index('\natomic_binary "${WORK}')]
        with dst.open() as running:
            r=subprocess.run(['bash','-c','set -eu\ndie() { exit 1; }\n'+fn+'\natomic_binary "$1" "$2"', 'test',str(src),str(dst)],capture_output=True,text=True)
            self.assertEqual(r.returncode,0,r.stderr)
            self.assertEqual(running.read(),'old version')
        self.assertEqual(dst.read_text(),'new version')
    def watchdog_setup(self):
        (self.d/'config').mkdir()
        (self.d/'config'/'test.env').write_text('WATCH_UNIT=frpc.service\nTUNNEL_URL=http://tunnel/health\nORIGIN_URL=http://origin/health\nEXPECTED_BODY=ok\n')
        self.env.update(CT_WATCHDOG_CONFIG_DIR=str(self.d/'config'), CT_WATCHDOG_STATE_DIR=str(self.d/'state'), MOCK=str(self.d))
        self.tool('systemctl', '''if [[ "$1" == is-active ]]; then [[ ! -e "$MOCK/inactive" ]]; else echo restart >> "$MOCK/restarts"; fi''')
        self.tool('curl', '''url="${!#}"; if [[ "$url" == http://tunnel/* && -e "$MOCK/tunnel-fail" ]] || [[ "$url" == http://origin/* && -e "$MOCK/origin-fail" ]]; then exit 7; fi; echo ok''')
    def tick(self):
        r=subprocess.run(['bash',str(ROOT/'scripts/ctunnel-watchdog.sh'),'test'],env=self.env,capture_output=True,text=True)
        self.assertEqual(r.returncode,0,r.stderr)
    def test_watchdog_three_failures_and_cooldown(self):
        self.watchdog_setup(); self.tick()
        (self.d/'tunnel-fail').touch()
        self.tick(); self.tick()
        self.assertFalse((self.d/'restarts').exists())
        self.tick()
        self.assertEqual((self.d/'restarts').read_text().count('restart'),1)
        for _ in range(5): self.tick()
        self.assertEqual((self.d/'restarts').read_text().count('restart'),1)
    def test_never_healthy_origin_down_and_manual_stop_do_not_restart(self):
        self.watchdog_setup(); (self.d/'tunnel-fail').touch()
        for _ in range(4): self.tick()
        self.assertFalse((self.d/'restarts').exists())
        (self.d/'tunnel-fail').unlink(); self.tick()
        (self.d/'tunnel-fail').touch(); (self.d/'origin-fail').touch()
        for _ in range(4): self.tick()
        self.assertFalse((self.d/'restarts').exists())
        (self.d/'origin-fail').unlink(); (self.d/'inactive').touch()
        for _ in range(4): self.tick()
        self.assertFalse((self.d/'restarts').exists())

if __name__ == '__main__': unittest.main()
