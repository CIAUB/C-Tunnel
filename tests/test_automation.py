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
    def installer_version(self, launcher='bash', args=(), source='', configured=None):
        script = (ROOT/'install.sh').read_text()
        helper = script[script.index('resolve_installer_version() {'):
                        script.index('\nresolve_installer_version "$0"')]
        code = ('set -euo pipefail\ndie() { echo "$*" >&2; exit 1; }\n' + helper +
                '\nresolve_installer_version "$0" "$INSTALLER_SOURCE" "$@"\nprintf "%s\\n" "$VERSION"\n')
        env = dict(self.env, INSTALLER_SOURCE=source)
        env.pop('CTUNNEL_VERSION', None)
        if configured is not None:
            env['CTUNNEL_VERSION'] = configured
        return subprocess.run(['bash', '-c', code, launcher, *args], env=env,
                              capture_output=True, text=True)
    def test_installer_version_from_bash_c_zero_argument(self):
        for tag in ('v0.2.1', '0.2.1', 'v0.3.0-rc.1'):
            with self.subTest(tag=tag):
                result = self.installer_version(launcher=tag)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout.strip(), tag if tag.startswith('v') else 'v'+tag)
    def test_installer_version_from_script_or_bash_c_positional(self):
        for launcher, source in (('/tmp/install.sh', '/tmp/install.sh'), ('--', ''), ('bash', '')):
            with self.subTest(launcher=launcher):
                result = self.installer_version(launcher, ('v0.2.1',), source, 'v0.2.2')
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout.strip(), 'v0.2.1')
        result = self.installer_version('v0.2.1', configured='v0.2.2')
        self.assertEqual(result.stdout.strip(), 'v0.2.1')
        self.assertEqual(self.installer_version('latest', configured='v0.2.2').stdout.strip(), 'latest')
    def test_installer_default_and_environment_version(self):
        for launcher, source in (('bash', ''), ('/bin/bash', ''), ('/tmp/v0.2.1', '/tmp/v0.2.1')):
            with self.subTest(launcher=launcher):
                result = self.installer_version(launcher, source=source)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout.strip(), 'latest')
        self.assertEqual(self.installer_version(configured='0.2.1').stdout.strip(), 'v0.2.1')
    def test_installer_rejects_invalid_or_multiple_versions(self):
        for args in (('',), ('../../etc/passwd',), ('--help',), ('v0.2.1;id',), ('v0.2.1', 'v0.2.2')):
            with self.subTest(args=args):
                self.assertNotEqual(self.installer_version(args=args).returncode, 0)
        self.assertNotEqual(self.installer_version(launcher='v0.2.1/invalid').returncode, 0)
    def installer_menu(self, interactive=True, disabled=False):
        import pty
        import shlex
        script = (ROOT/'install.sh').read_text()
        helper = script[script.index('launch_menu() {'):script.index('\nlaunch_menu\n')]
        work = self.d/'menu-work'; work.mkdir()
        marker = self.d/'menu-opened'
        executable = self.d/'menu'
        executable.write_text('#!/bin/bash\nset -eu\n'
                              '[[ ! -e "$WORK" && ! -e /proc/self/fd/9 ]]\n'
                              'flock -n "$MENU_LOCK" -c true\n'
                              'echo opened > "$MENU_MARKER"\n')
        executable.chmod(0o755)
        helper = helper.replace('/usr/local/bin/ctunnel', shlex.quote(str(executable)))
        code = ('set -euo pipefail\nexec 9>"$MENU_LOCK"\nflock 9\n' + helper + '\nlaunch_menu\n')
        env = dict(self.env, WORK=str(work), MENU_MARKER=str(marker),
                   MENU_LOCK=str(self.d/'menu.lock'), CTUNNEL_NO_MENU='1' if disabled else '0')
        if interactive:
            master, slave = pty.openpty()
            try:
                process = subprocess.Popen(['bash', '-c', code], env=env, stdin=slave, stdout=slave, stderr=slave)
                process.wait(timeout=5)
                result = process.returncode
            finally:
                os.close(slave)
                os.close(master)
        else:
            result = subprocess.run(['bash', '-c', code], env=env, stdin=subprocess.DEVNULL,
                                    capture_output=True, timeout=5).returncode
        return result, marker.exists(), work.exists()
    def test_installer_opens_menu_and_releases_lock_in_terminal(self):
        self.assertEqual(self.installer_menu(), (0, True, False))
    def test_installer_skips_menu_without_terminal(self):
        self.assertEqual(self.installer_menu(interactive=False), (0, False, True))
    def test_installer_menu_can_be_disabled_for_automation(self):
        self.assertEqual(self.installer_menu(disabled=True), (0, False, True))
    def test_installer_latest_pins_stable_endpoint_before_asset_downloads(self):
        import hashlib
        fixture=self.d/'release-fixture'; fixture.mkdir()
        work=self.d/'release-work'; work.mkdir()
        data=b'stable release asset'
        (fixture/'binary').write_bytes(data)
        (fixture/'SHA256SUMS').write_text(hashlib.sha256(data).hexdigest()+'  binary\n')
        self.tool('curl', '''url=''; for arg; do [[ "$arg" == https://* ]] && url="$arg"; done
printf '%s\\n' "$url" >> "$FIXTURE/urls"
if [[ "$url" == */releases/latest ]]; then
    printf '%s' 'https://github.com/CIAUB/C-Tunnel/releases/tag/v0.2.2'
else
    [[ "$url" == */releases/download/v0.2.2/* ]] || exit 1
    while [[ "$1" != -o ]]; do shift; done
    cp "$FIXTURE/${url##*/}" "$2"
fi''')
        script=(ROOT/'install.sh').read_text()
        helper=script[script.index('fetch_release() {'):script.index('\n# Go publishes')]
        code='set -euo pipefail\ndie() { echo "$*" >&2; exit 1; }\nASSETS=(binary)\n'+helper+'\nfetch_release\n'
        result=subprocess.run(['bash','-c',code], env=dict(self.env, WORK=str(work),
                              FIXTURE=str(fixture), VERSION='latest', REPO='CIAUB/C-Tunnel'),
                              capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((fixture/'urls').read_text().splitlines(), [
            'https://github.com/CIAUB/C-Tunnel/releases/latest',
            'https://github.com/CIAUB/C-Tunnel/releases/download/v0.2.2/SHA256SUMS',
            'https://github.com/CIAUB/C-Tunnel/releases/download/v0.2.2/binary'])
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
    def bootstrap(self, requested='', arch='amd64', mode='valid'):
        import hashlib
        import io
        import json
        import tarfile
        fixture=self.d/'go-fixture'; fixture.mkdir()
        work=self.d/'go-work'; work.mkdir()
        archive=fixture/'go.tgz'
        with tarfile.open(archive, 'w:gz') as tar:
            data=b'#!/bin/sh\necho fixture-go\n'
            info=tarfile.TarInfo('go/bin/go'); info.size=len(data); info.mode=0o755
            tar.addfile(info, io.BytesIO(data))
        digest=hashlib.sha256(archive.read_bytes()).hexdigest()
        if mode == 'corrupt': digest='0'*64
        if mode == 'bad-hash': digest='not a checksum'
        releases=[]
        for version in ['1.27.3','1.26.10']:
            releases.append({'version':'go'+version,'stable':True,'files':[
                {'filename':f'go{version}.linux-{a}.tar.gz','kind':'archive','sha256':digest}
                for a in ['amd64','arm64']]})
        (fixture/'metadata').write_text('<html>redirect</html>' if mode == 'html' else json.dumps(releases))
        self.tool('curl', '''url=''; for arg; do [[ "$arg" == https://* ]] && url="$arg"; done
printf '%s\\n' "$url" >> "$FIXTURE/urls"
while [[ "$1" != -o ]]; do shift; done
if [[ "$url" == *mode=json* ]]; then cp "$FIXTURE/metadata" "$2"; else cp "$FIXTURE/go.tgz" "$2"; fi''')
        script=(ROOT/'install.sh').read_text()
        helper=script[script.index('bootstrap_go() {'):script.index('# use_checkout lays out')]
        env=dict(self.env, WORK=str(work), FIXTURE=str(fixture), GO_VERSION=requested, ARCH=arch)
        code='set -euo pipefail\ndie() { echo "$*" >&2; exit 1; }\n'+helper+'\nbootstrap_go\ngo version\n'
        result=subprocess.run(['bash','-c',code],env=env,capture_output=True,text=True)
        return result, work, (fixture/'urls').read_text()
    def test_go_bootstrap_stable_and_architecture(self):
        result, work, urls=self.bootstrap(arch='arm64')
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertIn('fixture-go',result.stdout)
        self.assertTrue((work/'go/bin/go').is_file())
        self.assertIn('go1.27.3.linux-arm64.tar.gz', urls)
        self.assertNotIn('.sha256', urls)
    def test_go_bootstrap_pinned_version(self):
        result, _, urls=self.bootstrap(requested='1.26.10')
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertIn('include=all', urls)
        self.assertIn('go1.26.10.linux-amd64.tar.gz', urls)
    def test_go_bootstrap_rejects_html_metadata(self):
        result, work, urls=self.bootstrap(mode='html')
        self.assertNotEqual(result.returncode,0)
        self.assertFalse((work/'go').exists())
        self.assertNotIn('.tar.gz', urls)
    def test_go_bootstrap_rejects_invalid_hash_metadata(self):
        result, work, urls=self.bootstrap(mode='bad-hash')
        self.assertNotEqual(result.returncode,0)
        self.assertFalse((work/'go').exists())
        self.assertNotIn('.tar.gz', urls)
    def test_go_bootstrap_rejects_corrupt_archive_before_extracting(self):
        result, work, _=self.bootstrap(mode='corrupt')
        self.assertNotEqual(result.returncode,0)
        self.assertIn('Go checksum mismatch',result.stderr)
        self.assertFalse((work/'go').exists())
    def test_go_bootstrap_rejects_missing_release(self):
        result, work, urls=self.bootstrap(requested='1.0.0')
        self.assertNotEqual(result.returncode,0)
        self.assertFalse((work/'go').exists())
        self.assertNotIn('.tar.gz', urls)
    def test_wireguard_preflight_does_not_destroy_existing_interface(self):
        text=(ROOT/'scripts/ctunnel-kernel.sh').read_text()
        text=text[:text.index('\ncase "${1:-}" in')]
        marker=self.d/'deleted-interface'
        code=text+\
            '\nload_env() { KIND=wireguard; }\n'+\
            'links_down() { echo deleted > "$MARKER"; }\n'+\
            'cmd_up t1\n'
        env=dict(self.env, PATH=str(self.bin), MARKER=str(marker))
        result=subprocess.run(['/bin/bash','-c',code],env=env,capture_output=True,text=True)
        self.assertNotEqual(result.returncode,0)
        self.assertIn('wireguard-tools',result.stderr)
        self.assertFalse(marker.exists())
    def test_installer_includes_wireguard_tools_dependency(self):
        text=(ROOT/'install.sh').read_text()
        start=text.index('missing=()')
        end=text.index('if ! command -v go',start)
        result=subprocess.run(['/bin/bash','-c',text[start:end]+'\nprintf "%s\\n" "${missing[@]}"'],
                              env=dict(self.env,PATH=str(self.bin)),capture_output=True,text=True)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertIn('wireguard-tools',result.stdout.splitlines())
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
