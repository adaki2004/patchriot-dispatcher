"""Optional Linux image checks; use an owned volume, no network or credentials.

PATCHRIOT_GATEWAY_TEST_IMAGE must name a locally built mesh image. The probe
replaces only the final launcher, so it observes the real privilege transition.
"""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
import uuid

IMAGE = os.environ.get('PATCHRIOT_GATEWAY_TEST_IMAGE')


@unittest.skipUnless(IMAGE, 'Set PATCHRIOT_GATEWAY_TEST_IMAGE to test the built mesh image')
class GatewayEntrypointTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        metadata = json.loads(cls.docker('image', 'inspect', IMAGE).stdout)[0]
        cls.platform = metadata['Os'] + '/' + metadata['Architecture']
        if metadata.get('Variant'):
            cls.platform += '/' + metadata['Variant']
        cls.tag = 'patchriot-entrypoint-test:' + uuid.uuid4().hex
        cls.addClassCleanup(lambda: cls.docker('image', 'rm', cls.tag, check=False))
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder)
            (path / 'Dockerfile').write_text('ARG IMAGE=patchriot-gateway:local\nFROM ${IMAGE}\nCOPY --chmod=755 probe /usr/local/bin/start-gateway\n')
            (path / 'probe').write_text('''#!/bin/sh
set -eu
echo "uid=$(id -u) gid=$(id -g) groups=$(id -G)"
awk '/^Cap(Inh|Prm|Eff|Bnd|Amb):|^NoNewPrivs:/' /proc/self/status
echo "state=$(stat -c '%u:%g:%a' /var/lib/tailscale)"
if [ -f /var/lib/tailscale/owned-fixture ]; then
  echo "previous=$(cat /var/lib/tailscale/owned-fixture)"
else
  printf 'retained' > /var/lib/tailscale/owned-fixture
fi
echo 'service_probe_started'
''')
            cls.docker('build', '--platform', cls.platform, '--build-arg', 'IMAGE=' + IMAGE, '-t', cls.tag, str(path))

    @classmethod
    def docker(cls, *args, check=True):
        result = subprocess.run(['docker', *args], capture_output=True, text=True, timeout=90)
        if check and result.returncode:
            raise AssertionError('Owned Docker check failed: ' + result.stderr[-2000:])
        return result

    def run_image(self, *args):
        return self.docker('run', '--rm', '--platform', self.platform, '--network=none', '--read-only', '--user=0:0',
                           '--cap-drop=ALL', '--cap-add=CHOWN', '--cap-add=FOWNER',
                           '--cap-add=SETUID', '--cap-add=SETGID', '--cap-add=SETPCAP',
                           *args, self.tag, check=False)

    def test_root_volume_is_prepared_before_dropping_every_privilege(self):
        volume = 'patchriot-entrypoint-test-' + uuid.uuid4().hex
        self.docker('volume', 'create', volume)
        self.addCleanup(lambda: self.docker('volume', 'rm', volume, check=False))
        for attempt in range(2):
            result = self.run_image('--mount', f'type=volume,src={volume},dst=/var/lib/tailscale,volume-nocopy')
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn('uid=65534 gid=65534 groups=65534', result.stdout)
            self.assertIn('state=65534:65534:700', result.stdout)
            lines = dict(line.split(':', 1) for line in result.stdout.splitlines() if ':' in line and '=' not in line)
            for name in ('CapInh', 'CapPrm', 'CapEff', 'CapBnd', 'CapAmb'):
                self.assertEqual(int(lines[name].strip(), 16), 0)
            self.assertEqual(lines['NoNewPrivs'].strip(), '1')
            self.assertIn('service_probe_started', result.stdout)
            self.assertEqual('previous=retained' in result.stdout, attempt == 1)

    def test_root_cannot_initialize_an_arbitrary_path(self):
        result = self.run_image('-e', 'TS_STATE_DIR=/tmp/outside')
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn('service_probe_started', result.stdout)

    def test_root_cannot_follow_a_symlink_for_machine_state(self):
        # Only the disposable container layer changes; no host directory mounts.
        result = self.docker('run', '--rm', '--platform', self.platform, '--network=none', '--user=0:0', '--entrypoint=/bin/sh', self.tag,
                             '-c', 'rmdir /var/lib/tailscale && ln -s /tmp /var/lib/tailscale && exec /usr/local/bin/gateway-entrypoint', check=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('Root initialization only supports', result.stderr)
        self.assertNotIn('service_probe_started', result.stdout)


if __name__ == '__main__':
    unittest.main()
