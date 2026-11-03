"""Owned process fakes test lifecycle and credential separation, without a tailnet."""
import json
import os
from pathlib import Path
import signal
import subprocess
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]


class GatewayLauncherTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.folder = Path(self.temp.name)
        self.bin = self.folder / 'bin'
        self.bin.mkdir()
        fake = '''#!/usr/bin/env python3
import json,os,signal,sys,time
from pathlib import Path
name=Path(sys.argv[0]).name
folder=Path(os.environ['GATEWAY_FIXTURE'])
(folder/(name+'.json')).write_text(json.dumps(dict(os.environ)))
def stop(*_):
 (folder/(name+'.stopped')).write_text('stopped')
 raise SystemExit(0)
signal.signal(signal.SIGTERM,stop)
while not (folder/(name+'.exit')).exists(): time.sleep(0.02)
raise SystemExit(1)
'''
        for name in ('patchriot-relay-gateway', 'containerboot'):
            path = self.bin / name
            path.write_text(fake)
            path.chmod(0o700)
        self.env = {
            'PATH': str(self.bin) + os.pathsep + os.environ['PATH'],
            'GATEWAY_FIXTURE': str(self.folder), 'TS_STATE_DIR': str(self.folder / 'state'),
            'DATABASE_URL': 'postgres://fixture/owned', 'PATCHRIOT_AUDIENCE': 'fixture',
            'TS_AUTHKEY': 'synthetic-network-credential',
            'PATCHRIOT_INTERNAL_KEY': 'synthetic-unused-internal-credential',
            'PATCHRIOT_JEV_OPENROUTER_KEY': 'synthetic-unused-model-credential',
            'TS_EXTRA_ARGS': '--ssh --advertise-exit-node', 'TS_USERSPACE': 'false',
            'TS_DEST_IP': '203.0.113.1', 'TS_SERVE_CONFIG': '/untrusted/config',
        }
        self.process = None
        self.addCleanup(self.stop)

    def stop(self):
        if self.process and self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                os.killpg(self.process.pid, signal.SIGKILL)
                self.process.wait(timeout=5)

    def start(self):
        self.process = subprocess.Popen(['sh', str(ROOT / 'deploy/start-gateway.sh')], env=self.env,
                                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                        start_new_session=True)
        return self.process

    def ready(self):
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            if all((self.folder / (name + '.json')).exists() for name in ('containerboot', 'patchriot-relay-gateway')):
                return
            if self.process.poll() is not None:
                self.fail('Launcher exited before starting owned process fakes')
            time.sleep(0.02)
        self.fail('Launcher did not start both owned process fakes')

    def test_children_get_only_their_service_credentials_and_fixed_transport(self):
        self.start()
        self.ready()
        app = json.loads((self.folder / 'patchriot-relay-gateway.json').read_text())
        mesh = json.loads((self.folder / 'containerboot.json').read_text())
        self.assertIn('DATABASE_URL', app)
        self.assertNotIn('TS_AUTHKEY', app)
        self.assertIn('TS_AUTHKEY', mesh)
        self.assertNotIn('DATABASE_URL', mesh)
        for env in (app, mesh):
            self.assertNotIn('PATCHRIOT_INTERNAL_KEY', env)
            self.assertNotIn('PATCHRIOT_JEV_OPENROUTER_KEY', env)
            self.assertNotIn('TS_EXTRA_ARGS', env)
            self.assertNotIn('TS_DEST_IP', env)
            self.assertEqual(env['TS_USERSPACE'], 'true')
            self.assertEqual(env['TS_SERVE_CONFIG'], '/etc/patchriot/serve.json')
        self.process.terminate()
        self.assertEqual(self.process.wait(timeout=5), 0)
        self.assertTrue((self.folder / 'containerboot.stopped').exists())
        self.assertTrue((self.folder / 'patchriot-relay-gateway.stopped').exists())

    def test_either_child_exiting_stops_its_companion(self):
        for name, companion in [('containerboot', 'patchriot-relay-gateway'), ('patchriot-relay-gateway', 'containerboot')]:
            with self.subTest(child=name):
                # Fresh markers for the second run, not a second live launcher.
                for p in self.folder.glob('*.json'):
                    p.unlink()
                for p in self.folder.glob('*.exit'):
                    p.unlink()
                for p in self.folder.glob('*.stopped'):
                    p.unlink()
                self.start()
                self.ready()
                (self.folder / (name + '.exit')).touch()
                self.assertEqual(self.process.wait(timeout=5), 1)
                self.assertTrue((self.folder / (companion + '.stopped')).exists())

    def test_missing_network_identity_starts_neither_process(self):
        self.env.pop('TS_AUTHKEY')
        self.assertNotEqual(self.start().wait(timeout=5), 0)
        self.assertFalse((self.folder / 'containerboot.json').exists())
        self.assertFalse((self.folder / 'patchriot-relay-gateway.json').exists())

    def test_serve_only_proxies_the_agent_gateway(self):
        config = json.loads((ROOT / 'deploy/serve.json').read_text())
        self.assertEqual(config['TCP'], {'443': {'HTTPS': True}})
        self.assertEqual(config['AllowFunnel'], {})
        self.assertEqual(config['Web'], {'${TS_CERT_DOMAIN}:443': {
            'Handlers': {'/': {'Proxy': 'http://127.0.0.1:7412'}}}})


if __name__ == '__main__':
    unittest.main()
