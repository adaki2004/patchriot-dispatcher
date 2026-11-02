import importlib.util
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('prepare', Path(__file__).with_name('prepare-deploy.py'))
prepare = importlib.util.module_from_spec(spec)
spec.loader.exec_module(prepare)


class BuildInputsTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source = self.root / 'source'
        (self.source / 'src').mkdir(parents=True)
        (self.source / 'Cargo.toml').write_text('manifest')

    def test_only_source_inputs_are_copied(self):
        (self.source / 'src/main.rs').write_text('fn main() {}')
        for name in ['.env', 'provider.key', 'treasury.pem', 'private.toml']:
            (self.source / 'src' / name).write_text('synthetic excluded value')
        prepare.copy_inputs(self.source, self.root / 'output', ['Cargo.toml'], ['src'])
        saved = {str(p.relative_to(self.root / 'output')) for p in (self.root / 'output').rglob('*') if p.is_file()}
        self.assertEqual(saved, {'Cargo.toml', 'src/main.rs'})

    def test_a_source_symlink_cannot_copy_private_host_files(self):
        outside = self.root / 'private'
        outside.write_text('synthetic private value')
        (self.source / 'src/linked.rs').symlink_to(outside)
        with self.assertRaises(ValueError):
            prepare.copy_inputs(self.source, self.root / 'output', [], ['src'])

    def test_existing_or_in_repository_output_is_not_replaced(self):
        existing = self.root / 'existing'
        existing.mkdir()
        with self.assertRaises(FileExistsError):
            prepare.prepare(self.source, self.source, existing)
        with self.assertRaises(ValueError):
            prepare.prepare(self.source, self.source, self.source / 'build')


if __name__ == '__main__':
    unittest.main()
