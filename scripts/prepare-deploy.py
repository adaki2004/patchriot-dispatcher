"""Create a source-only build context beside the repositories, never inside one.

The private dispatcher needs core's shared protocol crate at build time. Copy
only the listed Rust inputs; no Git credentials, environment files or host state.
Runtime credentials belong in the deployment service's secret configuration.
"""
import argparse
from pathlib import Path
import shutil


def copy_inputs(source, destination, names, folders):
    source, destination = source.resolve(), destination.resolve()
    files = [source / name for name in names]
    for folder in folders:
        files.extend(p for p in (source / folder).rglob('*') if p.is_file()
                     and (p.suffix in ('.rs', '.sql') or p.name == 'Cargo.toml'))
    for file in files:
        if not file.is_file() or file.is_symlink() or not file.resolve().is_relative_to(source):
            raise ValueError('Build input is missing or points outside its repository')
        target = destination / file.relative_to(source)
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(file, target)


def prepare(core, dispatcher, output):
    core, dispatcher, output = core.resolve(), dispatcher.resolve(), output.resolve()
    if output.is_relative_to(core) or output.is_relative_to(dispatcher):
        raise ValueError('Choose an output directory outside both repositories')
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    copy_inputs(core, output / 'patchriot-core', ['Cargo.toml', 'Cargo.lock', 'rust-toolchain.toml'], ['crates'])
    copy_inputs(dispatcher, output / 'patchriot-dispatcher', [
        'Cargo.toml', 'Cargo.lock', 'rust-toolchain.toml', 'build.rs', 'Dockerfile', 'NOTICE',
        'deploy/start-gateway.sh', 'deploy/serve.json',
    ], ['src', 'migrations'])
    shutil.copyfile(output / 'patchriot-dispatcher/Dockerfile', output / 'Dockerfile')
    (output / '.dockerignore').write_text('**\n!Dockerfile\n!patchriot-core/**\n!patchriot-dispatcher/**\n')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--core', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    prepare(args.core, Path(__file__).resolve().parents[1], args.output)
    print('Prepared source-only deployment context. Runtime secrets were not copied.')
