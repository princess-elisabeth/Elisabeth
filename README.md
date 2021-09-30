# Elisabeth
This is a Rust implementation of Elisabeth. _Toward Globally Optimized Hybrid Homomorphic Encryption_, the paper introducing Elisabeth, is currently under review for Eurocrypt 2022 and should be made available on eprint in the near future.

## Prerequisite

To use elisabeth, you will need the Rust compiler, and the FFTW library. The compiler can be
installed on linux and osx with the following command:

```bash
curl  --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

Other rust installation methods are available on the
[rust website](https://forge.rust-lang.org/infra/other-installation-methods.html).

To install the FFTW library on MacOS, one could use the Homebrew package manager. To install
Homebrew, you can do the following:

```bash
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/master/install.sh)"
```

And then use it to install FFTW:

```bash
brew install fftw
```

To install FFTW on a debian-based distribution, you can use the following command:

```bash
sudo apt-get update && sudo apt-get install -y libfftw3-dev
```

You can then clone this repository by doing:

```bash
git clone git@github.com:princess-elisabeth/Elisabeth.git
```

## Usage
Before running any test or benchmark, you should export the following RUSTFLAGS:
```
export RUSTFLAGS="-C target-cpu=native"
```

### Tests
To run a correctness test of elisabeth, simply run the following command:
```bash
cargo test --release homomorphic -- *NUMBER_OF_NIBBLES*
```
Where *NUMBER_OF_NIBBLES* should be replaced by the actual number of nibbles over which you want the test to be run.

Nota: the timings given by the tests are indicative and not precisely measured. To have precise time measurment, refer to the benchmark section.

### Benchmarks
To run an benchmark, use the following command:
```
cargo bench
```
### Optional features
By default, Elisabeth runs in two-keyswitching-key, multithreaded mode. To run in single_key, add `--features single_key` right after the `test` or `bench` command. To run in monothread, add `--no-default-features`.

## How to cite
More on that soon.
