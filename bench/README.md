# The implementation and build study

Everything behind Section 6. Run on the Mac, in this order.

1. `run_impls.sh` builds OpenSSL 4.0.2 from source with and without assembly,
   liboqs 0.16.0 with its native aarch64 path and with a generic target,
   and PQClean's reference ML-DSA-65, then times each through one C harness
   and re-runs `compare_backends.py`. All builds finish before any timing
   starts.

2. `profile_wheel.sh` samples the PyPI wheel and the source build while each
   signs, and records the compiler line and out-of-line helper symbols in the
   wheel's shared object. This is what named the cause.

3. `build_o3_env.sh` builds `cryptography` 50.0.1 from source against the
   `-O3` OpenSSL from step 1 into `.venv-o3`. It installs a minimal Rust
   toolchain in `~/.cargo` if none is present.

4. `run_o3.sh` runs every timing experiment through `.venv-o3` into
   `out-o3/`. That is the paper's data. `run_both.sh` does the same and then
   repeats it through the wheel into `out-o0/`, for Table 14.

The finding in one line: the macOS arm64 wheel of cryptography 50.0.1 links an
OpenSSL 4.0.2 whose compiler line carries no `-O` flag, so it is built at
`-O0`. Every C primitive, which includes every post-quantum one, runs about ten
times slow; assembly-backed ones do not move. The Linux x86-64 wheel of the
same release is built at `-O3`. Check any installation with

    python -c "import cryptography,glob,os;so=glob.glob(os.path.join(os.path.dirname(cryptography.__file__),'hazmat','bindings','_rust*.so'))[0];b=open(so,'rb').read();i=b.find(b'compiler: ');print(b[i:b.index(b'\0',i)].decode())"
