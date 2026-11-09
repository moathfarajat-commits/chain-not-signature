#!/bin/bash
# x86-64 counterpart of bench/run_impls.sh builds + the Python env (Linux wheel, -O3).
set -u
B=~/x86/build; mkdir -p $B; cd $B
log(){ echo "[$(date +%H:%M:%S)] $*"; }
J=2
OSSL=4.0.2; OQS=0.16.0
[ -d openssl-$OSSL ] || { curl -fsSL -o o.tgz https://github.com/openssl/openssl/releases/download/openssl-$OSSL/openssl-$OSSL.tar.gz && tar xzf o.tgz; }
[ -d liboqs-$OQS ] || { curl -fsSL -o q.tgz https://github.com/open-quantum-safe/liboqs/archive/refs/tags/$OQS.tar.gz && tar xzf q.tgz; }
[ -d pqclean ] || git clone -q --depth 1 https://github.com/PQClean/PQClean pqclean
for v in asm noasm; do p=$B/ossl-$v
 [ -f $p/lib/libcrypto.a ] && continue
 log "openssl $v"; rm -rf src-$v; cp -R openssl-$OSSL src-$v
 f=""; [ $v = noasm ] && f=no-asm
 (cd src-$v && ./Configure linux-x86_64 --prefix=$p --libdir=lib no-shared no-tests no-docs $f >../cfg-$v.log 2>&1 && make -j$J build_libs >../make-$v.log 2>&1 && make install_dev >/dev/null 2>&1) || log "openssl $v FAILED"
done
for v in native generic shared; do p=$B/oqs-$v
 [ -f $p/lib/liboqs.a ] || [ -f $p/lib/liboqs.so ] && continue
 log "liboqs $v"
 extra="-DOQS_OPT_TARGET=auto -DOQS_DIST_BUILD=OFF -DBUILD_SHARED_LIBS=OFF -DOQS_USE_OPENSSL=OFF -DOQS_BUILD_ONLY_LIB=ON -DOQS_MINIMAL_BUILD=SIG_ml_dsa_65"
 [ $v = generic ] && extra="-DOQS_OPT_TARGET=generic -DOQS_DIST_BUILD=OFF -DBUILD_SHARED_LIBS=OFF -DOQS_USE_OPENSSL=OFF -DOQS_BUILD_ONLY_LIB=ON -DOQS_MINIMAL_BUILD=SIG_ml_dsa_65"
 # full shared build for liboqs-python, same defaults the Mac's ~/_oqs used
 [ $v = shared ] && extra="-DBUILD_SHARED_LIBS=ON -DOQS_BUILD_ONLY_LIB=ON -DOQS_USE_OPENSSL=OFF"
 cmake -S liboqs-$OQS -B ob-$v -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=$p $extra >oqs-cfg-$v.log 2>&1 && cmake --build ob-$v -j$J >oqs-make-$v.log 2>&1 && cmake --install ob-$v >/dev/null 2>&1 || log "liboqs $v FAILED"
 grep -iE "AVX2|OPT_TARGET|ml_dsa_65_avx2|USE_OPENSSL" ob-$v/CMakeCache.txt > oqs-flags-$v.txt 2>/dev/null
done
log "venv"
python3 -m venv ~/x86/venv && . ~/x86/venv/bin/activate
pip install -q --upgrade pip
pip install -q "cryptography==50.0.1" "cbor2>=6.1.4" "pillow>=11.0" numpy
export OQS_INSTALL_PATH=$B/oqs-shared LD_LIBRARY_PATH=$B/oqs-shared/lib
pip install -q liboqs-python
python -c "import oqs,cryptography;from cryptography.hazmat.backends.openssl.backend import backend;print('oqs',oqs.oqs_version(),'crypto',cryptography.__version__,backend.openssl_version_text())"
log BUILD_DONE
