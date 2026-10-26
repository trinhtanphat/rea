#!/usr/bin/env bash
# Produce two independently linked Windows PE x64 DLLs and prove byte identity.
# Lab-only: no execution of the Windows binary and no globally installed tools.
set -euo pipefail
LAB='/var/tmp/rea-native-build-20261026'
COMPILER="$LAB/bin/x86_64-w64-mingw32-g++"
SYSROOT="$LAB/sysroot"
if [[ $# -ne 1 ]]; then
  echo 'Usage: fork-lab-ghidra-reproducible-pe.sh /var/tmp/rea-native-build-20261026/.../rea-ghidra-arithmetic.cpp' >&2
  exit 2
fi
if [[ ! -x "$COMPILER" || ! -d "$SYSROOT" || ! -f "$1" ]]; then
  echo 'Missing isolated compiler, sysroot, or source fixture.' >&2
  exit 2
fi
SOURCE="$(realpath -e -- "$1")"
case "$SOURCE" in "$LAB"/*.cpp) ;; *)
  echo 'Source must be a .cpp file inside the isolated REA lab.' >&2
  exit 2 ;;
esac
WORKSPACE="$(mktemp -d "$LAB/fixtures/pe-repro-XXXXXXXX")"
mkdir -p "$WORKSPACE/first" "$WORKSPACE/second"
export PATH="$LAB/bin:$SYSROOT/usr/bin:$PATH"
export LD_LIBRARY_PATH="$SYSROOT/usr/lib/x86_64-linux-gnu"
for slot in first second; do
  "$COMPILER" -shared -O0 -fno-inline \
    -Wl,--no-insert-timestamp \
    -Wl,--image-base,0x180000000 \
    -o "$WORKSPACE/$slot/rea_lab_arithmetic.dll" "$SOURCE"
done
python3 - "$SOURCE" "$WORKSPACE" <<'PY'
import hashlib, json, pathlib, struct, sys
source=pathlib.Path(sys.argv[1]); workspace=pathlib.Path(sys.argv[2])
first=workspace/'first'/'rea_lab_arithmetic.dll'
second=workspace/'second'/'rea_lab_arithmetic.dll'
a=first.read_bytes();b=second.read_bytes()
if a!=b:
    raise SystemExit('FAIL: independently compiled PE DLLs differ')
if len(a)>1024*1024 or a[:2]!=b'MZ':
    raise SystemExit('FAIL: PE fixture has unexpected size or DOS header')
pe=struct.unpack_from('<I',a,0x3c)[0]
if a[pe:pe+4]!=b'PE\0\0':
    raise SystemExit('FAIL: PE signature missing')
machine=struct.unpack_from('<H',a,pe+4)[0]
timestamp=struct.unpack_from('<I',a,pe+8)[0]
optional=pe+24
magic=struct.unpack_from('<H',a,optional)[0]
imagebase=struct.unpack_from('<Q',a,optional+24)[0]
if machine!=0x8664 or magic!=0x20b or timestamp!=0 or imagebase!=0x180000000:
    raise SystemExit(f'FAIL: unexpected PE x64 metadata: {machine=} {magic=} {timestamp=} {imagebase=:#x}')
for name in (b'rea_lab_add',b'rea_lab_mix'):
    if name not in a: raise SystemExit(f'FAIL: function export missing: {name!r}')
# Negative control: an intentionally changed COPY of the PE must not match.
negative=workspace/'altered-copy.dll'
tampered=bytearray(b)
tampered[0x40] ^= 1
negative.write_bytes(tampered)
if tampered==a: raise SystemExit('FAIL: byte tampering was not detected')
sha=lambda data: hashlib.sha256(data).hexdigest()
result={
    'ok':True, 'same_source':str(source), 'source_sha256':sha(source.read_bytes()),
    'first_sha256':sha(a),'second_sha256':sha(b),
    'byte_identical':True,'pe_machine':'AMD64','pe_timestamp':timestamp,
    'pe_image_base':f'0x{imagebase:x}','fixture_size':len(a),
    'named_exports':['rea_lab_add','rea_lab_mix'],
    'negative_byte_tamper_rejected':True,'used_isolated_compiler':True,
    'no_windows_binary_execution':True,'workspace':str(workspace)
}
(workspace/'manifest.json').write_text(json.dumps(result,indent=2)+'\n',encoding='utf8')
print(json.dumps(result,indent=2))
PY
