#/bin/bash
BUILD_DIR="target/release"

if !(ls $BUILD_DIR | grep 'deno_argon2' > /dev/null);
then
    echo "A builded library not founded"
    echo "Please execute 'cargo build --release' first"
    exit 1;
fi

cp lib/internal.ts _tmp.ts
trap "mv _tmp.ts lib/internal.ts" EXIT

sed -i 's/dlopen(FETCH_OPTIONS, SYMBOLS)/dlopen(_FETCH_OPTIONS_FOR_DEV, SYMBOLS)/g' lib/internal.ts
deno test --allow-read --allow-write --allow-ffi --allow-run --allow-env --unstable tests/