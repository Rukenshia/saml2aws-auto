# This script takes care of testing your crate

set -ex

main() {
    cross build --target $TARGET
    cross build --target $TARGET --release

    if [ ! -z $DISABLE_TESTS ]; then
        return
    fi

    cross test --target $TARGET
    cross test --target $TARGET --release

    shell_session_update() { :; }

    if [ "$TARGET" != "x86_64-pc-windows-gnu" ]; then
        cross run --target $TARGET -- version
        cross run --target $TARGET --release -- version
    else
        echo "WARN: smoke test disabled for windows due to wine incompatibility"
    fi
}

# we don't run the "test phase" when doing deploys
if [ -z $TRAVIS_TAG ]; then
    main
fi
