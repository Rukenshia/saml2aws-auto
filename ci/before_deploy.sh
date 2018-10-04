# This script takes care of building your crate and packaging it for release

set -ex

main() {
    local src=$(pwd) \
          stage=

    local docs='./docs'

    case $TRAVIS_OS_NAME in
        linux)
            stage=$(mktemp -d)
            ;;
        osx)
            stage=$(mktemp -d -t tmp)
            ;;
    esac

    test -f Cargo.lock || cargo generate-lockfile

    cross rustc --bin saml2aws-auto --target $TARGET --release -- -C lto

    fname=target/$TARGET/release/saml2aws-auto
    test -f target/$TARGET/release/saml2aws-auto || fname=target/$TARGET/release/saml2aws-auto.exe
    cp $fname $stage/
    cp -r $docs $stage/

    cd $stage
    tar czf $src/$CRATE_NAME-$TRAVIS_TAG-$TARGET.tar.gz *
    cd $src

    rm -rf $stage
}

main
