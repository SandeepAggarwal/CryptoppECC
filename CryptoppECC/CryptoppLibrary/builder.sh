#!/bin/bash

XCODE_ROOT=`xcode-select -print-path`
ARCHS="x86_64 i386 armv7 arm64"
SDK_VERSION=9.2

echo "min sdk version support:"
echo $SDK_VERSION
echo "pwd is"
echo $PWD

APPEND_PATH="CryptoppECC/CryptoppLibrary"

STATIC_ARCHIVES=""
for ARCH in ${ARCHS}
do
    PLATFORM=""
    if [ "${ARCH}" == "i386" ] || [ "${ARCH}" == "x86_64" ]; then
        PLATFORM="iPhoneSimulator"
    else
        PLATFORM="iPhoneOS"
    fi

    export DEV_ROOT="${XCODE_ROOT}/Platforms/${PLATFORM}.platform/Developer"
    export SDK_ROOT="${DEV_ROOT}/SDKs/${PLATFORM}${SDK_VERSION}.sdk"
    export TOOLCHAIN_ROOT="${XCODE_ROOT}/Toolchains/XcodeDefault.xctoolchain/usr/bin/"
    export CC="clang -arch $ARCH -fembed-bitcode"
    export CXX=clang++
    export AR=${TOOLCHAIN_ROOT}libtool
    export RANLIB=${TOOLCHAIN_ROOT}ranlib
    export ARFLAGS="-static -o"
    export LDFLAGS="-arch ${ARCH} -isysroot ${SDK_ROOT}"
    export BUILD_PATH="${APPEND_PATH}/BUILD_${ARCH}"
    export CXXFLAGS="-x c++ -arch ${ARCH} -isysroot ${SDK_ROOT} -I${BUILD_PATH} -miphoneos-version-min=7.0 -mios-simulator-version-min=7.0"
    mkdir -p ${BUILD_PATH}

    make -f Makefile

    mv ${APPEND_PATH}/*.o ${BUILD_PATH}
    mv ${APPEND_PATH}/*.d ${BUILD_PATH}
    mv ${APPEND_PATH}/libcryptopp.a ${BUILD_PATH}

    STATIC_ARCHIVES="${STATIC_ARCHIVES} ${BUILD_PATH}/libcryptopp.a"

done

echo "Creating universal library..."
mkdir -p bin
lipo -create ${STATIC_ARCHIVES} -output ${APPEND_PATH}/bin/libcryptopp.a

echo "removing thin archs"
for ARCH in ${ARCHS}
do

    directoryName="${APPEND_PATH}/BUILD_${ARCH}"
    rm -rf ${directoryName}

done

echo "Build done!"




