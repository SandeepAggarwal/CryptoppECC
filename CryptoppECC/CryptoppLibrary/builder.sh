#!/bin/bash

cd CryptoppECC/CryptoppLibrary

XCODE_ROOT=`xcode-select -print-path`

echo "making for iOS"
ARCHS="x86_64 i386 armv7 arm64"
SDK_VERSION=`xcrun --sdk iphoneos --show-sdk-version 2> /dev/null`
MIN_SDK_VERSION=7.0


echo "sdk version is: "
echo ${SDK_VERSION}

IOS_STATIC_ARCHIVES=""
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
    export BUILD_PATH="IOS_BUILD_${ARCH}"
    export CXXFLAGS="-x c++ -arch ${ARCH} -isysroot ${SDK_ROOT} -I${BUILD_PATH} -miphoneos-version-min=${MIN_SDK_VERSION} -mios-simulator-version-min=${MIN_SDK_VERSION}"

    mkdir -pv ${BUILD_PATH}
    make -f Makefile
    mv *.o ${BUILD_PATH}
    mv *.d ${BUILD_PATH}
    mv libcryptopp.a ${BUILD_PATH}

    IOS_STATIC_ARCHIVES="${IOS_STATIC_ARCHIVES} ${BUILD_PATH}/libcryptopp.a"

done

echo "Creating universal library..."
 mkdir -p bin/ios
 lipo -create ${IOS_STATIC_ARCHIVES} -output bin/ios/libcryptopp.a

echo "removing thin archs"
for ARCH in ${ARCHS}
do

    directoryName=IOS_BUILD_${ARCH}
    rm -rf ${directoryName}

done


############################################################
echo "making for macOSX"
ARCHS="x86_64 i386"
SDK_VERSION=`xcrun --sdk macosx --show-sdk-version 2> /dev/null`
MIN_SDK_VERSION=10.10
PLATFORM="MacOSX"


echo "sdk version is: "
echo ${SDK_VERSION}


MACOSX_STATIC_ARCHIVES=""
for ARCH in ${ARCHS}
do

export DEV_ROOT="${XCODE_ROOT}/Platforms/${PLATFORM}.platform/Developer"
export SDK_ROOT="${DEV_ROOT}/SDKs/${PLATFORM}${SDK_VERSION}.sdk"
export TOOLCHAIN_ROOT="${XCODE_ROOT}/Toolchains/XcodeDefault.xctoolchain/usr/bin/"
export CC="clang -arch $ARCH -fembed-bitcode"
export CXX=clang++
export AR=${TOOLCHAIN_ROOT}libtool
export RANLIB=${TOOLCHAIN_ROOT}ranlib
export ARFLAGS="-static -o"
export LDFLAGS="-arch ${ARCH} -isysroot ${SDK_ROOT}"
export BUILD_PATH="MACOSX_BUILD_${ARCH}"
export CXXFLAGS="-x c++ -arch ${ARCH} -isysroot ${SDK_ROOT} -I${BUILD_PATH} -mmacosx-version-min=${MIN_SDK_VERSION}"

mkdir -pv ${BUILD_PATH}
make -f Makefile
mv *.o ${BUILD_PATH}
mv *.d ${BUILD_PATH}
mv libcryptopp.a ${BUILD_PATH}

MACOSX_STATIC_ARCHIVES="${MACOSX_STATIC_ARCHIVES} ${BUILD_PATH}/libcryptopp.a"

done

echo "Creating universal library..."
mkdir -p bin/macosx
lipo -create ${MACOSX_STATIC_ARCHIVES} -output bin/macosx/libcryptopp.a

echo "removing thin archs"
for ARCH in ${ARCHS}
do

directoryName=MACOSX_BUILD_${ARCH}
rm -rf ${directoryName}

done

echo "Build done!"
