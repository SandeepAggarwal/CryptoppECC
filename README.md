# CryptoppECC for iOS and MacOSX
==================================
[![Cocoapods Compatible](https://img.shields.io/cocoapods/v/CryptoppECC.svg)](https://img.shields.io/cocoapods/v/CryptoppECC.svg)
[![Platform](https://img.shields.io/cocoapods/p/CryptoppECC.svg?style=flat)](http://cocoadocs.org/docsets/CryptoppECC)

CryptoppECC-Encryption/Decryption using ECC(Elliptic curve cryptography).


### Features

1. Also supports Verify the signed message using ECDSA
2. Compatible with Android's Bouncy Castle.

### Installation with CocoaPods

#### Podfile

```ruby
pod "CryptoppECC"

```

## Methods

### Encyption/Decryption

```objective-c
#import "CryptoppECC.h"
```

```objective-c
-(void)randomKeysEncryptDecrypt;

-(void)encrypt:(NSString*) public_point;

-(void)decrypt:(NSString*)private_point;

-(NSString*) decrypt:(NSString*) encryptedMessageInBase64 : (NSString*) privateKeyExponentInBase64 curve:(CurveType)curveType;

-(NSString*) encrypt:(NSString*) message : (NSString*) compressedPublicKeyPointInBase64 curve:(CurveType)curveType;

```

###Verify Signing

```objective-c
#import "CryptoppECDSA.h"
```


```objective-c
-(BOOL)verifyMessage:(NSString*)message signedCertificate:(NSString*)signedCertificateInBase64  compressedServerPublicPoint:(NSString*)compressedServerPublicPointInBase64  curve:(CurveType)curveType;
-(void)exampleVerify;
```

## Requirements

ViewPager supports minimum iOS 7 and minimum MacOSX 10.10 and uses ARC.


## Contact
[@sandeepCool77](https://twitter.com/sandeepCool77)

[Sandeep Aggarwal](mailto:smartsandeep1129@gmail.com)

## License

CryptoppECC is released under the MIT license. See LICENSE for details.
