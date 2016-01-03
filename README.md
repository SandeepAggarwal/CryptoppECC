====================
# CryptoppECC
====================
[![Build Status](https://travis-ci.org/CryptoppECC/CryptoppECC.svg)](https://travis-ci.org/CryptoppECC/CryptoppECC)
[![codecov.io](https://codecov.io/github/CryptoppECC/CryptoppECC/coverage.svg?branch=master)](https://codecov.io/github/CryptoppECC/CryptoppECC?branch=master)
[![Cocoapods Compatible](https://img.shields.io/cocoapods/v/CryptoppECC.svg)](https://img.shields.io/cocoapods/v/CryptoppECC.svg)
[![Platform](https://img.shields.io/cocoapods/p/CryptoppECC.svg?style=flat)](http://cocoadocs.org/docsets/CryptoppECC)

CryptoppECC-Encryption/Decryption using ECC(Elliptic curve cryptography)

### Installation with CocoaPods

#### Podfile

```ruby
platform :ios, '7.0'
pod "CryptoppECC

## Methods

###Encyption/Decryption

```objective-c
-(void)randomKeysEncryptDecrypt;

-(void)encrypt:(NSString*) public_point;

-(void)decrypt:(NSString*)private_point;

-(NSString*) decrypt:(NSString*) encryptedMessageInBase64 : (NSString*) privateKeyExponentInBase64 curve:(CurveType)curveType;

-(NSString*) encrypt:(NSString*) message : (NSString*) compressedPublicKeyPointInBase64 curve:(CurveType)curveType;

```

###Verify Signing

```objective-c
-(BOOL)verifyMessage:(NSString*)message signedCertificate:(NSString*)signedCertificateInBase64  compressedServerPublicPoint:(NSString*)compressedServerPublicPointInBase64  curve:(CurveType)curveType;
-(void)exampleVerify;
```


## Contact
[@sandeepCool77](https://twitter.com/sandeepCool77)

[Sandeep Aggarwal](mailto:smartsandeep1129@gmail.com)

## License

CryptoppECC is released under the MIT license. See LICENSE for details.
