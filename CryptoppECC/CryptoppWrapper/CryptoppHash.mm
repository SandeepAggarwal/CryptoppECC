//
//  CryptoppHash.h
//  Cryptopp-for-iOS
//
//  Created by TAKEDA hiroyuki(aka @3ign0n) on 11/12/23.
//

#import "CryptoppHash.h"
#include "md5.h"
#include "sha.h"


@implementation CryptoppMD5
-(NSData*)getHashValue:(NSData*)data {
    CryptoPP::MD5 md5;
    byte digest[ CryptoPP::MD5::DIGESTSIZE ];
    
    md5.CalculateDigest(digest, (const byte*)[data bytes], [data length]);
    
    NSData * hashVale = [NSData dataWithBytes:digest length:sizeof digest];
    return hashVale;
}
@end


@interface CryptoppSHA()
@property (nonatomic, assign, readwrite) NSInteger length;
@end

@implementation CryptoppSHA
@synthesize length = _length;

- (id)initWithLength:(CryptppSHALength)length {
    self = [super init];
    if (self) {
        self.length = length;
    }
    return self;
}

-(NSData*)getHashValue:(NSData*)data {
    NSData * hashValue = nil;
    if (self.length == CryptppSHALength1) {
        CryptoPP::SHA1 sha;
        byte digest[ CryptoPP::SHA1::DIGESTSIZE ];
        sha.CalculateDigest(digest, (const byte*)[data bytes], [data length]);
        hashValue = [NSData dataWithBytes:digest length:sizeof digest];
    } else if (self.length == CryptppSHALength256) {
        CryptoPP::SHA256 sha;
        byte digest[ CryptoPP::SHA256::DIGESTSIZE ];
        sha.CalculateDigest(digest, (const byte*)[data bytes], [data length]);
        hashValue = [NSData dataWithBytes:digest length:sizeof digest];
    } else if (self.length == CryptppSHALength512) {
        CryptoPP::SHA512 sha;
        byte digest[ CryptoPP::SHA512::DIGESTSIZE ];
        sha.CalculateDigest(digest, (const byte*)[data bytes], [data length]);
        hashValue = [NSData dataWithBytes:digest length:sizeof digest];
    } else {
        NSLog(@"unknown hash length");
    }
    return hashValue;
}
@end
