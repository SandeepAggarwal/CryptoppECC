//
//  CryptoppECC.h
//  Cryptopp-for-iOS
//
//  Created by Sandeep Aggarwal on 14/06/15.
//
//



#import <Foundation/Foundation.h>
#import "Curve.h"


@interface CryptoppECC : NSObject

-(void)randomKeysEncryptDecrypt;
-(void)encrypt:(NSString*) public_point;
-(void)decrypt:(NSString*)private_point;

-(NSString*) decrypt:(NSString*) encryptedMessageInBase64 : (NSString*) privateKeyExponentInBase64 curve:(CurveType)curveType;
-(NSString*) encrypt:(NSString*) message : (NSString*) compressedPublicKeyPointInBase64 curve:(CurveType)curveType;

@end
    

