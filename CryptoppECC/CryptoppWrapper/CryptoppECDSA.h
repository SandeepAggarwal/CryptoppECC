//
//  CryptoppECDSA.h
//  Cryptopp-for-iOS
//
//  Created by Sandeep Aggarwal on 14/06/15.
//
//

#import <Foundation/Foundation.h>
#import "Curve.h"


@interface CryptoppECDSA : NSObject

-(BOOL)verifyMessage:(NSString*)message signedCertificate:(NSString*)signedCertificateInBase64  compressedServerPublicPoint:(NSString*)compressedServerPublicPointInBase64  curve:(CurveType)curveType;
-(void)exampleVerify;
@end
