//
//  Curve.h
//  Cryptopp-for-iOS
//
//  Created by Sandeep Aggarwal on 23/06/15.
//
//

#import <Foundation/Foundation.h>


typedef enum
{
    CurveType_secp112r1=1,
    CurveType_secp112r2,
    CurveType_secp128r1,
    CurveType_secp128r2,
    CurveType_secp160k1,
    CurveType_secp160r1,
    CurveType_secp160r2,
    CurveType_secp192k1,
    CurveType_secp192r1,
    CurveType_secp224k1,
    CurveType_secp224r1,
    CurveType_secp256k1,
    CurveType_secp256r1,
    CurveType_secp384r1,
    CurveType_secp521r1
    
}CurveType;


@interface Curve : NSObject

@end
