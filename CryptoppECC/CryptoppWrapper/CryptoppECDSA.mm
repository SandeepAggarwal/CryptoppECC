//
//  CryptoppECDSA.m
//  Cryptopp-for-iOS
//
//  Created by Sandeep Aggarwal on 14/06/15.


#import "CryptoppECDSA.h"
#import "luc.h"

#include <stdlib.h>

#include <sstream>
#include "hex.h"
#include "base64.h"
#include "dsa.h"

#include "filters.h"
#include "cryptlib.h"
#include <assert.h>

#include <iostream>
using std::cout;
using std::endl;

#include <string>
using std::string;

#include "osrng.h"
// using CryptoPP::AutoSeededX917RNG;
using CryptoPP::AutoSeededRandomPool;

#include "aes.h"
using CryptoPP::AES;

#include "integer.h"
using CryptoPP::Integer;

#include "sha.h"
using CryptoPP::SHA256;

#include "filters.h"
using CryptoPP::StringSource;
using CryptoPP::StringSink;
using CryptoPP::ArraySink;
using CryptoPP::SignerFilter;
using CryptoPP::SignatureVerificationFilter;

#include "files.h"
using CryptoPP::FileSource;
using CryptoPP::FileSink;

#include "eccrypto.h"
using CryptoPP::ECDSA;
using CryptoPP::ECP;
using CryptoPP::DL_GroupParameters_EC;



#include "oids.h"
using CryptoPP::OID;



@implementation CryptoppECDSA


std:: string decimalToBinary(size_t decimal)
{
    std::string binary = std::bitset<6>(decimal).to_string(); //to binary
    return binary;
}

std::string binaryToHex(std::string binaryString)
{
    static char hex[]="0123456789ABCDEF";
    std::string hexString;
    
    int multiplier=8;
    int accumulator=0;
    for(char c : binaryString)
    {
       
        if (c=='1')
        {
          accumulator+= multiplier;
        }
        multiplier/=2;
    }
    
    
    hexString.push_back(hex[accumulator]);
    return hexString;
}

- (NSString *)base64stringToHex:(NSString *)string
{
    //reference: http://stackoverflow.com/a/5533431/3632958
    std::string base64CharsString="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string inputString=[self cString:string];
    std::string binaryString="";
    
    size_t index;
    for(char& c : inputString)
    {
        index=base64CharsString.find_first_of(c);
        if (index!=string::npos)
        {
            binaryString+= decimalToBinary(index);
        }
    }
    std::string hexString="";
    
    int pointer=0;
    while (pointer<binaryString.length())
    {
       hexString+= binaryToHex(binaryString.substr(pointer,4));
       pointer+=4;
    }
    return [self objCString:hexString];
}


std::string removeLast(std::string x)
{
    std::string y;
    
    for(std::string::iterator i = x.begin(); i != x.end()-1; ++i)
        y.push_back(*i);
    
    return y;
}

-(BOOL)GeneratePrivateKey:(const CryptoPP:: OID&)oid  privateKey:(CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>:: PrivateKey&)key
{
    CryptoPP::AutoSeededRandomPool prng;
    
    key.Initialize( prng, oid );
    assert( key.Validate( prng, 3 ) );
    
    return key.Validate( prng, 3 );
}

-(BOOL)GeneratePublicKey: (const CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::PrivateKey&) privateKey publicKey:( CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::PublicKey&) publicKey
{
    CryptoPP::AutoSeededRandomPool prng;
    
    // Sanity check
    assert( privateKey.Validate( prng, 3 ) );
    
    privateKey.MakePublicKey(publicKey);
    assert( publicKey.Validate( prng, 3 ) );
    
    return publicKey.Validate( prng, 3 );
}



-(void)exampleVerify
{
    AutoSeededRandomPool prng;
    std::string hex_serverPublicKey="86FB5EB3CA0507226BE7197058B9EC041D3A3758D9D9C91902ACA3391F4E58AEF13AFF63CC4EF68942B9B94904DC1B890EDBEABD16B992110624968E894E560E";
    std::string hex_accessPointpublicKey="020000000000000001FFFFFFFFFFFFFFFE123456789ABCDEF000B3DA2000000100000300000003030003000300";
    
    std::string hex_signedCertificate="0199E984CEC75DDCA7F1DDF6E53E2E67352A2BE38A4B66F8ED596606FAB983FF300CAA76DE88CED9D563A5C03E8F3A7C000780F3F2061C611E9AA0B18B460D77";
    
    CryptoPP::HexDecoder hexDecoder;
    hexDecoder.Put((byte*)hex_serverPublicKey.data(), hex_serverPublicKey.size());
    hexDecoder.MessageEnd();
    

    
    ECP::Point q;
    size_t len =(size_t)hexDecoder.MaxRetrievable();
    
    
    q.identity = false;
    q.x.Decode(hexDecoder, len/2);
    q.y.Decode(hexDecoder, len/2);
    
    ECDSA<ECP, CryptoPP::SHA256>::PublicKey serverPublicKey;
    serverPublicKey.Initialize(CryptoPP::ASN1::secp256r1(), q);
    
    
    bool result = serverPublicKey.Validate( prng, 3 );
    if( result )
    {
        IFDBG(cout << "Validated public key" << endl);
    }
    else
    {
        std::cerr << "Failed to validate public key" << endl;
        exit(1);
    }
    
    const ECP::Point& qq = serverPublicKey.GetPublicElement();
    IFDBG(cout << "Q.x: " << std::hex << qq.x << endl);
    IFDBG(cout << "Q.y: " << std::hex << qq.y << endl);
    
    
    
    
    string accessPointPublicKey, signedCertificate;
    

    hexDecoder.Detach(new StringSink(accessPointPublicKey));
    hexDecoder.Put((byte*)hex_accessPointpublicKey.data(), hex_accessPointpublicKey.size());
    hexDecoder.MessageEnd();
    
    hexDecoder.Detach(new StringSink(signedCertificate));
    hexDecoder.Put((byte*)hex_signedCertificate.data(), hex_signedCertificate.size());
    hexDecoder.MessageEnd();
    
    ECDSA<ECP, CryptoPP::SHA256>::Verifier verifier(serverPublicKey);
    result = verifier.VerifyMessage((byte*)accessPointPublicKey.data(), accessPointPublicKey.size(), (byte*)signedCertificate.data(), signedCertificate.size());
    
    if( result )
    {
        IFDBG(cout << "Verified message" << endl);
    }
    else
    {
        std::cerr << "Failed to verify message" << endl;
        exit(1);
    }

    
}

-(BOOL)verifyMessage:(NSString*)message signedCertificate:(NSString*)signedCertificateInBase64  compressedServerPublicPoint:(NSString*)compressedServerPublicPointInBase64  curve:(CurveType)curveType
{
    CryptoPP::OID curve;
    switch (curveType)
    {
        case CurveType_secp112r1:
            curve=CryptoPP::ASN1::secp112r1();
            break;
            
        case CurveType_secp112r2:
            curve=CryptoPP::ASN1::secp112r2();
            break;
            
        case CurveType_secp128r1:
            curve=CryptoPP::ASN1::secp128r1();
            break;
            
        case CurveType_secp128r2:
            curve=CryptoPP::ASN1::secp128r2();
            break;
            
        case CurveType_secp160k1:
            curve=CryptoPP::ASN1::secp160k1();
            break;
            
        case CurveType_secp160r1:
            curve=CryptoPP::ASN1::secp160r1();
            break;
            
        case CurveType_secp160r2:
            curve=CryptoPP::ASN1::secp160r2();
            break;
            
        case CurveType_secp192k1:
            curve=CryptoPP::ASN1::secp192k1();
            break;
            
        case CurveType_secp192r1:
            curve=CryptoPP::ASN1::secp192r1();
            break;
            
        case CurveType_secp224k1:
            curve=CryptoPP::ASN1::secp224k1();
            break;
            
        case CurveType_secp224r1:
            curve=CryptoPP::ASN1::secp224r1();
            break;
            
        case CurveType_secp256k1:
            curve=CryptoPP::ASN1::secp256k1();
            break;
            
        case CurveType_secp256r1:
            curve=CryptoPP::ASN1::secp256r1();
            break;
            
        case CurveType_secp384r1:
            curve=CryptoPP::ASN1::secp384r1();
            break;
            
        case CurveType_secp521r1:
            curve=CryptoPP::ASN1::secp521r1();
            break;
            
        default:
            break;
    }
    
    AutoSeededRandomPool prng;
    std::string c_compressedServerPublicPointInBase64=[self cString:compressedServerPublicPointInBase64];
    IFDBG(cout<<"\n\ncompressed pub key: "<<c_compressedServerPublicPointInBase64<<endl);
    std::string c_unCompressedServerPublicPointInHex=[self getHexUnCompressedPublicPoint:c_compressedServerPublicPointInBase64 curve:curve];
    IFDBG(cout<<"\n\nuncompressed pub key: "<<c_unCompressedServerPublicPointInHex<<endl);
    
    std::string c_signedCertificateInBase64=[self cString:signedCertificateInBase64];
    
    
    std::string  c_signedCertificateInHex= [self get_ASN1_string_from_DER_string:c_signedCertificateInBase64];
    IFDBG(cout<<"\n\nsigned cert base 64: "<<c_signedCertificateInBase64<<endl);
    IFDBG(cout<<"\n\nsigned cert hex: "<<c_signedCertificateInHex<<endl);
    
    if (c_signedCertificateInHex.empty())
    {
        IFDBG(cout<<"invalid signed certifcate");
        return NO;
    }
    
    std::string c_message=[self cString:message];
   
    IFDBG(cout<<"\n\nmessage base 64: "<<c_message<<endl);
    CryptoPP::HexDecoder hexDecoder;
    hexDecoder.Put((byte*)c_unCompressedServerPublicPointInHex.data(), c_unCompressedServerPublicPointInHex.size());
    hexDecoder.MessageEnd();
    
    ECP::Point q;
    unsigned long long len = hexDecoder.MaxRetrievable();
    q.identity = false;
    q.x.Decode(hexDecoder, (size_t)len/2);
    q.y.Decode(hexDecoder, (size_t)len/2);
    
    ECDSA<ECP, CryptoPP::SHA256>::PublicKey serverPublicKey;
    serverPublicKey.Initialize(curve, q);
    
    bool result = serverPublicKey.Validate( prng, 3 );
    if( result )
    {
        IFDBG(cout << "Validated public key" << endl);
    }
    else
    {
        std::cerr << "Failed to validate public key" << endl;
        return NO;
    }
    
    string  signedCertificate;

    hexDecoder.Detach(new StringSink(signedCertificate));
    hexDecoder.Put((byte*)c_signedCertificateInHex.data(), c_signedCertificateInHex.size());
    hexDecoder.MessageEnd();
    
    ECDSA<ECP, CryptoPP::SHA256>::Verifier verifier(serverPublicKey);
    result = verifier.VerifyMessage((byte*)c_message.data(), c_message.size(), (byte*)signedCertificate.data(), signedCertificate.size());
    
    
    if( result )
    {
        IFDBG(cout << "Verified message" << endl);
        return YES;
    }
    else
    {
        std::cerr << "Failed to verify message" << endl;
        return NO;
    }

}

/** converts objc string to c string**/
-(std::string)cString:(NSString*)string
{
    return [string cStringUsingEncoding:NSUTF8StringEncoding];
}

/** converts c string to  objc string**/
-(NSString*)objCString:(std::string)string
{
    return [NSString stringWithCString:string.c_str()
                              encoding:[NSString defaultCStringEncoding]];
}




/** get ASN1 String from DER format string**/
-(std::string)get_ASN1_string_from_DER_string:(std::string)DER_stringInBase64
{
  //reference : http://stackoverflow.com/a/18350709/3632958
    std::string ASN1_string;
    
    std::string DER_stringInHex=[self cString:[self base64stringToHex:[self objCString:DER_stringInBase64]]];
    
    
    std::string prefix="30";
    if(DER_stringInHex.substr(0,prefix.size())!=prefix)
    {
        //not an ASN1 Sequence
        IFDBG(cout<<"not begins with 30");
        return "";
    }
    
    //first part of string - r
    std::string indicateFirstItemInteger="02";
    
    int stringPointer=4;
    
    if (DER_stringInHex.substr(stringPointer,indicateFirstItemInteger.size())!=indicateFirstItemInteger)
    {
        //something wrong
        IFDBG(cout<<"first integer missing of first string");
        return "";
    }
    stringPointer+=indicateFirstItemInteger.size(); //update the pointer
    unsigned int firstItemSize;
    std::stringstream ss;
    ss << std::hex << DER_stringInHex.substr(stringPointer,2);
    ss >> firstItemSize;
    
    firstItemSize=2*firstItemSize;
    
    stringPointer+=2;  //update the pointer
    std::string firstItemString= DER_stringInHex.substr(stringPointer,firstItemSize);
    
    //trim zeros
    if (firstItemString.substr(0,2)=="00")
    {
        firstItemString=firstItemString.substr(2);
    }
  
    
    //second part of string - s
    stringPointer+=firstItemSize;                     //update the pointer
    std::string indicateSecondItemInteger="02";
    if (DER_stringInHex.substr(stringPointer,indicateSecondItemInteger.size())!=indicateSecondItemInteger)
    {
        //something wrong
        IFDBG(cout<<"first integer missing of second string");
        return "";
    }
    
    stringPointer+=indicateSecondItemInteger.size();  //update the pointer
    unsigned int secondItemSize;
    std::stringstream ss1;
    ss1 << std::hex << DER_stringInHex.substr(stringPointer,2);
    ss1 >> secondItemSize;
    
    secondItemSize=2*secondItemSize;
    stringPointer+=2;    //update the pointer
    std::string secondItemString= DER_stringInHex.substr(stringPointer,secondItemSize);
    //trim zeros
    if (secondItemString.substr(0,2)=="00")
    {
        secondItemString=secondItemString.substr(2);
    }
  
    
    ASN1_string=  firstItemString+secondItemString;
    return ASN1_string;
}

/** get uncompressed public point from compressed public point **/
-(std::string)getHexUnCompressedPublicPoint:(std::string)compressedPublicKeyPointInBase64 curve:(CryptoPP::OID)curve
{
    StringSource ss(compressedPublicKeyPointInBase64, true, new CryptoPP::Base64Decoder);
    
    CryptoPP::ECIES_BC<CryptoPP::ECP>::Encryptor encryptor;
    encryptor.AccessKey().AccessGroupParameters().Initialize(curve);
    
    //get point on the used curve
    ECP::Point point;
    encryptor.GetKey().GetGroupParameters().GetCurve().DecodePoint(point, ss, (size_t)ss.MaxRetrievable());
    std::stringstream pointXStringStream, pointYStringStream;
    
    pointXStringStream<<std::hex<<point.x;
    pointYStringStream<<std::hex<<point.y;
    
    std::string pointXString=string(pointXStringStream.str());
    std::string pointYString=string(pointYStringStream.str());
    
    
    //trim  hexadecimal's 'h if present'
    if (pointXString.find_last_of("h")!=string::npos)
    {
        pointXString= removeLast(pointXString);
    }
    if (pointYString.find_last_of("h")!=string::npos)
    {
        pointYString= removeLast(pointYString);
    }
    
    //set the number of characters in 'x' and 'y' strings to be even
    if (pointXString.length()%2!=0)
    {
        pointXString='0'+pointXString;
    }
    if (pointYString.length()%2!=0)
    {
        pointYString='0'+pointYString;
    }
    
    NSLog(@"\n\nx: %s \nx length:%lu \n y: %s\n y length: %lu",pointXString.c_str(),pointXString.length(), pointYString.c_str(),pointYString.length());
    
    std::string unCompressedPublicPoint=pointXString+pointYString;
    
    //set the number of characters in 'unCompressedPublicPoint' string
    if (unCompressedPublicPoint.length()%2!=0)
    {
        unCompressedPublicPoint='0'+unCompressedPublicPoint;
    }
    NSLog(@"uncompressed public point: %s and its length: %lu",unCompressedPublicPoint.c_str(),unCompressedPublicPoint.length());
    
    return unCompressedPublicPoint;
    
}

@end
