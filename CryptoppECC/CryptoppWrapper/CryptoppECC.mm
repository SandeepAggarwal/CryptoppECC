//
//  CryptoppECC.m
//  Cryptopp-for-iOS
//
//  Created by Sandeep Aggarwal on 14/06/15.
//
//

#import "CryptoppECC.h"
#import "base64.h"



#include <iostream>
using std::ostream;
using std::cout;
using std::endl;

#include <string>
using std::string;

#include "files.h"
using CryptoPP::FileSink;
using CryptoPP::FileSource;

#include "hex.h"
using CryptoPP::HexEncoder;

#include "filters.h"
using CryptoPP::StringSink;
using CryptoPP::StringSource;
using CryptoPP::PK_EncryptorFilter;
using CryptoPP::PK_DecryptorFilter;

#include "osrng.h"
using CryptoPP::AutoSeededRandomPool;

#include "integer.h"
using CryptoPP::Integer;

#include "pubkey.h"
using CryptoPP::PublicKey;
using CryptoPP::PrivateKey;

#include "eccrypto.h"
using CryptoPP::ECP;    // Prime field
using CryptoPP::EC2N;   // Binary field
using CryptoPP::ECIES;
using CryptoPP::ECPPoint;
using CryptoPP::DL_GroupParameters_EC;
using CryptoPP::DL_GroupPrecomputation;
using CryptoPP::DL_FixedBasePrecomputation;

#include "pubkey.h"
using CryptoPP::DL_PrivateKey_EC;
using CryptoPP::DL_PublicKey_EC;

#include "asn.h"
#include "oids.h"
namespace ASN1 = CryptoPP::ASN1;

#include "cryptlib.h"
using CryptoPP::PK_Encryptor;
using CryptoPP::PK_Decryptor;
using CryptoPP::g_nullNameValuePairs;




void PrintPrivateKey(const DL_PrivateKey_EC<ECP>& key, ostream& out = cout);
void PrintPublicKey(const DL_PublicKey_EC<ECP>& key, ostream& out = cout);

std::string base64_encode(unsigned char const* , unsigned int len);
std::string base64_decode(std::string const& s);

static const string message("e8e5896b6940fbf4a8f3a107ff58e63b25353739");

@implementation CryptoppECC


static const std::string base64_chars =
"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
"abcdefghijklmnopqrstuvwxyz"
"0123456789+/";

static inline bool is_base64(unsigned char c)
{
    return (isalnum(c) || (c == '+') || (c == '/'));
}

std::string base64_encode(unsigned char const* bytes_to_encode, unsigned int in_len)
{
    std::string ret;
    int i = 0;
    int j = 0;
    unsigned char char_array_3[3];
    unsigned char char_array_4[4];
    
    while (in_len--) {
        char_array_3[i++] = *(bytes_to_encode++);
        if (i == 3) {
            char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
            char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
            char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
            char_array_4[3] = char_array_3[2] & 0x3f;
            
            for(i = 0; (i <4) ; i++)
                ret += base64_chars[char_array_4[i]];
            i = 0;
        }
    }
    
    if (i)
    {
        for(j = i; j < 3; j++)
            char_array_3[j] = '\0';
        
        char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
        char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
        char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
        char_array_4[3] = char_array_3[2] & 0x3f;
        
        for (j = 0; (j < i + 1); j++)
            ret += base64_chars[char_array_4[j]];
        
        while((i++ < 3))
            ret += '=';
        
    }
    
    return ret;
    
}

std::string base64_decode(std::string const& encoded_string)
{
    size_t in_len = encoded_string.size();
    int i = 0;
    int j = 0;
    int in_ = 0;
    unsigned char char_array_4[4], char_array_3[3];
    std::string ret;
    
    while (in_len-- && ( encoded_string[in_] != '=') && is_base64(encoded_string[in_])) {
        char_array_4[i++] = encoded_string[in_]; in_++;
        if (i ==4) {
            for (i = 0; i <4; i++)
                char_array_4[i] = base64_chars.find(char_array_4[i]);
            
            char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
            char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
            char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];
            
            for (i = 0; (i < 3); i++)
                ret += char_array_3[i];
            i = 0;
        }
    }
    
    if (i) {
        for (j = i; j <4; j++)
            char_array_4[j] = 0;
        
        for (j = 0; j <4; j++)
            char_array_4[j] = base64_chars.find(char_array_4[j]);
        
        char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
        char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
        char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];
        
        for (j = 0; (j < i - 1); j++) ret += char_array_3[j];
    }
    
    return ret;
}


-(std::string)cString:(NSString*)string
{
    if (string.length)
    {
      return [string cStringUsingEncoding:NSUTF8StringEncoding];
    }
    else
    {
        return "";
    }
    
}

-(NSString*)objCString:(std::string)string
{
    if (string.length())
    {
        return [NSString stringWithCString:string.c_str()
                                  encoding:[NSString defaultCStringEncoding]];
    }
    else
    {
        return @"";
    }
}



-(void)randomKeysEncryptDecrypt //random gen of keys
{
    AutoSeededRandomPool prng;
    
    //get private key generated
    CryptoPP::ECIES_BC<CryptoPP::ECP>::Decryptor d0(prng,ASN1::secp112r1());
    PrintPrivateKey(d0.GetKey());
    
    //get public key
    CryptoPP::ECIES_BC<CryptoPP::ECP>::Encryptor e0(d0);
    PrintPublicKey(e0.GetKey());
    
    //encrypt the message
    string em0; // encrypted message
    StringSource ss1 (message, true, new PK_EncryptorFilter(prng, e0, new StringSink(em0) ) );
    
    //decrypt the message
    string dm0; // decrypted message
    StringSource ss2 (em0, true, new PK_DecryptorFilter(prng, d0, new StringSink(dm0)) );
}

-(void)cEncrypt:(std::string) public_point //best working code for public key
{
    try
    {
        AutoSeededRandomPool prng;
        
        //public key is a point consisting of "public key point x" and "public key point y"
        //compressed public key also known as "public-point" formed using point-compression of public key
        
        
        //since the key is in base-64 format use Base64Decoder
        StringSource ss(public_point, true, new CryptoPP::Base64Decoder);
        
        
        
        CryptoPP::ECIES_BC<CryptoPP::ECP>::Encryptor encryptor;
        
        //curve used is secp256k1
        encryptor.AccessKey().AccessGroupParameters().Initialize(ASN1::secp256k1());
        
        //get point on the used curve
        ECP::Point point;
        encryptor.GetKey().GetGroupParameters().GetCurve().DecodePoint(point, ss, (size_t)ss.MaxRetrievable());
       IFDBG(cout << "X: " << std::hex << point.x << endl);
       IFDBG(cout << "Y: " << std::hex << point.y << endl);
        
        //set encryptor's public element
        encryptor.AccessKey().SetPublicElement(point);
        
        //check whether the encryptor's access key thus formed is valid or not
        encryptor.AccessKey().ThrowIfInvalid(prng, 3);
        
        PrintPublicKey(encryptor.GetKey());
        
        
        string em0; // encrypted message
        StringSource ss1(message, true, new PK_EncryptorFilter(prng, encryptor, new StringSink(em0) ) );
        IFDBG(cout<<"encrypted msg: "<<em0<<"  and its length: "<<em0.length()<<endl);
    }
    catch(const CryptoPP::Exception& ex)
    {
        std::cerr << ex.what() << endl;
    }
    
    
}

-(void)cDecrypt :(std::string) exponent//best working code for private key
{
   
    try
    {
        AutoSeededRandomPool prng;
        
        /**use this **/
        
        
        //since the key is in base-64 format use Base64Decoder
        StringSource ss(exponent, true , new CryptoPP::Base64Decoder);
        
      
        
        Integer x;
        x.Decode(ss, (size_t)ss.MaxRetrievable(), Integer::UNSIGNED);
        
        
        
        CryptoPP::ECIES_BC<CryptoPP::ECP>::Decryptor decryptor;
        
        //curve used is secp256k1
        //make decryptor's access key using decoded private exponent's value
        decryptor.AccessKey().Initialize(ASN1::secp256k1(), x);
        
        /* or this
         
         CryptoPP::Base64Decoder decoder;
         decoder.Put((byte*)exponent.data(), exponent.size());
         decoder.MessageEnd();
         
         Integer x;
         x.Decode(decoder, decoder.MaxRetrievable());
         
         CryptoPP::ECIES_BC<CryptoPP::ECP>::Decryptor decryptor;
         decryptor.AccessKey().Initialize(ASN1::secp256k1(), x);
         */
        
        
        
        
        //check whether decryptor's access key is valid or not
        bool valid = decryptor.AccessKey().Validate(prng, 3);
        if(!valid)
            decryptor.AccessKey().ThrowIfInvalid(prng, 3);
        
        IFDBG(cout << "Exponent is valid for P-256k1" << endl);
        
        PrintPrivateKey(decryptor.GetKey());
        
        
        //get public key from 'decryptor'
        CryptoPP::ECIES_BC<CryptoPP::ECP>::Encryptor encryptor(decryptor);
        PrintPublicKey(encryptor.GetKey());
        
        
        // encrypt the message using public key
        string em0;
        StringSource ss1(message, true, new PK_EncryptorFilter(prng, encryptor, new StringSink(em0) ) );
        IFDBG(cout<<"encrypted msg: "<<em0<<"  and its length: "<<em0.length()<<endl);
        
        
        //decrypt the message using private key
        string dm0;
        StringSource ss2 (em0, true, new PK_DecryptorFilter(prng, decryptor, new StringSink(dm0) ) );
        IFDBG(cout <<"decrypted msg: "<< dm0<<"  and its length: "<<dm0.length() << endl);
        
    }
    catch(const CryptoPP::Exception& ex)
    {
        std::cerr << ex.what() << endl;
    }
    
}


-(void)encrypt:(NSString*)public_point
{
    
    [self cEncrypt:[self cString:public_point]];
}


-(void)decrypt:(NSString*)private_point
{
   
    [self cDecrypt:[self cString:private_point]];
}


//this will be used for decryption
string cDecrypt(std::string encryptedMessageInBase64 ,  std::string  privateKeyExponentInBase64 ,CryptoPP::OID curve)
{
    IFDBG(cout<<"input encrypted msg in base 64: "<<encryptedMessageInBase64<<"  and its length: "<<encryptedMessageInBase64.length()<<endl);
    encryptedMessageInBase64=base64_decode(encryptedMessageInBase64);
   
    string decryptedMessage;
    try
    {
        AutoSeededRandomPool prng;
        
        //since the 'privateKeyExponent' is in base-64 format use Base64Decoder
        StringSource ss(privateKeyExponentInBase64, true /*pumpAll*/, new CryptoPP::Base64Decoder);
        
        Integer x;
        x.Decode(ss, (size_t)ss.MaxRetrievable(), Integer::UNSIGNED);
      
        
        CryptoPP::ECIES_BC<CryptoPP::ECP>::Decryptor decryptor;
        
        //curve used is secp256k1
        //make decryptor's access key using decoded private exponent's value
        decryptor.AccessKey().Initialize(curve, x);
        
        //check whether decryptor's access key is valid or not
        bool valid = decryptor.AccessKey().Validate(prng, 3);
        if(!valid)
        {
            IFDBG(cout<<"invalid private key exponent");
            return "";
        }
        IFDBG(cout<<"\n\ndecryption algo. name "<<decryptor.StaticAlgorithmName());
        //decrypt the message using private key
        IFDBG(cout<<"\n\nparam spec in decrypt: "<<prng.GenerateWord32());
        StringSource ss2 (encryptedMessageInBase64, true, new PK_DecryptorFilter(prng, decryptor, new StringSink(decryptedMessage) ) );
        IFDBG(cout <<"\n\ndecrypted msg: "<< decryptedMessage<<"  and its length: "<<decryptedMessage.length() << endl);
        
    }
    catch(const CryptoPP::Exception& ex)
    {
        std::cerr << ex.what() << endl;
        return "";
    }
    return decryptedMessage;
}


//this will be used for encryption
string CEncrypt(std::string message ,  std::string  compressedPublicKeyPointInBase64 , CryptoPP::OID curve )
{
    string encryptedMessage;
    try
    {
        AutoSeededRandomPool prng;
        
        //public key is a point consisting of "public key point x" and "public key point y"
        //compressed public key also known as "public-point" formed using point-compression of public key
        
        
        //since the key is in base-64 format use Base64Decoder
        StringSource ss(compressedPublicKeyPointInBase64, true, new CryptoPP::Base64Decoder);
        
        CryptoPP::ECIES_BC<CryptoPP::ECP>::Encryptor encryptor;
        
        encryptor.AccessKey().AccessGroupParameters().Initialize(curve);
        
        //get point on the used curve
        ECP::Point point;
        encryptor.GetKey().GetGroupParameters().GetCurve().DecodePoint(point, ss, (unsigned long)ss.MaxRetrievable());

        
        //set encryptor's public element
        encryptor.AccessKey().SetPublicElement(point);
        
        //check whether the encryptor's access key thus formed is valid or not
        if (!encryptor.AccessKey().Validate(prng, 3))
        {
            IFDBG(cout<<"invalid public key");
            return "";
        }
        // encrypted message
        StringSource ss1(message, true, new PK_EncryptorFilter(prng, encryptor, new StringSink(encryptedMessage) ) );
        IFDBG(cout<<"\n\nencryption algo. name "<<encryptor.StaticAlgorithmName());
       
    }
    catch(const CryptoPP::Exception& ex)
    {
        std::cerr << ex.what() << endl;
        return "";
    }
    IFDBG(cout<<"\n\nencrypted msg b4: "<<encryptedMessage<<endl);
    encryptedMessage= base64_encode(reinterpret_cast<const unsigned char*>(encryptedMessage.c_str()), (unsigned int)encryptedMessage.length());
    
    return encryptedMessage;
}

-(CryptoPP::OID)curve:(CurveType)curveType
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
    return curve;
}
-(NSString*) decrypt:(NSString*) encryptedMessageInBase64 : (NSString*) privateKeyExponentInBase64 curve:(CurveType)curveType
{
    return [self objCString:(cDecrypt([self cString:encryptedMessageInBase64], [self cString:privateKeyExponentInBase64] ,[self curve:curveType]))];
}

-(NSString*) encrypt:(NSString*) message : (NSString*) compressedPublicKeyPointInBase64 curve:(CurveType)curveType
{
    
    return [self objCString:(CEncrypt([self cString:message], [self cString:compressedPublicKeyPointInBase64],[self curve:curveType]))];
}


void PrintPrivateKey(const DL_PrivateKey_EC<ECP>& key, ostream& out)
{
    const std::ios_base::fmtflags flags = out.flags();
    
    // Group parameters
    const DL_GroupParameters_EC<ECP>& params = key.GetGroupParameters();
    // Base precomputation
    const DL_FixedBasePrecomputation<ECPPoint>& bpc = params.GetBasePrecomputation();
    // Public Key (just do the exponentiation)
    const ECPPoint point = bpc.Exponentiate(params.GetGroupPrecomputation(), key.GetPrivateExponent());
    
    out << "Modulus: " << std::hex << params.GetCurve().GetField().GetModulus() << endl;
    out << "Cofactor: " << std::hex << params.GetCofactor() << endl;
    
    out << "Coefficients" << endl;
    out << "  A: " << std::hex << params.GetCurve().GetA() << endl;
    out << "  B: " << std::hex << params.GetCurve().GetB() << endl;
    
    out << "Base Point" << endl;
    out << "  x: " << std::hex << params.GetSubgroupGenerator().x << endl;
    out << "  y: " << std::hex << params.GetSubgroupGenerator().y << endl;
    
    out << "Public Point" << endl;
    out << "  x: " << std::hex << point.x << endl;
    out << "  y: " << std::hex << point.y << endl;
  
    
    out << "Private Exponent (multiplicand): " << endl;
    out << "  " << std::hex << key.GetPrivateExponent() << endl;
    
    out << endl;
    out.flags(flags);
}

void PrintPublicKey(const DL_PublicKey_EC<ECP>& key, ostream& out)
{
    const std::ios_base::fmtflags flags = out.flags();
    
    // Group parameters
    const DL_GroupParameters_EC<ECP>& params = key.GetGroupParameters();
    // Public key
    const ECPPoint& point = key.GetPublicElement();
    
    out << "Modulus: " << std::hex << params.GetCurve().GetField().GetModulus() << endl;
    out << "Cofactor: " << std::hex << params.GetCofactor() << endl;
    
    out << "Coefficients" << endl;
    out << "  A: " << std::hex << params.GetCurve().GetA() << endl;
    out << "  B: " << std::hex << params.GetCurve().GetB() << endl;
    
    out << "Base Point" << endl;
    out << "  x: " << std::hex << params.GetSubgroupGenerator().x << endl;
    out << "  y: " << std::hex << params.GetSubgroupGenerator().y << endl;
    
    out << "Public Point" << endl;
    out << "  x: " << std::hex << point.x << endl;
    out << "  y: " << std::hex << point.y << endl;
    
    out << endl;
    out.flags(flags);
}






@end
