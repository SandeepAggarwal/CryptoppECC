package com.cmm.UtilityClasses;

import android.util.Base64;

import org.spongycastle.jcajce.provider.asymmetric.util.EC5Util;
import org.spongycastle.jce.ECNamedCurveTable;
import org.spongycastle.jce.ECPointUtil;
import org.spongycastle.jce.spec.ECNamedCurveParameterSpec;
import org.spongycastle.math.ec.ECCurve;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.EllipticCurve;
import java.sql.SQLException;

import javax.crypto.Cipher;


public class ECC
{
    public static final String TAG = "ECC";
    String curve = "secp128r1";
    static
    {
        Security.insertProviderAt(new org.spongycastle.jce.provider.BouncyCastleProvider(), 1);
    }

    public boolean verifySig(String accessPointPublicKey, String accessPointPublicKeySigned, String buildingPublicKey)
    {
        try
        {
            PublicKey accessPoint = loadPublicKey(curve, base64Decode(accessPointPublicKey));
            PublicKey building = loadPublicKey(curve, base64Decode(buildingPublicKey));
        
            boolean verified = verify(accessPointPublicKey.getBytes(),
                    building, base64Decode(accessPointPublicKeySigned));
            return verified;
        }
        catch (Exception e)
        {
            Logger.e(TAG, e.getMessage());
        }
        return false;
    }


    private boolean verify(byte[] data, PublicKey key, byte[] sig) throws Exception
    {
        Signature signer = Signature.getInstance("SHA256withECDSA");
        signer.initVerify(key);
        signer.update(data);
        return signer.verify(sig);
    }

    private byte[] base64Decode(String s) throws UnsupportedEncodingException
    {
        return Base64.decode(s, Base64.DEFAULT);
    }

    public PublicKey loadPublicKey(String curve, byte[] data)
            throws SQLException, IOException, GeneralSecurityException
    {
        KeyFactory factory = KeyFactory.getInstance("ECDSA", "SC");
       
        ECNamedCurveParameterSpec spec = ECNamedCurveTable.getParameterSpec(curve);
        ECCurve eccCurve = spec.getCurve();
        EllipticCurve ellipticCurve = EC5Util.convertCurve(eccCurve, spec.getSeed());
        java.security.spec.ECPoint point = ECPointUtil.decodePoint(ellipticCurve, data);
        java.security.spec.ECParameterSpec params = EC5Util.convertSpec(ellipticCurve, spec);
        ECPublicKeySpec keySpec = new ECPublicKeySpec(point, params);
        return factory.generatePublic(keySpec);
    }

    public PrivateKey loadPrivateKey(String curve, byte[] data)
            throws SQLException, IOException, GeneralSecurityException
    {
        KeyFactory factory = KeyFactory.getInstance("ECDSA", "SC");
        
        ECNamedCurveParameterSpec spec = ECNamedCurveTable.getParameterSpec(curve);
        ECCurve eccCurve = spec.getCurve();
        EllipticCurve ellipticCurve = EC5Util.convertCurve(eccCurve, spec.getSeed());
        java.security.spec.ECParameterSpec params = EC5Util.convertSpec(ellipticCurve, spec);
        ECPrivateKeySpec keySpec = new ECPrivateKeySpec(new BigInteger(1, data), params);
        return factory.generatePrivate(keySpec);
    }

    public String encryptData(String token, String public_key)
    {
        try
        {
            PublicKey accessPoint = loadPublicKey(curve, base64Decode(public_key));
          
            Cipher c = Cipher.getInstance("ECIES");
            c.init(Cipher.ENCRYPT_MODE, accessPoint);
            String messageString = token;
            byte[] message = messageString.getBytes();
            byte[] cipher = c.doFinal(message);
            
            return Base64.encodeToString(cipher, Base64.DEFAULT);
        }
        catch (Exception e)
        {
            e.printStackTrace();
        }
        return null;
    }

    public String decryptData(String message,String private_key)
    {
        try
        {
            PrivateKey privateKey = loadPrivateKey(curve, base64Decode(private_key));
           
            Cipher c = Cipher.getInstance("ECIES");
            byte[] token = ((Base64.decode(message.getBytes(), Base64.DEFAULT)));
            c.init(Cipher.DECRYPT_MODE, privateKey);
            byte[] plaintext = c.doFinal(token);
            
            return new String(plaintext);
        }
        catch (Exception e)
        {
            e.printStackTrace();
        }
        return null;
    }
}
