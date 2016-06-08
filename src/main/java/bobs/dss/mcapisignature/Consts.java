/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package bobs.dss.mcapisignature;

/**
 *
 * @author sbalabanov
 */
public class Consts {
    
    final static int PROV_GOST_2001_DH = 75;
    final static int CRYPT_VERIFYCONTEXT = 0xF0000000;
    final static int CRYPT_SILENT = 64;
    final static int CRYPT_MESSAGE_SILENT_KEYSET_FLAG = 64;
    final static int PP_NAME = 4;
    final static int AT_KEYEXCHANGE = 1;
    final static int AT_SIGNATURE = 2;
    final static int KP_CERTIFICATE = 26;
    final static int PP_KEYEXCHANGE_PIN = 32;
    final static int PP_SIGNATURE_PIN = 33;
    final static int X509_ASN_ENCODING = 1;
    final static int PKCS_7_ASN_ENCODING = 0x10000;
    final static int CERT_KEY_PROV_INFO_PROP_ID = 2;
    final static int CERT_STORE_ADD_REPLACE_EXISTING = 3;
    final static String szOID_CP_GOST_R3411 = "1.2.643.2.2.9";
    final static String szOID_RSA_SHA1RSA = "1.2.840.113549.1.1.5";
    final static String szOID_RSA_SHA256RSA = "1.2.840.113549.1.1.11";
    //TODO add all alg
}
