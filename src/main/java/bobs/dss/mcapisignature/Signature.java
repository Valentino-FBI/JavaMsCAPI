/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package bobs.dss.mcapisignature;

import static bobs.dss.mcapisignature.Consts.*;
import bobs.dss.mcapisignature.Structures.*;
import static bobs.dss.mcapisignature.CertUtils.dump;
import com.sun.jna.Memory;
import com.sun.jna.Native;
import com.sun.jna.Pointer;
import com.sun.jna.ptr.IntByReference;
import com.sun.jna.ptr.PointerByReference;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Base64;

/**
 *
 * @author sbalabanov
 */
public class Signature {

    private CERT_CONTEXT cert = null;
    private PointerByReference provRef = null;
    private IntByReference dwKeySpec = new IntByReference();
    private String signatureAlgorithm = "SHA256withRSA";

    public Signature() {

    }

    public Signature(CERT_CONTEXT cert) throws MCAPIException {
        this.cert = cert;
        setProvaider(cert);
    }

    private PointerByReference setProvaider(CERT_CONTEXT cert) throws MCAPIException {
        if (cert == null) {
            throw new MCAPIException("Not set certificate");
        }

        dwKeySpec = new IntByReference();
        provRef = new PointerByReference();
        if (!Crypt32.INST.CryptAcquireCertificatePrivateKey(cert, 0, null, provRef, dwKeySpec, null)) {
            throw new MCAPIException("CryptAcquireCertificatePrivateKey");
        }
        return provRef;
    }

    public void setPin(byte[] pin) throws MCAPIException {
        if (provRef == null) {
            throw new MCAPIException("Not set CryptoAPI provider");
        }
        Pointer ppp = new Memory(pin.length + 1);
        byte[] bzero = {0};
        ppp.write(0, pin, 0, pin.length);
        ppp.write(pin.length, bzero, 0, 1);

        if (!Advapi32.INST.CryptSetProvParam(provRef.getValue(), PP_SIGNATURE_PIN, ppp, 0)) {
            throw new MCAPIException("Set PIN");
        }

    }

    private int getMCAPISignatureAlgorithm(String signatureAlgorithm) throws MCAPIException {
        int CALG = 0;
        switch (signatureAlgorithm) {
            case "SHA256withRSA":
                CALG = Advapi32.CALG_SHA256;
                break;
            case "SHA1withRSA":
                CALG = Advapi32.CALG_SHA1;
                break;
            default:
                throw new MCAPIException("Unsupported alg " + signatureAlgorithm);
        }
        return CALG;
    }

    public byte[] sign(byte[] dataToSign) throws MCAPIException {

        setProvaider(cert);
        int keyType = AT_SIGNATURE;
        PointerByReference keyRef = new PointerByReference();

        if (!Advapi32.INST.CryptGetUserKey(provRef.getValue(), keyType, keyRef)) {
            keyType = AT_KEYEXCHANGE;
            if (!Advapi32.INST.CryptGetUserKey(provRef.getValue(), keyType, keyRef)) {
                throw new MCAPIException("CryptGetUserKey Error");

            }

        }
        PointerByReference hHash = new PointerByReference();
        Pointer hKey = new Pointer(0);
        int alg = getMCAPISignatureAlgorithm(getSignatureAlgorithm());
        if (!Advapi32.INST.CryptCreateHash(provRef.getValue(), alg, hKey, 0, hHash)) {
            throw new MCAPIException("CryptCreateHash Error");
        }

        byte[] sign;
        Pointer ptr = new Memory(dataToSign.length);
        ptr.write(0, dataToSign, 0, dataToSign.length);
        PointerByReference aMessage = new PointerByReference(ptr);
        IntByReference pMessageLen = new IntByReference(dataToSign.length);
        if (!Advapi32.INST.CryptHashData(hHash.getValue(), aMessage.getValue(), pMessageLen.getValue(), 0)) {
            throw new MCAPIException("CryptHashData Error");
        }
        IntByReference dwSigLen = new IntByReference();
        if (Advapi32.INST.CryptSignHashA(hHash.getValue(), dwKeySpec.getValue(), null, 0, null, dwSigLen)) {
            int signLen = dwSigLen.getValue();
            Pointer signPtr = new Memory(signLen);
            if (Advapi32.INST.CryptSignHashA(hHash.getValue(), dwKeySpec.getValue(), null, 0, signPtr, dwSigLen)) {
                sign = new byte[signLen];
                //Reverse read 
                for (int n = 0; n < signLen; n++) {
                    sign[n] = signPtr.getByte(signLen - 1 - n);
                }
                //signPtr.read(0, sign, 0, signLen);

                System.out.println("OK Sign length: " + signLen);
            } else {
                System.out.println("CryptSignHash Error " + Integer.toHexString(Native.getLastError()));
                throw new MCAPIException("CryptSignHash Error");
            }
        } else {
            System.out.println("CryptSignHash Error " + Integer.toHexString(Native.getLastError()));
            throw new MCAPIException("CryptSignHash Error");
        }

        return sign;
    }

    @Override
    protected void finalize() throws Throwable {
        super.finalize();
        if (cert != null) {
            Crypt32.INST.CertFreeCertificateContext(cert);
        }
        if (provRef != null) {
            Advapi32.INST.CryptReleaseContext(provRef.getValue(), 0);
        }
    }

    public static void main(String[] args) throws MCAPIException, CertificateException, SelectCertificateExceprion {
        byte[] data="test".getBytes();
        
        System.out.println("Signing data '"+"test"+"' base64:"+Base64.getEncoder().encodeToString(data));
        Structures.CERT_CONTEXT cert = CertUtils.selectCert("Select cert for test", "Using Smartcard");
        X509Certificate x509Cert = CertUtils.getX509Certificate(cert);
        System.out.println("Signing whit cert: '"+x509Cert.getSubjectDN().toString());
        Signature signature=new Signature(cert);
        signature.setSignatureAlgorithm("SHA256withRSA");        
        byte[] result=signature.sign(data);
        String resultb64 = Base64.getEncoder().encodeToString(result);
        System.out.println("result base64:"+resultb64);
    }

    /**
     * @param cert the cert to set
     */
    public void setCert(CERT_CONTEXT cert) {
        this.cert = cert;
    }

    /**
     * @return the signatureAlgorithm
     */
    public String getSignatureAlgorithm() {
        return signatureAlgorithm;
    }

    /**
     * @param signatureAlgorithm the signatureAlgorithm to set
     */
    public void setSignatureAlgorithm(String signatureAlgorithm) {
        this.signatureAlgorithm = signatureAlgorithm;
    }

}
