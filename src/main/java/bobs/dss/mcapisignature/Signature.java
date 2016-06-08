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
            System.out.println("Sign length: " + dwSigLen);
            Pointer signPtr = new Memory(signLen);
            if (Advapi32.INST.CryptSignHashA(hHash.getValue(), dwKeySpec.getValue(), null, 0, signPtr, dwSigLen)) {
                sign = new byte[signLen];
                signPtr.read(0, sign, 0, signLen);
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

    public static void main(String[] args) {
        IntByReference dwKeySpec = new IntByReference();
        PointerByReference provRef = new PointerByReference();
        CERT_CONTEXT cert = CertUtils.selectCert("test", "test");
        if (Crypt32.INST.CryptAcquireCertificatePrivateKey(cert, 0, null, provRef, dwKeySpec, null)) {
            System.out.println("CryptAcquireCertificatePrivateKey ok");
        } else {
            System.out.println("CryptAcquireCertificatePrivateKey Error" + Integer.toHexString(Native.getLastError()));
        }
        int keyType = AT_SIGNATURE;
        PointerByReference keyRef = new PointerByReference();

        if (!Advapi32.INST.CryptGetUserKey(provRef.getValue(), keyType, keyRef)) {
            keyType = AT_KEYEXCHANGE;
            if (!Advapi32.INST.CryptGetUserKey(provRef.getValue(), keyType, keyRef)) {
                System.out.println("CryptGetUserKey error " + Integer.toHexString(Native.getLastError()));

            }
        }
        PointerByReference hHash = new PointerByReference();
        Pointer hKey = new Pointer(0);

        byte[] pin = "1234".getBytes();
        Pointer ppp = new Memory(pin.length + 1);
        byte[] bzero = {0};
        ppp.write(0, pin, 0, pin.length);
        ppp.write(pin.length, bzero, 0, 1); // добавляем в конец нудевой байт, иначе плохо работает
        /*if (!Advapi32.INST.CryptSetProvParam(provRef.getValue(), PP_KEYEXCHANGE_PIN, ppp, 0)) {
            System.out.println("SetProvParam error " + Integer.toHexString(Native.getLastError()));
        }
        
        if (!Advapi32.INST.CryptSetProvParam(provRef.getValue(), PP_SIGNATURE_PIN, ppp, 0)) {
            System.out.println("SetProvParam error " + Integer.toHexString(Native.getLastError()));
        }
         */
        if (Advapi32.INST.CryptCreateHash(provRef.getValue(), Advapi32.CALG_SHA1, hKey, 0, hHash)) {
            System.out.println("CryptCreateHash ok");
        } else {
            System.out.println("CryptCreateHash Error " + Integer.toHexString(Native.getLastError()));
        }

        byte[] message = "test".getBytes();
        byte[] sign;
        Pointer ptr = new Memory(message.length);
        ptr.write(0, message, 0, message.length);
        PointerByReference aMessage = new PointerByReference(ptr);
        IntByReference pMessageLen = new IntByReference(message.length);
        if (!Advapi32.INST.CryptHashData(hHash.getValue(), aMessage.getValue(), pMessageLen.getValue(), 0)) {
            System.out.println("CryptHashData Error " + Integer.toHexString(Native.getLastError()));
        }
        IntByReference dwSigLen = new IntByReference();
        if (Advapi32.INST.CryptSignHashA(hHash.getValue(), dwKeySpec.getValue(), null, 0, null, dwSigLen)) {
            int signLen = dwSigLen.getValue();
            System.out.println("Sign length: " + dwSigLen);
            Pointer signPtr = new Memory(signLen);
            if (Advapi32.INST.CryptSignHashA(hHash.getValue(), dwKeySpec.getValue(), null, 0, signPtr, dwSigLen)) {
                sign = new byte[signLen];
                signPtr.read(0, sign, 0, signLen);
                dump(sign, "dump.bin");
                System.out.println("OK Sign length: " + signLen);
            } else {
                System.out.println("CryptSignHash Error " + Integer.toHexString(Native.getLastError()));
            }
        } else {
            System.out.println("CryptSignHash Error " + Integer.toHexString(Native.getLastError()));
        }

        Crypt32.INST.CertFreeCertificateContext(cert);

        Advapi32.INST.CryptReleaseContext(provRef.getValue(), 0);
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
