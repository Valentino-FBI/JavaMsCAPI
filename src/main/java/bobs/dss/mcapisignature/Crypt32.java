/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package bobs.dss.mcapisignature;
import bobs.dss.mcapisignature.Structures.*;
import com.sun.jna.Library;
import com.sun.jna.Native;
import com.sun.jna.Pointer;
import com.sun.jna.ptr.IntByReference;
import com.sun.jna.ptr.PointerByReference;

/**
 *
 * @author sbalabanov
 */
public interface Crypt32 extends Library {

        public Crypt32 INST = (Crypt32) Native.loadLibrary("crypt32", Crypt32.class);
        public static final int CERT_FIND_HASH = 65536;

        public CERT_CONTEXT.ByReference CertCreateCertificateContext(
                int dwCertEncodingType,
                byte[] pbCert,
                int cbCert);

        public boolean CertFreeCertificateContext(
                CERT_CONTEXT pCertContext);

        public boolean CertGetCertificateContextProperty(
                CERT_CONTEXT pCertContext,
                int dwPropId,
                PointerByReference pData,
                IntByReference pcbData);

        public boolean CertSetCertificateContextProperty(
                CERT_CONTEXT pCertContext,
                int dwPropId,
                int dwFlags,
                CRYPT_KEY_PROV_INFO pData);

        public Pointer CertOpenSystemStoreA(
                Pointer hCryptProv,
                String psStoreName);

        public boolean CertCloseStore(
                Pointer hCertStore,
                int dwFlags);

        public boolean CertAddCertificateContextToStore(
                Pointer hCertStore,
                CERT_CONTEXT pCertContext,
                int dwAddDisposition,
                CERT_CONTEXT.ByReference ppStoreContext);

        public boolean CryptSignMessage(
                CRYPT_SIGN_MESSAGE_PARA pSignPara,
                boolean fDetachedSignature,
                int cToBeSigned,
                PointerByReference rgpbToBeSigned,
                IntByReference rgcbToBeSigned,
                Pointer pbSignedBlob,
                IntByReference pcbSignedBlob
        );

        public boolean CryptAcquireCertificatePrivateKey(
                CERT_CONTEXT pCertContext,
                int dwFlags,
                IntByReference pvParameters,
                PointerByReference phCryptProvOrNCryptKey,
                IntByReference pdwKeySpec,
                Pointer pfCallerFreeProvOrNCryptKey
        );

        CERT_CONTEXT.ByReference CertGetIssuerCertificateFromStore(
                Pointer hCertStore, //  _In_ HCERTSTORE hCertStore,
                CERT_CONTEXT pSubjectContext, //_In_ PCCERT_CONTEXT pSubjectContext,
                CERT_CONTEXT.ByReference pPrevIssuerContext, //_In_opt_ PCCERT_CONTEXT pPrevIssuerContext,
                IntByReference pdwFlags //_Inout_ DWORD *pdwFlags
        );

        /*
        CertFindCertificateInStore(
    _In_ HCERTSTORE hCertStore,
    _In_ DWORD dwCertEncodingType,
    _In_ DWORD dwFindFlags,
    _In_ DWORD dwFindType,
    _In_opt_ const void *pvFindPara,
    _In_opt_ PCCERT_CONTEXT pPrevCertContext
    );
         */
        CERT_CONTEXT.ByReference CertFindCertificateInStore(
                Pointer hCertStore,
                int dwCertEncodingType,
                int dwFindFlags,
                int dwFindType,
                CRYPT_BIT_BLOB pvFindPara,
                CERT_CONTEXT.ByReference pPrevCertContext
        );

    }