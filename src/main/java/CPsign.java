
import java.io.FileOutputStream;
import java.util.Arrays;
import java.util.List;

import com.sun.jna.Structure;
import com.sun.jna.Library;
import com.sun.jna.Memory;
import com.sun.jna.Native;
import com.sun.jna.Pointer;
import com.sun.jna.PointerType;
import com.sun.jna.ptr.IntByReference;
import com.sun.jna.ptr.PointerByReference;
import com.sun.jna.WString;
import com.sun.jna.platform.win32.WinDef;
import com.sun.jna.win32.W32APIOptions;

public class CPsign {

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
    /**
     *
     * Структуры
     *
     */
    public static class CERT_CONTEXT extends Structure {

        public int dwCertEncodingType;
        public Pointer pbCertEncoded;
        public int cbCertEncoded;
        public CERT_INFO.ByReference pCertInfo;
        public Pointer hCertStore;

        public CERT_CONTEXT() {
        }

        protected List<?> getFieldOrder() {
            return Arrays.asList("dwCertEncodingType", "pbCertEncoded", "cbCertEncoded", "pCertInfo", "hCertStore");
        }

        public static class ByReference extends CERT_CONTEXT implements Structure.ByReference {
        };
    }

    public static class PCERT_CONTEXT extends Structure {

        public CERT_CONTEXT.ByReference certContext;

        public PCERT_CONTEXT() {
        }

        ;
        protected List<?> getFieldOrder() {
            return Arrays.asList("certContext");
        }

        public static class ByReference extends PCERT_CONTEXT implements Structure.ByReference {
        };

        public static class ByValue extends PCERT_CONTEXT implements Structure.ByValue {
        };
    }

    public static class CERT_EXTENSION extends Structure {

        public String pszObjId;
        public boolean fCritical;
        public CRYPT_INTEGER_BLOB Value;

        public CERT_EXTENSION() {
        }

        protected List<?> getFieldOrder() {
            return Arrays.asList("pszObjId", "fCritical", "Value");
        }

        public static class ByReference extends CERT_EXTENSION implements Structure.ByReference {
        };
    }

    public static class CERT_EXTENSIONS extends Structure {

        public int cExtension;
        public CERT_EXTENSION.ByReference rgExtension;

        public CERT_EXTENSIONS() {
            super();
        }

        protected List<?> getFieldOrder() {
            return Arrays.asList("cExtension", "rgExtension");
        }

        public static class ByReference extends CERT_EXTENSIONS implements Structure.ByReference {
        };
    }

    public static class CERT_INFO extends Structure {

        public int dwVersion;
        public CRYPT_INTEGER_BLOB SerialNumber;
        public CRYPT_ALGORITHM_IDENTIFIER SignatureAlgorithm;
        public CRYPT_INTEGER_BLOB Issuer;
        public FILETIME NotBefore;
        public FILETIME NotAfter;
        public CRYPT_INTEGER_BLOB Subject;
        public CERT_PUBLIC_KEY_INFO SubjectPublicKeyInfo;
        public CRYPT_BIT_BLOB IssuerUniqueId;
        public CRYPT_BIT_BLOB SubjectUniqueId;
        public int cExtension;
        public CERT_EXTENSION.ByReference rgExtension;

        public CERT_INFO() {
        }

        protected List<?> getFieldOrder() {
            return Arrays.asList("dwVersion", "SerialNumber", "SignatureAlgorithm", "Issuer", "NotBefore", "NotAfter", "Subject", "SubjectPublicKeyInfo", "IssuerUniqueId", "SubjectUniqueId", "cExtension", "rgExtension");
        }

        public static class ByReference extends CERT_INFO implements Structure.ByReference {
        };
    }

    public static class CERT_PUBLIC_KEY_INFO extends Structure {

        public CRYPT_ALGORITHM_IDENTIFIER Algorithm;
        public CRYPT_BIT_BLOB PublicKey;

        public CERT_PUBLIC_KEY_INFO() {
        }

        protected List<?> getFieldOrder() {
            return Arrays.asList("Algorithm", "PublicKey");
        }

        public static class ByReference extends CERT_PUBLIC_KEY_INFO implements Structure.ByReference {
        };
    }

    public static class CRL_CONTEXT extends Structure {

        public int dwCertEncodingType;
        public Pointer pbCrlEncoded;
        public int cbCrlEncoded;
        public CRL_INFO.ByReference pCrlInfo;
        public Pointer hCertStore;

        public CRL_CONTEXT() {
        }

        protected List<?> getFieldOrder() {
            return Arrays.asList("dwCertEncodingType", "pbCrlEncoded", "cbCrlEncoded", "pCrlInfo", "hCertStore");
        }

        public static class ByReference extends CRL_CONTEXT implements Structure.ByReference {
        };
    }

    public static class CRL_ENTRY extends Structure {

        public CRYPT_INTEGER_BLOB SerialNumber;
        public FILETIME RevocationDate;
        public int cExtension;
        public CERT_EXTENSION.ByReference rgExtension;

        public CRL_ENTRY() {
        }

        protected List<?> getFieldOrder() {
            return Arrays.asList("SerialNumber", "RevocationDate", "cExtension", "rgExtension");
        }

        public static class ByReference extends CRL_ENTRY implements Structure.ByReference {
        };
    }

    public static class CRL_INFO extends Structure {

        public int dwVersion;
        public CRYPT_ALGORITHM_IDENTIFIER SignatureAlgorithm;
        public CRYPT_INTEGER_BLOB Issuer;
        public FILETIME ThisUpdate;
        public FILETIME NextUpdate;
        public int cCRLEntry;
        public CRL_ENTRY.ByReference rgCRLEntry;
        public int cExtension;
        public CERT_EXTENSION.ByReference rgExtension;

        public CRL_INFO() {
        }

        protected List<?> getFieldOrder() {
            return Arrays.asList("dwVersion", "SignatureAlgorithm", "Issuer", "ThisUpdate", "NextUpdate", "cCRLEntry", "rgCRLEntry", "cExtension", "rgExtension");
        }

        public static class ByReference extends CRL_INFO implements Structure.ByReference {
        };
    }

    public static class CRYPT_ALGORITHM_IDENTIFIER extends Structure {

        public String pszObjId;
        public CRYPT_INTEGER_BLOB Parameters;

        public CRYPT_ALGORITHM_IDENTIFIER() {
        }

        protected List<?> getFieldOrder() {
            return Arrays.asList("pszObjId", "Parameters");
        }

        public static class ByReference extends CRYPT_ALGORITHM_IDENTIFIER implements Structure.ByReference {
        };
    }

    public static class CRYPT_ATTRIBUTE extends Structure {

        public String pszObjId;
        public int cValue;
        public CRYPT_INTEGER_BLOB.ByReference rgValue;

        public CRYPT_ATTRIBUTE() {
        }

        protected List<?> getFieldOrder() {
            return Arrays.asList("pszObjId", "cValue", "rgValue");
        }

        public static class ByReference extends CRYPT_ATTRIBUTE implements Structure.ByReference {
        };
    }

    public static class CRYPT_BIT_BLOB extends Structure {

        public int cbData;
        public Pointer pbData;
        public int cUnusedBits;

        public CRYPT_BIT_BLOB() {
        }

        protected List<?> getFieldOrder() {
            return Arrays.asList("cbData", "pbData", "cUnusedBits");
        }

        public static class ByReference extends CRYPT_BIT_BLOB implements Structure.ByReference {
        };
    }

    public static class CRYPT_INTEGER_BLOB extends Structure {

        public int cbData;
        public Pointer pbData;

        public CRYPT_INTEGER_BLOB() {
        }

        protected List<?> getFieldOrder() {
            return Arrays.asList("cbData", "pbData");
        }

        public static class ByReference extends CRYPT_INTEGER_BLOB implements Structure.ByReference {
        };
    }

    public static class CRYPT_KEY_PROV_INFO extends Structure {

        public WString pwszContainerName;
        public WString pwszProvName;
        public int dwProvType;
        public int dwFlags;
        public int cProvParam;
        public CRYPT_KEY_PROV_PARAM.ByReference[] rgProvParam = new CRYPT_KEY_PROV_PARAM.ByReference[1];
        public int dwKeySpec;

        public CRYPT_KEY_PROV_INFO() {
        }

        protected List<?> getFieldOrder() {
            return Arrays.asList("pwszContainerName", "pwszProvName", "dwProvType", "dwFlags", "cProvParam", "rgProvParam", "dwKeySpec");
        }

        public static class ByReference extends CRYPT_KEY_PROV_INFO implements Structure.ByReference {
        };
    }

    public static class CRYPT_KEY_PROV_PARAM extends Structure {

        public int dwParam;
        public byte[] pbData;
        public int cbData;
        public int dwFlags;

        public CRYPT_KEY_PROV_PARAM() {
        }

        protected List<?> getFieldOrder() {
            return Arrays.asList("dwParam", "pbData", "cbData", "dwFlags");
        }

        public static class ByReference extends CRYPT_KEY_PROV_PARAM implements Structure.ByReference {
        };
    }

    public static class CRYPT_SIGN_MESSAGE_PARA extends Structure {

        public int cbSize;
        public int dwMsgEncodingType;
        public CERT_CONTEXT.ByReference pSigningCert;
        public CRYPT_ALGORITHM_IDENTIFIER HashAlgorithm;
        public Pointer pvHashAuxInfo;
        public int cMsgCert;
        public PCERT_CONTEXT.ByReference rgpMsgCert;
        public int cMsgCrl;
        public CRL_CONTEXT.ByReference rgpMsgCrl;
        public int cAuthAttr;
        public CRYPT_ATTRIBUTE.ByReference rgAuthAttr;
        public int cUnauthAttr;
        public CRYPT_ATTRIBUTE.ByReference rgUnauthAttr;
        public int dwFlags;
        public int dwInnerContentType;

        public CRYPT_SIGN_MESSAGE_PARA() {
        }

        protected List<?> getFieldOrder() {
            return Arrays.asList("cbSize", "dwMsgEncodingType", "pSigningCert", "HashAlgorithm", "pvHashAuxInfo", "cMsgCert", "rgpMsgCert", "cMsgCrl", "rgpMsgCrl", "cAuthAttr", "rgAuthAttr", "cUnauthAttr", "rgUnauthAttr", "dwFlags", "dwInnerContentType");
        }

        public static class ByReference extends CRYPT_SIGN_MESSAGE_PARA implements Structure.ByReference {
        };
    }

    public static class FILETIME extends Structure {

        public int dwLowDateTime;
        public int dwHighDateTime;

        public FILETIME() {
        }

        protected List<?> getFieldOrder() {
            return Arrays.asList("dwLowDateTime", "dwHighDateTime");
        }

        public static class ByReference extends FILETIME implements Structure.ByReference {
        };

        public static class ByValue extends FILETIME implements Structure.ByValue {
        };
    }

    /**
     *
     * Интерфейс
     *
     */
    public interface Advapi32 extends Library {

        public Advapi32 INST = (Advapi32) Native.loadLibrary("advapi32", Advapi32.class);
        public static final int CALG_SHA1 = 32772;

        public boolean CryptAcquireContextA(
                PointerByReference hprov,
                String pszContainer,
                String pszProvider,
                int dwProvType,
                int dwFlags);

        public boolean CryptGetProvParam(
                Pointer prov,
                int dwParam,
                byte[] pbData,
                IntByReference dwDataLen,
                int dwFlags
        );

        public boolean CryptSetProvParam(
                Pointer prov,
                int dwParam,
                //	byte[] pbData,
                Pointer pbData,
                int dwFlags);

        public boolean CryptGetUserKey(
                Pointer prov,
                int dwKeyParam,
                PointerByReference hkey);

        public boolean CryptGetKeyParam(
                Pointer key,
                int dwParam,
                byte[] pbCert,
                IntByReference dwCertLen,
                int dwFlag);

        public boolean CryptSetKeyParam(
                Pointer key,
                int dwParam,
                byte[] pbCert,
                int dwFlag);

        public boolean CryptReleaseContext(
                Pointer prov,
                int dwFlags);

        public boolean CryptCreateHash(
                Pointer hProv, //in	HCRYPTPROV 	a handle of CSP
                int Algid, //in	ALG_ID		An ALG_ID value 
                Pointer hKey, //in	HCRYPTKEY 	the key for the hash, 0 for nonkeyed
                int dwFlags, //in	DWORD 		reserved, must be zero
                PointerByReference phHash //out	HCRYPTHASH*	pointer to a handle of hash object
        );

        public boolean CryptHashData(
                Pointer hHash, //in  HCRYPTHASH	Handle of the hash object.
                Pointer pbData, //in  BYTE*			pointer to a buffer with data to hash 
                int dwDataLen, //in  DWORD 		must be zero if CRYPT_USERDATA flag is set.
                int dwFlags //in  DWORD 
        );

        boolean CryptSignHashA(
                Pointer hHash, //in	HCRYPTHASH	Handle of the hash object to be signed.
                int dwKeySpec, //in    DWORD 		Identifies the private key to use
                Pointer sDescription, //in    LPCTSTR		must be null
                int dwFlags, //in    DWORD 
                Pointer pbSignature, //out   BYTE*		buffer receiving the signature data.
                IntByReference pdwSigLen //inout DWORD*		size of the pbSignature buffer. 
        );
    }

    public interface Cryptui extends Library {

        public Cryptui INST = (Cryptui) Native.loadLibrary("Cryptui", Cryptui.class, W32APIOptions.UNICODE_OPTIONS);

        CERT_CONTEXT.ByReference CryptUIDlgSelectCertificateFromStore(
                Pointer hCertStore,
                WinDef.HWND hwnd,
                String pwszTitle,
                String pwszDisplayString,
                int dwDontUseColumn,
                int dwFlags,
                PointerType pvReserved
        );
    }

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

    public static byte[] Sign(byte[] message, String contName, String pinCode, boolean detach) {
        byte[] sign = null;
        int keyType = 0;
        PointerByReference provRef = new PointerByReference();
        String provName;

// создаем контекст криптопровайдера
        if (!Advapi32.INST.CryptAcquireContextA(provRef, contName, null, PROV_GOST_2001_DH, CRYPT_SILENT)) {
            System.out.println("CryptAcquireContext error " + Integer.toHexString(Native.getLastError()));
            return null;
        }

// получаем имя провайдера
        IntByReference dataLen = new IntByReference();
        if (Advapi32.INST.CryptGetProvParam(provRef.getValue(), PP_NAME, null, dataLen, 0)) {
            byte data[] = new byte[dataLen.getValue()];
            Advapi32.INST.CryptGetProvParam(provRef.getValue(), PP_NAME, data, dataLen, 0);
            provName = new String(data);
        } else {
            System.out.println("CryptGetProvParam error " + Integer.toHexString(Native.getLastError()));
            return null;
        }

// получаем ключ
        keyType = AT_SIGNATURE;
        PointerByReference keyRef = new PointerByReference();
        if (!Advapi32.INST.CryptGetUserKey(provRef.getValue(), keyType, keyRef)) {
            keyType = AT_KEYEXCHANGE;
            if (!Advapi32.INST.CryptGetUserKey(provRef.getValue(), keyType, keyRef)) {
                System.out.println("CryptGetUserKey error " + Integer.toHexString(Native.getLastError()));
                return null;
            }
        }

// получаем сертификат
        IntByReference сertLen = new IntByReference();
        byte[] cert = null;
        if (Advapi32.INST.CryptGetKeyParam(keyRef.getValue(), KP_CERTIFICATE, null, сertLen, 0)) {
            cert = new byte[сertLen.getValue()];
            Advapi32.INST.CryptGetKeyParam(keyRef.getValue(), KP_CERTIFICATE, cert, сertLen, 0);
        } else {
            System.out.println("CryptGetKeyParam error " + Integer.toHexString(Native.getLastError()));
            return null;
        }

// устанавливаем ПИН-код или пароль к контейнеру 
        byte[] pin = pinCode.getBytes();
        Pointer ppp = new Memory(pin.length + 1);
        byte[] bzero = {0};
        ppp.write(0, pin, 0, pin.length);
        ppp.write(pin.length, bzero, 0, 1); // добавляем в конец нудевой байт, иначе плохо работает
        if (!Advapi32.INST.CryptSetProvParam(provRef.getValue(), PP_KEYEXCHANGE_PIN, ppp, 0)) {
            System.out.println("SetProvParam error " + Integer.toHexString(Native.getLastError()));
        }
        if (!Advapi32.INST.CryptSetProvParam(provRef.getValue(), PP_SIGNATURE_PIN, ppp, 0)) {
            System.out.println("SetProvParam error " + Integer.toHexString(Native.getLastError()));
        }

// получаем контекст сертификата
        CERT_CONTEXT.ByReference certCont = Crypt32.INST.CertCreateCertificateContext(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, cert, cert.length);
        if (certCont != null) {
// связываем контекст сертификата с ключом
            CRYPT_KEY_PROV_INFO keyInfo = new CRYPT_KEY_PROV_INFO();
            keyInfo.pwszContainerName = new WString(contName);
            keyInfo.pwszProvName = new WString(provName);
            keyInfo.dwProvType = 75;
            keyInfo.dwFlags = 0;
            keyInfo.cProvParam = 0;
            keyInfo.rgProvParam[0] = null;
            keyInfo.dwKeySpec = keyType;

            if (!Crypt32.INST.CertSetCertificateContextProperty(certCont, CERT_KEY_PROV_INFO_PROP_ID, 0, keyInfo)) {
                System.out.println("CertSetCertificateContextProperty error " + Integer.toHexString(Native.getLastError()));
                return null;
            }

// помещаем контекст сертификата в хранилище
            Pointer hStore = null;
            hStore = Crypt32.INST.CertOpenSystemStoreA(null, "MY");
            if (hStore != null) {
                if (!Crypt32.INST.CertAddCertificateContextToStore(hStore, certCont, CERT_STORE_ADD_REPLACE_EXISTING, null)) {
                    System.out.println("AddCertContext error " + Integer.toHexString(Native.getLastError()));
                    return null;
                }
                Crypt32.INST.CertCloseStore(hStore, 0);
            } else {
                System.out.println("OpenStore error " + Integer.toHexString(Native.getLastError()));
                return null;
            }

// создаем и заполняем структуру для создания цифроовой подписи
            CRYPT_SIGN_MESSAGE_PARA SigParams = new CRYPT_SIGN_MESSAGE_PARA();

            PCERT_CONTEXT.ByReference pCertCont = new PCERT_CONTEXT.ByReference();
            pCertCont.certContext = certCont;

            SigParams.dwMsgEncodingType = X509_ASN_ENCODING | PKCS_7_ASN_ENCODING;
            SigParams.pSigningCert = certCont;
            SigParams.HashAlgorithm.pszObjId = new String(szOID_CP_GOST_R3411);
            SigParams.HashAlgorithm.Parameters.cbData = 0;
            SigParams.pvHashAuxInfo = null;
            SigParams.cMsgCert = 1;
            SigParams.rgpMsgCert = pCertCont;
            SigParams.cAuthAttr = 0;
            SigParams.dwInnerContentType = 0;
            SigParams.cMsgCrl = 0;
            SigParams.rgpMsgCrl = null;
            SigParams.cUnauthAttr = 0;
            SigParams.dwFlags = CRYPT_MESSAGE_SILENT_KEYSET_FLAG;
            SigParams.rgAuthAttr = null;
            SigParams.rgUnauthAttr = null;
            SigParams.cbSize = SigParams.size();

// формируем указатель на массив сообщений и массив размеров сообщений
            Pointer ptr = new Memory(message.length);
            ptr.write(0, message, 0, message.length);
            PointerByReference aMessage = new PointerByReference(ptr);
            IntByReference pMessageLen = new IntByReference(message.length);

// определяем длину и формируем подпись
            IntByReference pSignLen = new IntByReference();
            if (Crypt32.INST.CryptSignMessage(SigParams, true, 1, aMessage, pMessageLen, null, pSignLen)) {
                int signLen = pSignLen.getValue();
                System.out.println("Sign length: " + signLen);
                Pointer signPtr = new Memory(signLen);
                if (Crypt32.INST.CryptSignMessage(SigParams, true, 1, aMessage, pMessageLen, signPtr, pSignLen)) {
                    sign = new byte[signLen];
                    signPtr.read(0, sign, 0, signLen);
                }
            } else {
                System.out.println("CryptSignMessage error " + Integer.toHexString(Native.getLastError()));
            }
            Crypt32.INST.CertFreeCertificateContext(certCont);
        }
        Advapi32.INST.CryptReleaseContext(provRef.getValue(), 0);
        return sign;
    }

    private static void echo(byte[] content, String file) {
        try {
            FileOutputStream fos = new FileOutputStream(file);
            fos.write(content);
            fos.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    public static void findCertByHash(String Sha1Hash){
        byte[] decoded = hexStringToByteArray(Sha1Hash);
        Pointer hStore = Crypt32.INST.CertOpenSystemStoreA(null, "MY");
        CRYPT_BIT_BLOB pvFindPara=new CRYPT_BIT_BLOB();
        pvFindPara.pbData= new Memory(decoded.length);
        pvFindPara.pbData.write(0, decoded, 0, decoded.length);
        pvFindPara.cbData=decoded.length;
        CERT_CONTEXT.ByReference cert=Crypt32.INST.CertFindCertificateInStore(hStore, 1, 0,Crypt32.CERT_FIND_HASH, pvFindPara, null);
        byte[] certIssuerCertBytes = cert.pbCertEncoded.getByteArray(0, cert.cbCertEncoded);
        echo(certIssuerCertBytes, "fintCert.cer");
    }
    public static void selectCertPKCS7() {
        Pointer hStore = null;
        hStore = Crypt32.INST.CertOpenSystemStoreA(null, "MY");
        WinDef.HWND hwnd = null;
        CERT_CONTEXT.ByReference pCertContSel = Cryptui.INST.CryptUIDlgSelectCertificateFromStore(hStore, hwnd, "test", "test 2", 0, 0, null);
        IntByReference dwKeySpec = new IntByReference();
        PointerByReference provRef = new PointerByReference();
        if (Crypt32.INST.CryptAcquireCertificatePrivateKey(pCertContSel, 0, null, provRef, dwKeySpec, null)) {
            System.out.println("CryptAcquireCertificatePrivateKey ok");
        } else {
            System.out.println("CryptAcquireCertificatePrivateKey Errror");
        }
        byte[] pin = "1234".getBytes();
        Pointer ppp = new Memory(pin.length + 1);
        byte[] bzero = {0};
        ppp.write(0, pin, 0, pin.length);
        ppp.write(pin.length, bzero, 0, 1); // добавляем в конец нудевой байт, иначе плохо работает
        /*if (!Advapi32.INST.CryptSetProvParam(provRef.getValue(), PP_KEYEXCHANGE_PIN, ppp, 0)) {
            System.out.println("SetProvParam error " + Integer.toHexString(Native.getLastError()));
        }
         */
        if (!Advapi32.INST.CryptSetProvParam(provRef.getValue(), PP_SIGNATURE_PIN, ppp, 0)) {
            System.out.println("SetProvParam error " + Integer.toHexString(Native.getLastError()));
        }

        byte[] message = "test".getBytes();
        byte[] sign;
        CRYPT_SIGN_MESSAGE_PARA SigParams = new CRYPT_SIGN_MESSAGE_PARA();

        PCERT_CONTEXT.ByReference pCertCont = new PCERT_CONTEXT.ByReference();
        CERT_CONTEXT.ByReference certCont = pCertContSel;
        pCertCont.certContext = certCont;

        SigParams.dwMsgEncodingType = X509_ASN_ENCODING | PKCS_7_ASN_ENCODING;
        SigParams.pSigningCert = certCont;
        SigParams.HashAlgorithm.pszObjId = new String("1.2.840.113549.1.1.5");
        SigParams.HashAlgorithm.Parameters.cbData = 0;
        SigParams.pvHashAuxInfo = null;
        SigParams.cMsgCert = 1;
        SigParams.rgpMsgCert = pCertCont;
        SigParams.cAuthAttr = 0;
        SigParams.dwInnerContentType = 0;
        SigParams.cMsgCrl = 0;
        SigParams.rgpMsgCrl = null;
        SigParams.cUnauthAttr = 0;
        SigParams.dwFlags = CRYPT_MESSAGE_SILENT_KEYSET_FLAG;
        SigParams.rgAuthAttr = null;
        SigParams.rgUnauthAttr = null;
        SigParams.cbSize = SigParams.size();

// формируем указатель на массив сообщений и массив размеров сообщений
        Pointer ptr = new Memory(message.length);
        ptr.write(0, message, 0, message.length);
        PointerByReference aMessage = new PointerByReference(ptr);
        IntByReference pMessageLen = new IntByReference(message.length);

// определяем длину и формируем подпись
        IntByReference pSignLen = new IntByReference();
        if (Crypt32.INST.CryptSignMessage(SigParams, true, 1, aMessage, pMessageLen, null, pSignLen)) {
            int signLen = pSignLen.getValue();
            System.out.println("Sign length: " + signLen);
            Pointer signPtr = new Memory(signLen);
            if (Crypt32.INST.CryptSignMessage(SigParams, true, 1, aMessage, pMessageLen, signPtr, pSignLen)) {
                sign = new byte[signLen];
                signPtr.read(0, sign, 0, signLen);
                echo(sign, "D:\\Junk\\JMSCAPI\\dump.pkcs7");
                System.out.println("OK Sign length: " + signLen);
            } else {
                System.out.println("CryptSignMessage error " + Integer.toHexString(Native.getLastError()));
            }
        } else {
            System.out.println("CryptSignMessage error " + Integer.toHexString(Native.getLastError()));
        }
        Crypt32.INST.CertFreeCertificateContext(certCont);

        Advapi32.INST.CryptReleaseContext(provRef.getValue(), 0);

    }

    public static void IssuerCertificate(CERT_CONTEXT.ByReference cert) {
        Pointer hStoreCa = Crypt32.INST.CertOpenSystemStoreA(null, "CA");
        IntByReference dwVerificationFlags = new IntByReference();
        CERT_CONTEXT.ByReference certIssuerCert = Crypt32.INST.CertGetIssuerCertificateFromStore(hStoreCa, cert, null, dwVerificationFlags);
        byte[] certIssuerCertBytes = certIssuerCert.pbCertEncoded.getByteArray(0, certIssuerCert.cbCertEncoded);
        echo(certIssuerCertBytes, "certIssuerCert.cer");
    }

    public static void selectCert() {
        Pointer hStore = null;
        hStore = Crypt32.INST.CertOpenSystemStoreA(null, "MY");
        WinDef.HWND hwnd = null;
        CERT_CONTEXT.ByReference certCont = Cryptui.INST.CryptUIDlgSelectCertificateFromStore(hStore, hwnd, "test", "test 2", 0, 0, null);

        IntByReference dwKeySpec = new IntByReference();
        PointerByReference provRef = new PointerByReference();
        if (Crypt32.INST.CryptAcquireCertificatePrivateKey(certCont, 0, null, provRef, dwKeySpec, null)) {
            System.out.println("CryptAcquireCertificatePrivateKey ok");
        } else {
            System.out.println("CryptAcquireCertificatePrivateKey Error" + Integer.toHexString(Native.getLastError()));
        }

        // получаем ключ
        int keyType = AT_SIGNATURE;
        PointerByReference keyRef = new PointerByReference();
        if (!Advapi32.INST.CryptGetUserKey(provRef.getValue(), keyType, keyRef)) {
            keyType = AT_KEYEXCHANGE;
            if (!Advapi32.INST.CryptGetUserKey(provRef.getValue(), keyType, keyRef)) {
                System.out.println("CryptGetUserKey error " + Integer.toHexString(Native.getLastError()));

            }
        }

// получаем сертификат
        IntByReference сertLen = new IntByReference();
        byte[] cert = null;
        if (Advapi32.INST.CryptGetKeyParam(keyRef.getValue(), KP_CERTIFICATE, null, сertLen, 0)) {
            cert = new byte[сertLen.getValue()];
            Advapi32.INST.CryptGetKeyParam(keyRef.getValue(), KP_CERTIFICATE, cert, сertLen, 0);
            echo(cert, "cert.cer");
        } else {
            System.out.println("CryptGetKeyParam error " + Integer.toHexString(Native.getLastError()));

        }
        IssuerCertificate(certCont);
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
                echo(sign, "D:\\Junk\\JMSCAPI\\dump.bin");
                System.out.println("OK Sign length: " + signLen);
            } else {
                System.out.println("CryptSignHash Error " + Integer.toHexString(Native.getLastError()));
            }
        } else {
            System.out.println("CryptSignHash Error " + Integer.toHexString(Native.getLastError()));
        }

        Crypt32.INST.CertFreeCertificateContext(certCont);

        Advapi32.INST.CryptReleaseContext(provRef.getValue(), 0);
    }
public static byte[] hexStringToByteArray(String s) {
    int len = s.length();
    byte[] data = new byte[len / 2];
    for (int i = 0; i < len; i += 2) {
        data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                             + Character.digit(s.charAt(i+1), 16));
    }
    return data;
}
    public static void main(String[] args) {
        findCertByHash("D525114F7A061BA0BC83D94646AE95F855931175");
        selectCert();
        // selectCertPKCS7();
//	String contName = "SCARD\\rutoken_2ae66d67\\0A00\\B9A6";
/*        
String contName = "Srebrin";
        String pin = "12345678";
        byte[] message = "String for signature".getBytes();
        echo(message, "D:\\php_gtk2.pdf.txt");
        byte[] sign = Sign(message, contName, pin, true);
        if (sign != null) {
            echo(sign, "d:\\php_gtk2.pdf.txt.p7");
        }
         */
    }
}
