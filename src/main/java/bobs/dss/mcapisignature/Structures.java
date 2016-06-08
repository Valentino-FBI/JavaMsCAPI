/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package bobs.dss.mcapisignature;

import com.sun.jna.Pointer;
import com.sun.jna.Structure;
import com.sun.jna.WString;
import java.util.Arrays;
import java.util.List;

/**
 *
 * @author sbalabanov
 */
public class Structures {
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
}
