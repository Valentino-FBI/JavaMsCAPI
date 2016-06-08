/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package bobs.dss.mcapisignature;

import java.util.Base64;
import org.junit.Test;
import static org.junit.Assert.*;

/**
 *
 * @author sbalabanov
 */
public class SignatureTest {
    static String testCertHash="D525114F7A061BA0BC83D94646AE95F855931175";
    public SignatureTest() {
    }

    /**
     * Test of sign method, of class Signature.
     */
    @Test
    public void testSign() throws MCAPIException {
        System.out.println("sign");
        byte[] data="test".getBytes();
        Signature signature=new Signature();
        String Sha1Hash=testCertHash;
        Structures.CERT_CONTEXT cert = CertUtils.findCertByHash(Sha1Hash);
        signature.setSignatureAlgorithm("SHA1withRSA");
        signature.setCert(cert);
        signature.sign(data);
    }
    @Test
    public void testSignSelectCert() throws MCAPIException {
        System.out.println("SignSelectCert");
        byte[] data="test".getBytes();
        Signature signature=new Signature();
        String Sha1Hash=testCertHash;
        Structures.CERT_CONTEXT cert = CertUtils.selectCert("Select cert for test", "Using Smartcard");
        signature.setSignatureAlgorithm("SHA256withRSA");
        signature.setCert(cert);
        signature.sign(data);
    }
    @Test
    public void testSignValidHash() throws MCAPIException {
        System.out.println("SignSelectCert");
        byte[] data="test".getBytes();
        Signature signature=new Signature();
        String Sha1Hash="6FEE4E5DBB351A252A397F09A50C70587123E824";//CertUtils.getThumbprint(CertUtils.selectCert("dd", "ddd"));
        Structures.CERT_CONTEXT cert =CertUtils.findCertByHash(Sha1Hash);
      //  Structures.CERT_CONTEXT cert = CertUtils.selectCert("Select cert for test", "Using Smartcard");
        signature.setSignatureAlgorithm("SHA256withRSA");
        signature.setCert(cert);
        byte[] result=signature.sign(data);
        String resultb64 = Base64.getEncoder().encodeToString(result);
        System.out.println(resultb64);
    }
    
}
