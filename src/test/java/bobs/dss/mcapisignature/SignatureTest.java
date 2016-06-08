/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package bobs.dss.mcapisignature;

import org.junit.Test;
import static org.junit.Assert.*;

/**
 *
 * @author sbalabanov
 */
public class SignatureTest {
    
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
        String Sha1Hash="D525114F7A061BA0BC83D94646AE95F855931175";
        Structures.CERT_CONTEXT cert = CertUtils.findCertByHash(Sha1Hash);
        signature.setSignatureAlgorithm("SHA1withRSA");
        signature.setCert(cert);
        signature.sign(data);
        // TODO review the generated test code and remove the default call to fail.
       // fail("The test case is a prototype.");
    }
    
}
