/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package bobs.dss.mcapisignature;

import com.sun.jna.Library;
import com.sun.jna.Native;
import com.sun.jna.Pointer;
import com.sun.jna.ptr.IntByReference;
import com.sun.jna.ptr.PointerByReference;

/**
 *
 * @author sbalabanov
 */
public interface Advapi32 extends Library {

        public Advapi32 INST = (Advapi32) Native.loadLibrary("advapi32", Advapi32.class);
        public static final int CALG_SHA1 = 32772;
        public static final int CALG_SHA256 = 32772-4+12;
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
