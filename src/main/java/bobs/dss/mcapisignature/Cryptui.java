/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package bobs.dss.mcapisignature;

import bobs.dss.mcapisignature.Structures.CERT_CONTEXT;
import com.sun.jna.Library;
import com.sun.jna.Native;
import com.sun.jna.Pointer;
import com.sun.jna.PointerType;
import com.sun.jna.platform.win32.WinDef;
import com.sun.jna.win32.W32APIOptions;

/**
 *
 * @author sbalabanov
 */
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
        boolean CryptUIDlgViewContext(
           int dwContextType,         //_In_       DWORD   dwContextType,
           CERT_CONTEXT  pvContext,       //_In_ const void    *pvContext,
           WinDef.HWND hwnd,         //_In_       HWND    hwnd,
           String pwszTitle,         //_In_       LPCWSTR pwszTitle,
           int dwFlags,         //_In_       DWORD   dwFlags,
           PointerType pvReserved        //_In_       void    *pvReserved
        );
    }
