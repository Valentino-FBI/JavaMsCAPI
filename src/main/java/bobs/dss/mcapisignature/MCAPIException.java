/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package bobs.dss.mcapisignature;

import com.sun.jna.Native;

/**
 *
 * @author sbalabanov
 */
class MCAPIException extends Exception {

    public MCAPIException(String message) {
        super(message+" (0x"+Integer.toHexString(Native.getLastError())+")");
    }
    
}
