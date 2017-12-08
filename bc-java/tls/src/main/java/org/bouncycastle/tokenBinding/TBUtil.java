package org.bouncycastle.tokenBinding;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;

public class TBUtil {

    public static boolean isValidUint16(int i)
    {
        return (i & 0xFFFF) == i;
    }

    public static boolean isValidUint8(int i)
    {
        return (i & 0xFF) == i;
    }

    public static void writeOpaque8(byte[] buf, OutputStream output)
            throws TokenBindingException
    {
        checkUint8(buf.length);
        writeUint8(buf.length, output);
        try {
            output.write(buf);
        }catch (IOException e){
            throw new TokenBindingException(e.getMessage());
        }
    }

    public static void writeOpaque16(byte[] buf, OutputStream output)
            throws TokenBindingException
    {
        checkUint16(buf.length);
        writeUint16(buf.length, output);
        try {
            output.write(buf);
        }catch (IOException e){
            throw new TokenBindingException(e.getMessage());
        }
    }

    public static void checkUint16(int i) throws TokenBindingException
    {
        if (!isValidUint16(i))
        {
            throw new TokenBindingException("checkUnit16 failed");
//            throw new TokenBindingException("checkUnit16 failed");
            
        }
    }

    public static void checkUint8(int i) throws TokenBindingException
    {
        if (!isValidUint8(i))
        {
            throw new TokenBindingException("checkUnit8 failed");
        }
    }

    public static void writeUint8(int i, OutputStream output)
            throws TokenBindingException
    {
        try {
            output.write(i);
        }catch (IOException e){
            throw new TokenBindingException(e.getMessage());
        }
    }

    public static void writeUint16(int i, OutputStream output)
            throws TokenBindingException
    {
        try {
            output.write(i >>> 8);
            output.write(i);
        }catch (IOException e){
            throw new TokenBindingException(e.getMessage());
        }
    }
    public static void writeBufTo(ByteArrayOutputStream buf, OutputStream output)
            throws TokenBindingException
    {
        try {
            buf.writeTo(output);
        }catch (IOException e){
            throw new TokenBindingException(e.getMessage());
        }
    }



}

