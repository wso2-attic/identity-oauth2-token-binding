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
            throws IOException
    {
        checkUint8(buf.length);
        writeUint8(buf.length, output);
        output.write(buf);
    }

    public static void writeOpaque16(byte[] buf, OutputStream output)
            throws IOException
    {
        checkUint16(buf.length);
        writeUint16(buf.length, output);
        output.write(buf);
    }

    public static void checkUint16(int i) throws IOException
    {
        if (!isValidUint16(i))
        {
            throw new IOException("checkUnit16 failed");
        }
    }

    public static void checkUint8(int i) throws IOException
    {
        if (!isValidUint8(i))
        {
            throw new IOException("checkUnit8 failed");
        }
    }

    public static void writeUint8(int i, OutputStream output)
            throws IOException
    {
        output.write(i);
    }

    public static void writeUint16(int i, OutputStream output)
            throws IOException
    {
        output.write(i >>> 8);
        output.write(i);
    }
    public static void writeBufTo(ByteArrayOutputStream buf, OutputStream output)
            throws IOException
    {
        buf.writeTo(output);
    }
}
