package org.bouncycastle.tokenBinding;

import org.apache.commons.codec.binary.Base64;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jsse.provider.BouncyCastleJsseProvider;
import org.bouncycastle.jsse.provider.NegotiatedTokenBinding;
import org.bouncycastle.jsse.provider.ProvSSLSessionImpl;
import org.bouncycastle.jsse.provider.ProvSSLSocketFactory;
import org.bouncycastle.tls.TlsSessionImpl;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManagerFactory;
import javax.xml.bind.DatatypeConverter;
import java.io.BufferedWriter;
import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.InputStream;
import java.io.OutputStreamWriter;
import java.net.URLEncoder;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.RSAPublicKey;
import java.util.Enumeration;

import static org.bouncycastle.tokenBinding.TBUtil.writeBufTo;
import static org.bouncycastle.tokenBinding.TBUtil.writeOpaque16;
import static org.bouncycastle.tokenBinding.TBUtil.writeOpaque8;
import static org.bouncycastle.tokenBinding.TBUtil.writeUint16;
import static org.bouncycastle.tokenBinding.TBUtil.writeUint8;

/**
 * This is a simple http client to test token binding
 */
public class SampleHttpClient {
    private KeyPair providedKeypair;
    private KeyPair referredKeypair;

    public static void main(String args[]) throws Exception {
        SampleHttpClient sampleHttpClient = new SampleHttpClient();
        String client_id = "b9WotKTjVk988BSpEhSWNB7BxN8a";
        String client_secret = "kQY8rAqj8sDGPqYL4EFvQA78cpsa";
        String host = "wso2.is.com";
        int port = 443;

        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
        if (Security.getProvider(BouncyCastleJsseProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleJsseProvider());
        }

        TrustManagerFactory trustMgrFact = TrustManagerFactory.getInstance("PKIX",
                BouncyCastleJsseProvider.PROVIDER_NAME);

        KeyManagerFactory keyMgrFact = KeyManagerFactory.getInstance("PKIX",
                BouncyCastleJsseProvider.PROVIDER_NAME);

        KeyStore ks = KeyStore.getInstance("JKS");

        ks.load(new FileInputStream("keystore.jks"), "123456".toCharArray());

        keyMgrFact.init(ks, "123456".toCharArray());

        trustMgrFact.init(ks);

        SSLContext clientContext = SSLContext.getInstance("TLS", BouncyCastleJsseProvider.PROVIDER_NAME);

        clientContext.init(keyMgrFact.getKeyManagers(), trustMgrFact.getTrustManagers(),
                SecureRandom.getInstance("DEFAULT", BouncyCastleProvider.PROVIDER_NAME));


        ProvSSLSocketFactory factt = (ProvSSLSocketFactory) clientContext.getSocketFactory();


        SSLSocket socket = (SSLSocket) factt.createSocket(host, port);

        socket.startHandshake();

        NegotiatedTokenBinding negotiatedTokenBinding = sampleHttpClient.getTokenbinding(clientContext);

        sampleHttpClient.initKeypairs();

        String secTokenBinding = new String(Base64.encodeBase64URLSafe(sampleHttpClient.createTokenBindingMessage(
                negotiatedTokenBinding)));
//        String secTokenBinding=new String(Base64.encodeBase64URLSafe(sampleHttpClient.createTokenBindingMessage(providedKeypair,
//                negotiatedTokenBinding)));

        String data1 = URLEncoder.encode("grant_type", "UTF-8") + "=" + URLEncoder.encode("password", "UTF-8");
        String data2 = URLEncoder.encode("username", "UTF-8") + "=" + URLEncoder.encode("admin", "UTF-8");
        String data3 = URLEncoder.encode("password", "UTF-8") + "=" + URLEncoder.encode("admin", "UTF-8");
        String data4 = URLEncoder.encode("client_id", "UTF-8") + "=" + URLEncoder.encode(client_id, "UTF-8");
        String data5 = URLEncoder.encode("client_secret", "UTF-8") + "=" + URLEncoder.encode(client_secret, "UTF-8");

        String data = data1 + "&" + data2 + "&" + data3 + "&" + data4 + "&" + data5;

        BufferedWriter wr = new BufferedWriter(new OutputStreamWriter(socket.getOutputStream(), "UTF8"));
        wr.write("POST /oauth2/token  HTTP/1.1\r\n");
        wr.write("Content-Length: " + data.length() + "\r\n");
        wr.write("Content-Type: application/x-www-form-urlencoded\r\n");
        wr.write("Host: localhost \r\n");
        wr.write("Connection: keep-alive");
        wr.write("Cache-Control: no-cache\r\n");
        wr.write("Sec-token-binding: " + secTokenBinding + "\r\n");
        wr.write("\r\n");

        wr.write(data);
        wr.flush();

        byte[] buffer = new byte[1024];
        int read;
        InputStream is = socket.getInputStream();
        while ((read = is.read(buffer)) != -1) {
            String output = new String(buffer, 0, read);
            System.out.print(output);
            System.out.flush();
        }
        socket.close();

    }

    private void initKeypairs() throws NoSuchProviderException, NoSuchAlgorithmException {
        providedKeypair = createKeypair();
        referredKeypair = createKeypair();
    }


    public byte[] getSignedTokenBindingStructure(NegotiatedTokenBinding negotiatedTokenBinding, KeyPair keyPair, int
            type) throws
            Exception {
        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        writeUint8(type, buf);
        writeUint8(0, buf);
        return signMessage(concat(buf.toByteArray(), negotiatedTokenBinding.exportKeyingMaterial), keyPair);
    }

    public byte[] concat(byte[] a, byte[] b) {
        byte[] c = new byte[a.length + b.length];
        System.arraycopy(a, 0, c, 0, a.length);
        System.arraycopy(b, 0, c, a.length, b.length);
        return c;
    }

    public ByteArrayOutputStream createTokenBindingStructure(NegotiatedTokenBinding negotiatedTokenBinding, int type,
                                                             KeyPair keyPair)
            throws Exception {
        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        writeUint8(type, buf);
        writeUint8(0, buf);

        RSAPublicKey pub = (RSAPublicKey) keyPair.getPublic();
        byte[] exponent = pub.getPublicExponent().toByteArray();
        byte[] modulus = pub.getModulus().toByteArray();

        int keylength = exponent.length + modulus.length + 3;
        writeUint16(keylength, buf);
        writeOpaque16(modulus, buf);
        writeOpaque8(exponent, buf);
        writeOpaque16(getSignedTokenBindingStructure(negotiatedTokenBinding, keyPair, type), buf);
        writeUint16(0, buf);
        return buf;
    }

    public byte[] createTokenBindingMessage(NegotiatedTokenBinding negotiatedTokenBinding) throws Exception {
        ByteArrayOutputStream provideTB = createTokenBindingStructure(negotiatedTokenBinding, 0, providedKeypair);
        ByteArrayOutputStream referredTB = createTokenBindingStructure(negotiatedTokenBinding, 1, referredKeypair);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        writeUint16(provideTB.size() + referredTB.size(), out);
        writeBufTo(provideTB, out);
        writeBufTo(referredTB, out);
        return out.toByteArray();
    }

    public byte[] createTokenBindingMessage(KeyPair provided, NegotiatedTokenBinding negotiatedTokenBinding) throws
            Exception {
        ByteArrayOutputStream provideTB = createTokenBindingStructure(negotiatedTokenBinding, 0, provided);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        writeUint16(provideTB.size(), out);
        writeBufTo(provideTB, out);
        return out.toByteArray();
    }

    public KeyPair createKeypair() throws NoSuchProviderException, NoSuchAlgorithmException {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA", "BC");
        keyGen.initialize(2048, new SecureRandom());
        return keyGen.generateKeyPair();

    }

    public byte[] signMessage(byte[] message, KeyPair keyPair) throws NoSuchProviderException, NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature signature = Signature.getInstance("SHA256withRSA", "BC");
        signature.initSign(keyPair.getPrivate());
        signature.update(message);
        return signature.sign();
    }

    public NegotiatedTokenBinding getTokenbinding(SSLContext sslContext) throws Exception {
        Enumeration<byte[]> e = sslContext.getClientSessionContext().getIds();
        NegotiatedTokenBinding s = null;
        while (e.hasMoreElements()) {
            byte[] b = e.nextElement();
            System.out.println("session id: " + DatatypeConverter.printHexBinary(b).toLowerCase());
            ProvSSLSessionImpl Session = (ProvSSLSessionImpl) sslContext.getClientSessionContext().getSession(b);
            TlsSessionImpl tlsSession = (TlsSessionImpl) Session.getTlsSession();
            s = tlsSession.exportSessionParameters().getNegotiatedTokenBinding();
        }
        return s;
    }

}
