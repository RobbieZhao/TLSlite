import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.math.BigInteger;
import java.net.Socket;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;

public class Client {

    private static Socket socket;
    private static ByteArrayOutputStream historyBytes = new ByteArrayOutputStream();
    public static byte[] clientNonce;
    public static byte[] server_DHPublicKey;
    private static BigInteger Kc;
    private static BigInteger N;
    private static BigInteger g = new BigInteger("2");

    private static byte[] client_DHPublicKey;
    private static byte[] DHSharedSecret;


    private static SecretKeySpec serverEncrypt;
    private static SecretKeySpec clientEncrypt;
    private static SecretKeySpec serverMAC;
    private static SecretKeySpec clientMAC;
    private static IvParameterSpec serverIV;
    private static IvParameterSpec clientIV;

    private static byte[] generateNonce() {
        SecureRandom random = new SecureRandom();

        byte[] bytes = new byte[32];
        random.nextBytes(bytes);

        return bytes;
    }

    private static void sendClientNonce() throws IOException {
        clientNonce = generateNonce();
        Helper.sendBytes(socket, clientNonce);

        historyBytes.writeBytes(clientNonce);
    }

    public static void handshake() throws IOException, CertificateException, InvalidKeySpecException, NoSuchAlgorithmException, InvalidKeyException, SignatureException, NoSuchProviderException {
        // Step 1: client send the client nonce
        sendClientNonce();

        // Step 2: client read and verify server's signature:
        server_DHPublicKey = Helper.verifySignedDHPublicKey(socket, historyBytes);

        // Step 3: client sent to the server
        // 1. Client Certificate
        // 2. DiffieHellman public key
        // 3. Signed DiffieHellman public key (Sign[g^kc % N, Cpriv])
        sendClientCertificate();
        sendDHPublicKey();
        sendSignedDHPublicKey();

        // Step 4: client and server compute the shared secret here using DH
        DHSharedSecret = Helper.computeSharedDHKey(server_DHPublicKey, Kc.toByteArray(), N.toByteArray());

        // Step 5: client and server derive 6 session keys from the shared secret.
        // 2 each of bulk encryption keys, MAC keys, IVs for CBC using HKDF
        makeSecretKeys();

        // Step 6: receive MAC from server and verify
        Helper.receiveMAC(socket, serverMAC, historyBytes);

        // Step 7: MAC(all handshake messages so far including the previous step, Client's MAC key).
        Helper.sendMAC(socket, clientMAC, historyBytes);

        System.out.println("Client: finished handshakes");
    }

    public static void makeSecretKeys() throws InvalidKeyException, NoSuchAlgorithmException {
        byte[] prk = Helper.HMAC(clientNonce, DHSharedSecret);

        serverEncrypt = new SecretKeySpec(Helper.hkdfExpand(prk, "server encrypt"), "AES");
        clientEncrypt = new SecretKeySpec(Helper.hkdfExpand(serverEncrypt.getEncoded(), "client encrypt"), "AES");
        serverMAC = new SecretKeySpec(Helper.hkdfExpand(clientEncrypt.getEncoded(), "server MAC"), "AES");
        clientMAC = new SecretKeySpec(Helper.hkdfExpand(serverMAC.getEncoded(), "client MAC"), "AES");
        serverIV = new IvParameterSpec(Helper.hkdfExpand(clientMAC.getEncoded(), "server IV"));
        clientIV = new IvParameterSpec(Helper.hkdfExpand(serverIV.getIV(), "client IV"));
    }

    public static void sendClientCertificate() throws IOException, CertificateException {
        byte[] certificateBytes = Helper.read_certificate("client");

        Helper.sendBytes(socket, certificateBytes);
        historyBytes.writeBytes(certificateBytes);
    }

    public static void sendDHPublicKey() throws IOException {
        Kc = Helper.generateDHPrivateKey();
        N = new BigInteger(Helper.read_N(), 16);

        client_DHPublicKey = Helper.computeDHPubKey(g, Kc, N).toByteArray();

        Helper.sendBytes(socket, client_DHPublicKey);
        historyBytes.writeBytes(client_DHPublicKey);
    }

    public static void sendSignedDHPublicKey() throws IOException, InvalidKeySpecException, NoSuchAlgorithmException, SignatureException, InvalidKeyException {
        PrivateKey RSA_privateKey = Helper.readPrivateKey("client");

        byte[] signedDHPublicKey = Helper.signDHPublicKey(client_DHPublicKey, RSA_privateKey);

        Helper.sendBytes(socket, signedDHPublicKey);
        historyBytes.writeBytes(signedDHPublicKey);
    }

    public static void recv_file(String filename) throws IOException, ClassNotFoundException, NoSuchPaddingException, InvalidKeyException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {
        FileOutputStream fos = new FileOutputStream(filename);

        byte[] bytes = Helper.receiveEncrypted(socket, serverMAC, serverIV);

        fos.write(bytes);
    }

    public static void sendACK() throws InvalidKeyException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, NoSuchPaddingException, IOException {
        byte[] ACKBytes = "Filed Received".getBytes();

        Helper.sendEncrypted(socket, ACKBytes, clientMAC, clientIV);
    }

    public static void main(String[] args) throws IOException, NoSuchAlgorithmException, CertificateException, InvalidKeySpecException, InvalidKeyException, SignatureException, ClassNotFoundException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, NoSuchPaddingException, NoSuchProviderException {
        socket = new Socket("127.0.0.1", 8080);

        System.out.println("Client Connected");

        handshake();

        recv_file("paper_recv.pdf");

        System.out.println("Client: Successfully received a file from the server");

        sendACK();
    }
}
