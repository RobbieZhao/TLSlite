import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.math.BigInteger;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;

public class Server {

    private static int port = 8080;
    private static ServerSocket serverSocket;
    private static Socket socket;
    private static BigInteger Ks;
    private static BigInteger N;
    private static byte[] server_DHPublicKey;
    private static byte[] client_DHPublicKey;
    private static byte[] DHSharedSecret;
    private static BigInteger g = new BigInteger("2");

    private static ByteArrayOutputStream historyBytes = new ByteArrayOutputStream();

    public static byte[] clientNonce;

    private static SecretKeySpec serverEncrypt;
    private static SecretKeySpec clientEncrypt;
    private static SecretKeySpec serverMAC;
    private static SecretKeySpec clientMAC;
    private static IvParameterSpec serverIV;
    private static IvParameterSpec clientIV;

    public static void receiveNonce() throws IOException {
        clientNonce = Helper.receiveBytes(socket);

        historyBytes.writeBytes(clientNonce);
    }

    public static void sendServerCertificate() throws IOException, CertificateException {
        byte[] certificateBytes = Helper.read_certificate("server");

        Helper.sendBytes(socket, certificateBytes);
        historyBytes.writeBytes(certificateBytes);
    }

    public static void sendDHPublicKey() throws IOException {
        Ks = Helper.generateDHPrivateKey();
        N = new BigInteger(Helper.read_N(), 16);

        server_DHPublicKey = Helper.computeDHPubKey(g, Ks, N).toByteArray();

        Helper.sendBytes(socket, server_DHPublicKey);
        historyBytes.writeBytes(server_DHPublicKey);
    }

    public static void sendSignedDHPublicKey() throws IOException, InvalidKeySpecException, NoSuchAlgorithmException, SignatureException, InvalidKeyException {
        PrivateKey RSA_privateKey = Helper.readPrivateKey("server");

        byte[] signedDHPublicKey = Helper.signDHPublicKey(server_DHPublicKey, RSA_privateKey);

        Helper.sendBytes(socket, signedDHPublicKey);
        historyBytes.writeBytes(signedDHPublicKey);
    }

    public static void handshake() throws IOException, CertificateException, NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, SignatureException, NoSuchProviderException {
        // Step 1: receive the client nonce sent by client
        receiveNonce();

        // Step 2: Server:
        // 1. Send server Certificate
        // 2. DiffieHellman public key
        // 3. Signed DiffieHellman public key (Sign[g^ks % N, Spriv])
        sendServerCertificate();
        sendDHPublicKey();
        sendSignedDHPublicKey();

        // Step 3: server read and verify client's signature:
        client_DHPublicKey = Helper.verifySignedDHPublicKey(socket, historyBytes);

        // Step 4: client and server compute the shared secret here using DH
        DHSharedSecret = Helper.computeSharedDHKey(client_DHPublicKey, Ks.toByteArray(), N.toByteArray());

        // Step 5: client and server derive 6 session keys from the shared secret.
        // 2 each of bulk encryption keys, MAC keys, IVs for CBC using HKDF
        makeSecretKeys();

        // Step 6: MAC(all handshake messages so far, Server's MAC key)
        Helper.sendMAC(socket, serverMAC, historyBytes);

        // Step 7: receive MAC from server and verify
        Helper.receiveMAC(socket, clientMAC, historyBytes);

        System.out.println("Server: finished handshakes");
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

    public static void sendFile(String filename) throws IOException, InvalidKeyException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, NoSuchPaddingException {
        InputStream inputStream = new FileInputStream(filename);

        byte[] allBytes = inputStream.readAllBytes();

        Helper.sendEncrypted(socket, allBytes, serverMAC, serverIV);
    }

    public static void receiveACK() throws IOException, InvalidKeyException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, NoSuchPaddingException {

        byte[] ACKBytes = Helper.receiveEncrypted(socket, clientMAC, clientIV);
        String ACKMessage = new String(ACKBytes);

        if (ACKMessage.equals("Filed Received")) {
            System.out.println("Successfully received an ACK");
        }
    }

    public static void main(String[] args) throws IOException, CertificateException, InvalidKeySpecException, NoSuchAlgorithmException, InvalidKeyException, SignatureException, ClassNotFoundException, NoSuchPaddingException, BadPaddingException, InvalidAlgorithmParameterException, IllegalBlockSizeException, NoSuchProviderException {

        serverSocket = new ServerSocket(port);

        System.out.println("Server waiting for connections on 8080");

        socket = serverSocket.accept();

        System.out.println("Server Connected");

        handshake();

        sendFile("paper.pdf");

        System.out.println("Successfully sent the file to server");

        receiveACK();
    }
}
