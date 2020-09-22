import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.math.BigInteger;
import java.net.Socket;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Arrays;
import java.util.Random;
import java.util.Scanner;

public class Helper {

    public static BigInteger computeDHPubKey(BigInteger g, BigInteger K, BigInteger N) {
        return g.modPow(K, N);
    }

    public static BigInteger generateDHPrivateKey() {
        // Generate a 2048 bit number that will be used to compute the public key
        //   e.g. Ks in g^Ks % N
        // Note: This number is never shared nor saved to disc
        Random rnd = new Random();
        BigInteger K = new BigInteger(2048, rnd);

        return K;
    }

    // N is the 2048-bit prime in DH
    // The file is from: https://www.ietf.org/rfc/rfc3526.txt
    public static String read_N() throws FileNotFoundException {
        Scanner scanner = new Scanner(new File("Crypto/BigPrime_DH.txt"));

        String str = "";
        while (scanner.hasNext()) {
            str += scanner.next();
        }

        return str;
    }

    public static void sendBytes(Socket socket, byte[] toBeSent) throws IOException {
        DataOutputStream dOut = new DataOutputStream(socket.getOutputStream());

        dOut.writeInt(toBeSent.length);
        dOut.write(toBeSent);
    }

    public static void sendInt(Socket socket, int num) throws IOException {
        DataOutputStream dOut = new DataOutputStream(socket.getOutputStream());

        dOut.writeInt(num);
    }

    public static int receiveInt(Socket socket) throws IOException {
        DataInputStream dIn = new DataInputStream(socket.getInputStream());

        return dIn.readInt();
    }

    public static byte[] receiveBytes(Socket socket) throws IOException {
        DataInputStream dIn = new DataInputStream(socket.getInputStream());

        int length = dIn.readInt();
        if(length>0) {
            byte[] message = new byte[length];
            dIn.readFully(message, 0, message.length);
            return message;
        }

        return null;
    }

    // The two sides should be "client" or "server"
    public static byte[] read_certificate(String side) throws IOException, CertificateException {
        String filename;
        if (side.equals("client"))
            filename = "Crypto/CASignedClientCertificate.pem";
        else
            filename = "Crypto/CASignedServerCertificate.pem";

        InputStream inputStream = new FileInputStream(filename);

        return inputStream.readAllBytes();
    }

    public static PublicKey getCAPublicKey() throws IOException, CertificateException {
        String filename = "Crypto/CAcertificate.pem";

        InputStream inputStream = new FileInputStream(filename);

        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");

        InputStream certificateInputStream = new ByteArrayInputStream(inputStream.readAllBytes());

        Certificate certificate = certificateFactory.generateCertificate(certificateInputStream);

        return certificate.getPublicKey();
    }

    public static byte[] signDHPublicKey(byte[] DHPublicKey, PrivateKey RSA_privateKey) throws NoSuchAlgorithmException, SignatureException, InvalidKeyException, IOException, InvalidKeySpecException {
        // Create a signature object with the specified algorithm
        Signature signature = Signature.getInstance("SHA256WithRSA");

        // Initialize the signature object
        SecureRandom secureRandom = new SecureRandom();
        signature.initSign(RSA_privateKey, secureRandom);

        // Create a digital signature for the DH public key,
        // i.e. sign the DH public key using the DSA private key
        signature.update(DHPublicKey);

        return signature.sign();
    }

    /**
     * Read RSA private key from "clientPrivateKey.der" or "serverPrivateKey.der"
     * @param side indicating which private key to write: "client" or "server"
     * @return the RSA private key
     */
    public static PrivateKey readPrivateKey(String side) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        String filename = "Crypto/" + side + "PrivateKey.der";

        InputStream inputStream = new FileInputStream(filename);
        byte[] keyBytes = inputStream.readAllBytes();

        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory kf = KeyFactory.getInstance("RSA");

        return kf.generatePrivate(spec);
    }

    public static PublicKey getRSAPubKey(byte[] certificateBytes) throws  CertificateException {

        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");

        InputStream certificateInputStream = new ByteArrayInputStream(certificateBytes);

        Certificate certificate = certificateFactory.generateCertificate(certificateInputStream);

        return certificate.getPublicKey();
    }

    public static Certificate getCertificate(byte[] certificateBytes) throws  CertificateException {

        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");

        InputStream certificateInputStream = new ByteArrayInputStream(certificateBytes);

        Certificate certificate = certificateFactory.generateCertificate(certificateInputStream);

        return certificate;
    }

    public static boolean verify(byte[] signature_toBeVerified,
                                 byte[] DHPubKey_toBeVerified,
                                 PublicKey RSAPubKey) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature signature = Signature.getInstance("SHA256WithRSA");

        signature.initVerify(RSAPubKey);

        signature.update(DHPubKey_toBeVerified);

        return signature.verify(signature_toBeVerified);
    }

    public static byte[] verifySignedDHPublicKey(Socket socket,
                                                 ByteArrayOutputStream historyBytes) throws IOException, NoSuchAlgorithmException, InvalidKeyException, SignatureException, CertificateException, NoSuchProviderException {
        // 1. read Certificate
        // 2. read DiffieHellman public key
        // 3. read Signed DiffieHellman public key
        byte[] certificate = Helper.receiveBytes(socket);
        historyBytes.writeBytes(certificate);
        PublicKey RSAPublicKey = Helper.getRSAPubKey(certificate);

        PublicKey CAPublicKey = getCAPublicKey();
        Certificate CACertificate = getCertificate(certificate);
        CACertificate.verify(CAPublicKey);


        System.out.println("passed");

        byte[] DHPublicKey = Helper.receiveBytes(socket);
        historyBytes.writeBytes(DHPublicKey);
        byte[] signedDHPublicKey = Helper.receiveBytes(socket);
        historyBytes.writeBytes(signedDHPublicKey);

        boolean verified = Helper.verify(signedDHPublicKey, DHPublicKey, RSAPublicKey);

        if (!verified) {
            socket.close();
            System.exit(1);
        }

        return DHPublicKey;
    }

    public static byte[] computeSharedDHKey(byte[] _T, byte[] _K, byte[] _N) {
        // T is the other side's public key
        BigInteger T = new BigInteger(_T);
        // K is this side's private key
        BigInteger K = new BigInteger(_K);
        BigInteger N = new BigInteger(_N);

        return T.modPow(K, N).toByteArray();
    }

    public static boolean equals(byte[] a, byte[] b) {
        if (a.length != b.length) {
            return false;
        }

        for (int i = 0; i < a.length; i++)
            if (a[i] != b[i]) {
                System.out.println("bytes");
                return false;
            }

        return true;
    }

    public static byte[] HMAC(byte[] key, byte[] data) throws NoSuchAlgorithmException, InvalidKeyException {
        Mac sha256_HMAC = Mac.getInstance("HmacSHA256");
        SecretKeySpec keySpec = new SecretKeySpec(key, "HmacSHA256");
        sha256_HMAC.init(keySpec);

        // The size of HMAC bytes is a fixed to be 32
        byte [] mac_data = sha256_HMAC.doFinal(data);

        return mac_data;
    }

    public static byte[] addOneByteToTag(String tag) {
        byte[] result = new byte[tag.length() + 1];

        byte[] originalBytes = tag.getBytes();
        System.arraycopy(originalBytes, 0, result, 0, originalBytes.length);

        // Add a byte with value 1 to the end of tag
        result[tag.length()] = (byte)1;

        return result;
    }

    public static byte[] hkdfExpand(byte[] key, String tag) throws InvalidKeyException, NoSuchAlgorithmException {
        byte[] okm = HMAC(key, addOneByteToTag(tag));

        // Return the first 16 bytes
        return Arrays.copyOfRange(okm, 0, 16);
    }

    public static void sendMAC(Socket socket, SecretKeySpec MACKey, ByteArrayOutputStream os) throws InvalidKeyException, NoSuchAlgorithmException, IOException {
        byte[] HMAC = Helper.HMAC(MACKey.getEncoded(), os.toByteArray());

        Helper.sendBytes(socket, HMAC);
        os.writeBytes(HMAC);
    }

    public static void receiveMAC(Socket socket, SecretKeySpec MACKey, ByteArrayOutputStream os) throws IOException, InvalidKeyException, NoSuchAlgorithmException {
        byte[] HMAC_received = Helper.receiveBytes(socket);

        byte[] HMAC = Helper.HMAC(MACKey.getEncoded(), os.toByteArray());
        if (!Helper.equals(HMAC_received, HMAC)) {
            socket.close();
            System.exit(1);
        }

        os.writeBytes(HMAC_received);
    }

    public static byte[] encrypt(byte[] message, SecretKeySpec key, IvParameterSpec IV) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, InvalidAlgorithmParameterException, BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");

        cipher.init(Cipher.ENCRYPT_MODE, key, IV);

        return cipher.doFinal(message);
    }

    public static byte[] decrypt(byte[] encrypted, SecretKeySpec key, IvParameterSpec IV) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");

        cipher.init(Cipher.DECRYPT_MODE, key, IV);

        return cipher.doFinal(encrypted);
    }

    public static byte[] concatenate(byte[] a, byte[] b) {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();

        bos.writeBytes(a);
        bos.writeBytes(b);

        return bos.toByteArray();
    }

    public static void sendEncrypted(Socket socket, byte[] toBeSent, SecretKeySpec key, IvParameterSpec IV) throws IOException, NoSuchPaddingException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException {
        // Divide the bytes into 100-byte chunks
        int chunkSize = 1000;
        int numOfChunks = (int) Math.ceil(toBeSent.length / (double)chunkSize);

        Helper.sendInt(socket, numOfChunks);

        for (int i = 0; i < numOfChunks; i++) {
            byte[] messageBytes = Arrays.copyOfRange(toBeSent, i * chunkSize, (i + 1) * chunkSize);
            byte[] HMAC = Helper.HMAC(key.getEncoded(), messageBytes);

            byte[] concatenatedBytes = Helper.concatenate(messageBytes, HMAC);

            byte[] encryptedBytes = Helper.encrypt(concatenatedBytes, key, IV);

            Helper.sendBytes(socket, encryptedBytes);
        }
    }

    public static byte[] receiveEncrypted(Socket socket, SecretKeySpec key, IvParameterSpec IV) throws IOException, InvalidKeyException, NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, NoSuchPaddingException {

        ByteArrayOutputStream bos = new ByteArrayOutputStream();

        int numOfChunks = Helper.receiveInt(socket);

        for (int i = 0; i < numOfChunks; i++) {
            byte[] encrypted = Helper.receiveBytes(socket);
            byte[] original = Helper.decrypt(encrypted, key, IV);

            byte[] message = new byte[original.length - 32];
            byte[] HMAC_received = new byte[32];
            System.arraycopy(original, 0, message, 0, original.length - 32);
            System.arraycopy(original, original.length-32, HMAC_received, 0, 32);

            byte[] HMAC = Helper.HMAC(key.getEncoded(), message);
            if (!Helper.equals(HMAC, HMAC_received)) {
                socket.close();
                System.exit(1);
            }

            bos.write(message);
        }

        return bos.toByteArray();
    }
}
