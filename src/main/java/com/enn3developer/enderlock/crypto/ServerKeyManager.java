package com.enn3developer.enderlock.crypto;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.EnumSet;

import com.enn3developer.enderlock.Config;
import com.enn3developer.enderlock.EnderLock;

/**
 * Persistent server RSA identity. The private key ({@code config/enderlock/server_key.der}, PKCS#8 DER) is the single
 * source of truth; the public key and fingerprint files are convenience exports for admins to publish.
 *
 * Fail-closed: if the key cannot be loaded or created, {@link #getKeyPair()} returns null and the login mixin refuses
 * every EnderLock login instead of falling back to plaintext.
 */
public final class ServerKeyManager {

    private static final String PRIVATE_KEY_FILE = "server_key.der";
    private static final String PUBLIC_KEY_FILE = "server_key.pub.der";
    private static final String FINGERPRINT_FILE = "server_fingerprint.txt";
    private static final int KEY_BITS = 2048;

    private static boolean initialized;
    private static KeyPair keyPair;
    private static String fingerprint;

    private ServerKeyManager() {}

    /** The persistent keypair, or null if it is unavailable (logged loudly once). */
    public static synchronized KeyPair getKeyPair() {
        if (!initialized) {
            initialized = true;
            try {
                keyPair = loadOrCreate();
                fingerprint = FingerprintUtil.sha256Fingerprint(
                    keyPair.getPublic()
                        .getEncoded());
                EnderLock.LOG.info("EnderLock server key fingerprint (SHA-256): {}", fingerprint);
            } catch (Exception e) {
                keyPair = null;
                EnderLock.LOG.error(
                    "EnderLock could not load or create its server keypair. Encrypted logins will be REFUSED"
                        + " (no plaintext fallback). Fix or delete 'config/enderlock/{}' and restart.",
                    PRIVATE_KEY_FILE,
                    e);
            }
        }
        return keyPair;
    }

    public static synchronized String getFingerprint() {
        getKeyPair();
        return fingerprint;
    }

    /** Eagerly loads the key so problems surface at boot instead of at the first login. */
    public static void warmUp() {
        getKeyPair();
    }

    private static KeyPair loadOrCreate() throws GeneralSecurityException, IOException {
        File dir = Config.getEnderLockDir();
        File privateFile = new File(dir, PRIVATE_KEY_FILE);
        KeyPair pair;
        if (privateFile.isFile()) {
            pair = load(privateFile);
        } else {
            pair = generate(privateFile);
        }
        exportPublicParts(dir, pair.getPublic());
        return pair;
    }

    private static KeyPair load(File privateFile) throws GeneralSecurityException, IOException {
        byte[] der = Files.readAllBytes(privateFile.toPath());
        KeyFactory rsa = KeyFactory.getInstance("RSA");
        PrivateKey privateKey = rsa.generatePrivate(new PKCS8EncodedKeySpec(der));
        if (!(privateKey instanceof RSAPrivateCrtKey)) {
            throw new InvalidKeyException(privateFile + " does not contain an RSA (CRT) private key");
        }
        RSAPrivateCrtKey crt = (RSAPrivateCrtKey) privateKey;
        PublicKey publicKey = rsa.generatePublic(new RSAPublicKeySpec(crt.getModulus(), crt.getPublicExponent()));
        EnderLock.LOG.info("Loaded EnderLock server key from {}", privateFile);
        return new KeyPair(publicKey, privateKey);
    }

    private static KeyPair generate(File privateFile) throws GeneralSecurityException, IOException {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(KEY_BITS);
        KeyPair pair = generator.generateKeyPair();
        writeAtomically(
            privateFile,
            pair.getPrivate()
                .getEncoded());
        restrictPermissions(privateFile);
        EnderLock.LOG.info("Generated new {}-bit EnderLock server key at {}", KEY_BITS, privateFile);
        return pair;
    }

    /** Best-effort exports; failures don't affect operation. */
    private static void exportPublicParts(File dir, PublicKey publicKey) {
        try {
            writeAtomically(new File(dir, PUBLIC_KEY_FILE), publicKey.getEncoded());
            String fp = FingerprintUtil.sha256Fingerprint(publicKey.getEncoded());
            writeAtomically(
                new File(dir, FINGERPRINT_FILE),
                ("SHA-256 fingerprint of this server's EnderLock key (publish this to your players):\n" + fp + "\n")
                    .getBytes(StandardCharsets.UTF_8));
        } catch (IOException e) {
            EnderLock.LOG.warn("Could not export the public key/fingerprint files (not fatal)", e);
        }
    }

    private static void writeAtomically(File target, byte[] content) throws IOException {
        File tmp = new File(target.getParentFile(), target.getName() + ".tmp");
        Files.write(tmp.toPath(), content);
        try {
            Files.move(
                tmp.toPath(),
                target.toPath(),
                StandardCopyOption.REPLACE_EXISTING,
                StandardCopyOption.ATOMIC_MOVE);
        } catch (AtomicMoveNotSupportedException e) {
            Files.move(tmp.toPath(), target.toPath(), StandardCopyOption.REPLACE_EXISTING);
        }
    }

    private static void restrictPermissions(File file) {
        try {
            Files.setPosixFilePermissions(
                file.toPath(),
                EnumSet.of(
                    java.nio.file.attribute.PosixFilePermission.OWNER_READ,
                    java.nio.file.attribute.PosixFilePermission.OWNER_WRITE));
        } catch (UnsupportedOperationException | IOException e) {
            // non-POSIX filesystem (Windows) or permission issue; not fatal
        }
    }
}
