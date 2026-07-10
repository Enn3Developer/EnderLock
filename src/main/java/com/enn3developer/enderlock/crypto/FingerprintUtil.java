package com.enn3developer.enderlock.crypto;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/** SHA-256 fingerprints of DER-encoded public keys, displayed SSH-style as colon-separated hex. */
public final class FingerprintUtil {

    private FingerprintUtil() {}

    public static String sha256Fingerprint(byte[] derEncodedKey) {
        MessageDigest digest;
        try {
            digest = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("JVM without SHA-256", e);
        }
        byte[] hash = digest.digest(derEncodedKey);
        StringBuilder sb = new StringBuilder(hash.length * 3 - 1);
        for (int i = 0; i < hash.length; i++) {
            if (i > 0) {
                sb.append(':');
            }
            sb.append(Character.forDigit((hash[i] >> 4) & 0xF, 16));
            sb.append(Character.forDigit(hash[i] & 0xF, 16));
        }
        return sb.toString()
            .toUpperCase(java.util.Locale.ROOT);
    }

    /** Splits a fingerprint into two roughly equal lines at a colon boundary, for narrow GUI rendering. */
    public static String[] splitFingerprint(String fingerprint) {
        int cut = fingerprint.indexOf(':', fingerprint.length() / 2 - 1);
        if (cut < 0) {
            return new String[] { fingerprint };
        }
        return new String[] { fingerprint.substring(0, cut), fingerprint.substring(cut + 1) };
    }
}
