package com.enn3developer.enderlock;

import java.io.File;

import net.minecraftforge.common.config.Configuration;

public class Config {

    /** Server-side master switch. When false the vanilla offline (plaintext) login flow is left untouched. */
    public static boolean enabled = true;

    /**
     * Login timeout in seconds, applied on the server to connections going through the EnderLock handshake and on the
     * client as the window in which the trust screen may stay open. Vanilla kicks after 30 seconds, which is not
     * enough for a user reading a fingerprint confirmation screen.
     */
    public static int loginTimeoutSeconds = 300;

    /**
     * Client-side: attempt the regular Mojang session-server join (best effort, failures are ignored) before the
     * EnderLock handshake. Keeps premium accounts working on online-mode servers. Offline accounts simply fail the
     * call and continue.
     */
    public static boolean attemptMojangSessionJoin = true;

    private static File enderLockDir;

    public static void synchronizeConfiguration(File configFile, File modConfigDir) {
        enderLockDir = new File(modConfigDir, "enderlock");

        Configuration configuration = new Configuration(configFile);

        enabled = configuration.getBoolean(
            "enabled",
            Configuration.CATEGORY_GENERAL,
            enabled,
            "Master switch for the server side. When false, offline-mode logins stay plaintext like vanilla.");
        loginTimeoutSeconds = configuration.getInt(
            "loginTimeoutSeconds",
            Configuration.CATEGORY_GENERAL,
            loginTimeoutSeconds,
            30,
            3600,
            "Login timeout in seconds for connections handled by EnderLock. Raised well above vanilla's 30s"
                + " because the client may sit on the key-confirmation screen.");
        attemptMojangSessionJoin = configuration.getBoolean(
            "attemptMojangSessionJoin",
            "client",
            attemptMojangSessionJoin,
            "Attempt the regular Mojang session join before the EnderLock handshake (best effort, failures are"
                + " ignored). Keeps premium accounts compatible with online-mode servers. Offline/LAN-only setups"
                + " can disable this to avoid a useless HTTP call on every connect.");

        if (configuration.hasChanged()) {
            configuration.save();
        }
    }

    /** Directory holding the server keypair and the client known_hosts file ({@code config/enderlock}). */
    public static File getEnderLockDir() {
        File dir = enderLockDir;
        if (dir == null) {
            throw new IllegalStateException("EnderLock configuration has not been initialised yet");
        }
        if (!dir.isDirectory() && !dir.mkdirs()) {
            EnderLock.LOG.error("Could not create directory {}", dir);
        }
        return dir;
    }
}
