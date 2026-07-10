package com.enn3developer.enderlock.client;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.TreeMap;
import java.util.regex.Pattern;

import com.enn3developer.enderlock.Config;
import com.enn3developer.enderlock.EnderLock;

/**
 * SSH-style known-hosts store ({@code config/enderlock/known_hosts}). One entry per line:
 * {@code normalized_address SHA256-fingerprint}. Corrupted lines are dropped with a warning (the affected servers are
 * then treated as unknown and re-prompt) and the file is healed on the next successful trust.
 */
public final class KnownHostsStore {

    private static final Pattern FINGERPRINT_PATTERN = Pattern.compile("^[0-9A-F]{2}(?::[0-9A-F]{2}){31}$");
    private static final int DEFAULT_PORT = 25565;

    private static KnownHostsStore instance;

    private final File file;
    private final Map<String, String> pins = new HashMap<>();

    public static synchronized KnownHostsStore instance() {
        if (instance == null) {
            instance = new KnownHostsStore(new File(Config.getEnderLockDir(), "known_hosts"));
        }
        return instance;
    }

    private KnownHostsStore(File file) {
        this.file = file;
        load();
    }

    private void load() {
        if (!file.isFile()) {
            return;
        }
        try {
            List<String> lines = Files.readAllLines(file.toPath(), StandardCharsets.UTF_8);
            for (String raw : lines) {
                String line = raw.trim();
                if (line.isEmpty() || line.startsWith("#")) {
                    continue;
                }
                String[] parts = line.split("\\s+");
                if (parts.length != 2 || !FINGERPRINT_PATTERN.matcher(parts[1])
                    .matches()) {
                    EnderLock.LOG.warn(
                        "Corrupted known_hosts entry ignored (server will re-prompt, file heals on next trust): '{}'",
                        line);
                    continue;
                }
                pins.put(parts[0].toLowerCase(Locale.ROOT), parts[1]);
            }
        } catch (Exception e) {
            pins.clear();
            EnderLock.LOG.warn(
                "known_hosts is unreadable — treating every server as unknown; the file is rewritten on the next trust",
                e);
        }
    }

    /** The pinned fingerprint for a normalized address, or null if unknown. */
    public synchronized String getFingerprint(String normalizedAddress) {
        return pins.get(normalizedAddress);
    }

    /** Pins (or replaces) the fingerprint and flushes to disk before returning. */
    public synchronized void pin(String normalizedAddress, String fingerprint) throws IOException {
        pins.put(normalizedAddress, fingerprint);
        save();
    }

    private void save() throws IOException {
        File dir = file.getParentFile();
        if (dir != null && !dir.isDirectory() && !dir.mkdirs()) {
            throw new IOException("Could not create " + dir);
        }
        StringBuilder sb = new StringBuilder();
        sb.append("# EnderLock known hosts — trusted server key fingerprints (SHA-256).\n");
        sb.append("# Delete a line to forget a server; you will be prompted again on the next connect.\n");
        for (Map.Entry<String, String> entry : new TreeMap<>(pins).entrySet()) {
            sb.append(entry.getKey())
                .append(' ')
                .append(entry.getValue())
                .append('\n');
        }
        File tmp = new File(dir, file.getName() + ".tmp");
        Files.write(
            tmp.toPath(),
            sb.toString()
                .getBytes(StandardCharsets.UTF_8));
        try {
            Files
                .move(tmp.toPath(), file.toPath(), StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
        } catch (AtomicMoveNotSupportedException e) {
            Files.move(tmp.toPath(), file.toPath(), StandardCopyOption.REPLACE_EXISTING);
        }
    }

    /** Lowercased host with an explicit port, so {@code Example.org} and {@code example.org:25565} match. */
    public static String normalizeAddress(String host, int port) {
        String h = host.trim()
            .toLowerCase(Locale.ROOT);
        if (h.startsWith("[") && h.endsWith("]")) {
            h = h.substring(1, h.length() - 1);
        }
        int p = port > 0 ? port : DEFAULT_PORT;
        if (h.indexOf(':') >= 0) {
            // bare IPv6 literal
            return "[" + h + "]:" + p;
        }
        return h + ":" + p;
    }
}
