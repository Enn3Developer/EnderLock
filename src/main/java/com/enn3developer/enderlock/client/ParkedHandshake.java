package com.enn3developer.enderlock.client;

import java.io.IOException;
import java.security.PublicKey;

import javax.crypto.SecretKey;

import net.minecraft.network.NetworkManager;
import net.minecraft.network.login.client.C01PacketEncryptionResponse;
import net.minecraft.util.ChatComponentText;

import com.enn3developer.enderlock.EnderLock;
import com.enn3developer.enderlock.mixins.NetworkManagerAccessor;

import io.netty.channel.Channel;
import io.netty.handler.timeout.ReadTimeoutHandler;
import io.netty.util.concurrent.Future;
import io.netty.util.concurrent.GenericFutureListener;

/**
 * A login handshake halted before the Encryption Response is sent. Encryption is not yet enabled at this point, so
 * simply not answering is safe; the server waits (with its raised login timeout) until the user decides.
 */
public final class ParkedHandshake {

    /** Vanilla client read timeout (seconds), restored when the handshake resumes. */
    private static final int VANILLA_READ_TIMEOUT = 20;

    private final NetworkManager networkManager;
    private final SecretKey secretKey;
    private final PublicKey serverPublicKey;
    private final byte[] verifyToken;
    private final String address;
    private final String fingerprint;
    private volatile boolean resolved;

    public ParkedHandshake(NetworkManager networkManager, SecretKey secretKey, PublicKey serverPublicKey,
        byte[] verifyToken, String address, String fingerprint) {
        this.networkManager = networkManager;
        this.secretKey = secretKey;
        this.serverPublicKey = serverPublicKey;
        this.verifyToken = verifyToken;
        this.address = address;
        this.fingerprint = fingerprint;
    }

    public NetworkManager getNetworkManager() {
        return networkManager;
    }

    public String getAddress() {
        return address;
    }

    public String getFingerprint() {
        return fingerprint;
    }

    /**
     * Extends the client-side netty read timeout so the connection survives while the user is on the trust screen
     * (the server sends nothing while we are parked).
     */
    public void parkReadTimeout(int seconds) {
        replaceReadTimeout(seconds);
    }

    /** User trusts the key: persist the pin first (crash-safe), then resume the handshake. */
    public void accept() {
        if (resolved) {
            return;
        }
        try {
            KnownHostsStore.instance()
                .pin(address, fingerprint);
        } catch (IOException e) {
            EnderLock.LOG.error("Could not save known_hosts — you may be prompted again on the next connect", e);
        }
        resume();
    }

    /** Sends the Encryption Response and enables encryption once it is flushed, exactly like vanilla. */
    public void resume() {
        if (resolved) {
            return;
        }
        resolved = true;
        replaceReadTimeout(VANILLA_READ_TIMEOUT);
        final NetworkManager manager = this.networkManager;
        final SecretKey key = this.secretKey;
        manager.scheduleOutboundPacket(
            new C01PacketEncryptionResponse(secretKey, serverPublicKey, verifyToken),
            new GenericFutureListener[] { new GenericFutureListener<Future<? super Void>>() {

                @Override
                public void operationComplete(Future<? super Void> future) {
                    try {
                        manager.enableEncryption(key);
                    } catch (Throwable t) {
                        // fail closed: never continue on a half-encrypted pipeline
                        EnderLock.LOG.error("Failed to enable encryption — closing connection", t);
                        manager.closeChannel(new ChatComponentText("EnderLock: failed to enable encryption"));
                    }
                }
            } });
    }

    /** User refuses: close the channel with a clear reason (shown on the vanilla disconnect screen). */
    public void disconnect(String reason) {
        if (resolved) {
            return;
        }
        resolved = true;
        networkManager.closeChannel(new ChatComponentText(reason));
    }

    private void replaceReadTimeout(int seconds) {
        try {
            Channel channel = ((NetworkManagerAccessor) (Object) networkManager).enderlock$getChannel();
            channel.pipeline()
                .replace("timeout", "timeout", new ReadTimeoutHandler(seconds));
        } catch (Exception e) {
            EnderLock.LOG.warn("Could not adjust the network read timeout", e);
        }
    }
}
