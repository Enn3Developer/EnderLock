package com.enn3developer.enderlock.mixins;

import java.math.BigInteger;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.security.PublicKey;
import java.util.UUID;

import javax.crypto.SecretKey;

import net.minecraft.client.Minecraft;
import net.minecraft.client.multiplayer.ServerAddress;
import net.minecraft.client.multiplayer.ServerData;
import net.minecraft.client.network.NetHandlerLoginClient;
import net.minecraft.network.NetworkManager;
import net.minecraft.network.login.server.S01PacketEncryptionRequest;
import net.minecraft.util.ChatComponentText;
import net.minecraft.util.CryptManager;

import org.spongepowered.asm.mixin.Final;
import org.spongepowered.asm.mixin.Mixin;
import org.spongepowered.asm.mixin.Shadow;
import org.spongepowered.asm.mixin.Unique;
import org.spongepowered.asm.mixin.injection.At;
import org.spongepowered.asm.mixin.injection.Inject;
import org.spongepowered.asm.mixin.injection.callback.CallbackInfo;

import com.enn3developer.enderlock.Config;
import com.enn3developer.enderlock.EnderLock;
import com.enn3developer.enderlock.client.GuiTrustServer;
import com.enn3developer.enderlock.client.KnownHostsStore;
import com.enn3developer.enderlock.client.ParkedHandshake;
import com.enn3developer.enderlock.crypto.FingerprintUtil;
import com.mojang.authlib.yggdrasil.YggdrasilAuthenticationService;

/**
 * Takes over the client side of the encryption handshake: the Mojang session join becomes best-effort (it must not
 * abort the login — offline accounts cannot complete it), and the server's public key is checked against the
 * known-hosts store before the Encryption Response is sent (trust on first use).
 *
 * Fail-closed: any error while handling the request closes the channel; the Encryption Response is only ever sent by
 * {@link ParkedHandshake#resume()} after a fingerprint match or an explicit user decision.
 */
@Mixin(NetHandlerLoginClient.class)
public abstract class MixinNetHandlerLoginClient {

    @Shadow
    @Final
    private Minecraft field_147394_b;

    @Shadow
    @Final
    private NetworkManager field_147393_d;

    @Inject(method = "handleEncryptionRequest", at = @At("HEAD"), cancellable = true)
    private void enderlock$handleEncryptionRequest(S01PacketEncryptionRequest packet, CallbackInfo ci) {
        ci.cancel();
        try {
            this.enderlock$process(packet);
        } catch (Throwable t) {
            EnderLock.LOG.error("Encryption handshake failed — closing connection", t);
            this.field_147393_d
                .closeChannel(new ChatComponentText("EnderLock: encryption handshake failed (" + t + ")"));
        }
    }

    @Unique
    private void enderlock$process(S01PacketEncryptionRequest packet) {
        final PublicKey publicKey = packet.func_149608_d();
        if (publicKey == null || !"RSA".equalsIgnoreCase(publicKey.getAlgorithm())) {
            throw new IllegalStateException("Server sent an invalid public key");
        }
        final SecretKey secretKey = CryptManager.createNewSharedKey();

        if (Config.attemptMojangSessionJoin) {
            enderlock$bestEffortSessionJoin(packet.func_149609_c(), publicKey, secretKey);
        }

        String fingerprint = FingerprintUtil.sha256Fingerprint(publicKey.getEncoded());
        String address = this.enderlock$resolveAddress();
        final ParkedHandshake handshake = new ParkedHandshake(
            this.field_147393_d,
            secretKey,
            publicKey,
            packet.func_149607_e(),
            address,
            fingerprint);

        String pinned = KnownHostsStore.instance()
            .getFingerprint(address);
        if (fingerprint.equals(pinned)) {
            EnderLock.LOG.info("Server key for {} matches known_hosts, proceeding", address);
            handshake.resume();
            return;
        }

        // Unknown or mismatching key: park the handshake (no response sent, encryption not yet enabled)
        // and ask the user on the main thread. The read timeout is extended so the connection survives.
        if (pinned == null) {
            EnderLock.LOG
                .info("First connection to {} — asking the user to confirm fingerprint {}", address, fingerprint);
        } else {
            EnderLock.LOG.warn(
                "SERVER KEY MISMATCH for {}! expected {} received {} — asking the user",
                address,
                pinned,
                fingerprint);
        }
        handshake.parkReadTimeout(Config.loginTimeoutSeconds + 60);
        final GuiTrustServer gui = new GuiTrustServer(handshake, pinned);
        final Minecraft mc = this.field_147394_b;
        mc.func_152344_a(new Runnable() {

            @Override
            public void run() {
                mc.displayGuiScreen(gui);
            }
        });
    }

    /**
     * Vanilla aborts the login when the Mojang session join fails; offline accounts can never complete it, so here it
     * is reduced to best effort. Premium accounts on online-mode servers still get a valid session out of it.
     */
    @Unique
    private void enderlock$bestEffortSessionJoin(String serverId, PublicKey publicKey, SecretKey secretKey) {
        try {
            String serverIdHash = new BigInteger(CryptManager.getServerIdHash(serverId, publicKey, secretKey))
                .toString(16);
            new YggdrasilAuthenticationService(
                this.field_147394_b.getProxy(),
                UUID.randomUUID()
                    .toString()).createMinecraftSessionService()
                        .joinServer(
                            this.field_147394_b.getSession()
                                .func_148256_e(),
                            this.field_147394_b.getSession()
                                .getToken(),
                            serverIdHash);
        } catch (Exception e) {
            EnderLock.LOG.info("Mojang session join failed (harmless for offline accounts): {}", e.toString());
        }
    }

    /** The address the user typed (server list entry), falling back to the socket address. */
    @Unique
    private String enderlock$resolveAddress() {
        ServerData serverData = this.field_147394_b.func_147104_D();
        if (serverData != null && serverData.serverIP != null) {
            ServerAddress parsed = ServerAddress.func_78860_a(serverData.serverIP);
            if (parsed != null) {
                return KnownHostsStore.normalizeAddress(parsed.getIP(), parsed.getPort());
            }
        }
        SocketAddress socketAddress = this.field_147393_d.getSocketAddress();
        if (socketAddress instanceof InetSocketAddress) {
            InetSocketAddress inet = (InetSocketAddress) socketAddress;
            return KnownHostsStore.normalizeAddress(inet.getHostString(), inet.getPort());
        }
        return KnownHostsStore.normalizeAddress(String.valueOf(socketAddress), 0);
    }
}
