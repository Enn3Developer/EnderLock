package com.enn3developer.enderlock.mixins;

import java.security.KeyPair;

import net.minecraft.network.NetworkManager;
import net.minecraft.network.login.client.C01PacketEncryptionResponse;
import net.minecraft.server.MinecraftServer;
import net.minecraft.server.network.NetHandlerLoginServer;

import org.spongepowered.asm.mixin.Final;
import org.spongepowered.asm.mixin.Mixin;
import org.spongepowered.asm.mixin.Shadow;
import org.spongepowered.asm.mixin.Unique;
import org.spongepowered.asm.mixin.injection.At;
import org.spongepowered.asm.mixin.injection.Inject;
import org.spongepowered.asm.mixin.injection.Redirect;
import org.spongepowered.asm.mixin.injection.callback.CallbackInfo;

import com.enn3developer.enderlock.Config;
import com.enn3developer.enderlock.EnderLock;
import com.enn3developer.enderlock.crypto.ServerKeyManager;

import cpw.mods.fml.common.network.internal.FMLNetworkHandler;
import io.netty.channel.Channel;
import io.netty.handler.timeout.ReadTimeoutHandler;

/**
 * Re-enables the vanilla protocol-encryption handshake on offline-mode servers, presenting a persistent RSA key, and
 * skips only the Mojang session lookup afterwards.
 *
 * Fail-closed by construction: when engaged, vanilla's own login state machine is left in charge. The state is KEY
 * after {@code processLoginStart}, and the only transition out of KEY is a valid Encryption Response — a bad verify
 * token or an undecryptable shared secret throws, which the vanilla network layer answers with a kick. Login
 * completion ({@code func_147326_c}) is only reachable after {@code enableEncryption} succeeded, so no code path
 * leads to an unencrypted session.
 */
@Mixin(NetHandlerLoginServer.class)
public abstract class MixinNetHandlerLoginServer {

    @Shadow
    @Final
    public NetworkManager field_147333_a;

    @Shadow
    public abstract void func_147322_a(String reason);

    @Shadow
    public abstract void func_147326_c();

    @Unique
    private boolean enderlock$engaged;

    /**
     * Makes offline-mode servers take the vanilla encrypted-login branch (state KEY + Encryption Request). Online
     * mode, local (single-player) channels and disabled config are left exactly as vanilla.
     */
    @Redirect(
        method = "processLoginStart",
        at = @At(value = "INVOKE", target = "Lnet/minecraft/server/MinecraftServer;isServerInOnlineMode()Z"))
    private boolean enderlock$forceEncryptedLogin(MinecraftServer server) {
        if (server.isServerInOnlineMode()) {
            return true; // vanilla online-mode flow, untouched
        }
        if (!Config.enabled || this.field_147333_a.isLocalChannel()) {
            return false; // vanilla offline flow (single-player / mod disabled)
        }
        if (ServerKeyManager.getKeyPair() == null) {
            // fail closed: without a key we refuse the login instead of letting it continue in plaintext.
            // Returning true still parks the state machine in KEY, which has no plaintext exit.
            this.func_147322_a("EnderLock: the server encryption key is unavailable. Contact the administrator.");
            return true;
        }
        this.enderlock$engaged = true;
        // the client may sit on the trust screen for a while; don't let the 30s read timeout kill it
        this.enderlock$replaceReadTimeout(Config.loginTimeoutSeconds + 30);
        return true;
    }

    /** Presents the persistent EnderLock key instead of the per-boot vanilla key on engaged connections. */
    @Redirect(
        method = { "processLoginStart", "processEncryptionResponse" },
        at = @At(
            value = "INVOKE",
            target = "Lnet/minecraft/server/MinecraftServer;getKeyPair()Ljava/security/KeyPair;"))
    private KeyPair enderlock$usePersistentKeyPair(MinecraftServer server) {
        return this.enderlock$engaged ? ServerKeyManager.getKeyPair() : server.getKeyPair();
    }

    /**
     * Runs right after vanilla verified the token, decrypted the shared secret and enabled encryption. On engaged
     * connections we complete the login immediately with the vanilla offline profile path (OfflinePlayer:<name>
     * UUIDv3, ban/whitelist checks, LoginSuccess, FML handshake) and cancel the Mojang hasJoined thread.
     */
    @Inject(
        method = "processEncryptionResponse",
        at = @At(
            value = "INVOKE",
            target = "Lnet/minecraft/network/NetworkManager;enableEncryption(Ljavax/crypto/SecretKey;)V",
            shift = At.Shift.AFTER),
        cancellable = true)
    private void enderlock$completeOfflineLogin(C01PacketEncryptionResponse packet, CallbackInfo ci) {
        if (!this.enderlock$engaged) {
            return;
        }
        ci.cancel(); // never reach the Mojang session-lookup thread
        this.enderlock$replaceReadTimeout(FMLNetworkHandler.READ_TIMEOUT);
        EnderLock.LOG.info("Encrypted offline login from {}", this.field_147333_a.getSocketAddress());
        this.func_147326_c();
    }

    /** Raises the login timeout on engaged connections; the client may be waiting on the trust screen. */
    @Redirect(
        method = "onNetworkTick",
        at = @At(
            value = "FIELD",
            target = "Lcpw/mods/fml/common/network/internal/FMLNetworkHandler;LOGIN_TIMEOUT:I",
            remap = false))
    private int enderlock$extendLoginTimeout() {
        int vanilla = FMLNetworkHandler.LOGIN_TIMEOUT;
        return this.enderlock$engaged ? Math.max(Config.loginTimeoutSeconds * 20, vanilla) : vanilla;
    }

    @Unique
    private void enderlock$replaceReadTimeout(int seconds) {
        try {
            Channel channel = ((NetworkManagerAccessor) (Object) this.field_147333_a).enderlock$getChannel();
            channel.pipeline()
                .replace("timeout", "timeout", new ReadTimeoutHandler(seconds));
        } catch (Exception e) {
            EnderLock.LOG.warn("Could not adjust the network read timeout", e);
        }
    }
}
