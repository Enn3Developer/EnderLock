package com.enn3developer.enderlock.client;

import net.minecraft.client.gui.GuiButton;
import net.minecraft.client.gui.GuiScreen;
import net.minecraft.client.resources.I18n;
import net.minecraft.network.NetworkManager;
import net.minecraft.util.EnumChatFormatting;

import org.lwjgl.input.Keyboard;

import com.enn3developer.enderlock.crypto.FingerprintUtil;

/**
 * SSH-style trust-on-first-use confirmation screen. Two variants: first connect (neutral) and key mismatch (alarming,
 * safe default is Disconnect — Escape and Enter both disconnect, they never trust).
 *
 * While this screen is open it takes over pumping the network from GuiConnecting, so disconnects and (after
 * accepting) the rest of the login are still processed.
 */
public class GuiTrustServer extends GuiScreen {

    private static final int BUTTON_TRUST = 0;
    private static final int BUTTON_DISCONNECT = 1;

    private final ParkedHandshake handshake;
    /** The previously pinned fingerprint; non-null means this is the mismatch variant. */
    private final String expectedFingerprint;
    private boolean accepted;

    public GuiTrustServer(ParkedHandshake handshake, String expectedFingerprint) {
        this.handshake = handshake;
        this.expectedFingerprint = expectedFingerprint;
    }

    private boolean isMismatch() {
        return expectedFingerprint != null;
    }

    @Override
    public void initGui() {
        this.buttonList.clear();
        if (!accepted) {
            String trustLabel = I18n
                .format(isMismatch() ? "enderlock.trust.button.trustAnyway" : "enderlock.trust.button.trust");
            this.buttonList
                .add(new GuiButton(BUTTON_TRUST, this.width / 2 - 154, this.height - 40, 150, 20, trustLabel));
            this.buttonList.add(
                new GuiButton(
                    BUTTON_DISCONNECT,
                    this.width / 2 + 4,
                    this.height - 40,
                    150,
                    20,
                    I18n.format("enderlock.trust.button.disconnect")));
        }
    }

    @Override
    public void updateScreen() {
        // GuiConnecting normally does this; we replaced it, so we must keep the network pumping.
        NetworkManager manager = handshake.getNetworkManager();
        if (manager.isChannelOpen()) {
            manager.processReceivedPackets();
        } else if (manager.getExitMessage() != null) {
            manager.getNetHandler()
                .onDisconnect(manager.getExitMessage());
        }
    }

    @Override
    protected void actionPerformed(GuiButton button) {
        if (accepted) {
            return;
        }
        if (button.id == BUTTON_TRUST) {
            accepted = true;
            this.buttonList.clear();
            handshake.accept();
        } else if (button.id == BUTTON_DISCONNECT) {
            disconnect();
        }
    }

    @Override
    protected void keyTyped(char typedChar, int keyCode) {
        if (accepted) {
            return;
        }
        // Safe default: neither Escape nor Enter can ever trust a key.
        if (keyCode == Keyboard.KEY_ESCAPE || keyCode == Keyboard.KEY_RETURN) {
            disconnect();
        }
    }

    private void disconnect() {
        String reason;
        if (isMismatch()) {
            reason = "EnderLock: server key mismatch — connection aborted.\nExpected: " + expectedFingerprint
                + "\nReceived: "
                + handshake.getFingerprint();
        } else {
            reason = "EnderLock: server key not trusted by user.\nFingerprint: " + handshake.getFingerprint();
        }
        handshake.disconnect(reason);
    }

    @Override
    public void drawScreen(int mouseX, int mouseY, float partialTicks) {
        this.drawDefaultBackground();
        int centerX = this.width / 2;

        if (accepted) {
            this.drawCenteredString(
                this.fontRendererObj,
                I18n.format("enderlock.trust.connecting"),
                centerX,
                this.height / 2 - 20,
                0xFFFFFF);
            super.drawScreen(mouseX, mouseY, partialTicks);
            return;
        }

        int wrapWidth = Math.min(this.width - 50, 380);
        int y = 20;

        if (isMismatch()) {
            this.drawCenteredString(
                this.fontRendererObj,
                EnumChatFormatting.RED.toString() + EnumChatFormatting.BOLD
                    + I18n.format("enderlock.trust.title.mismatch"),
                centerX,
                y,
                0xFF5555);
        } else {
            this.drawCenteredString(
                this.fontRendererObj,
                EnumChatFormatting.YELLOW + I18n.format("enderlock.trust.title.first"),
                centerX,
                y,
                0xFFFF55);
        }
        y += 14;
        this.drawCenteredString(
            this.fontRendererObj,
            I18n.format("enderlock.trust.server", handshake.getAddress()),
            centerX,
            y,
            0xAAAAAA);
        y += 16;

        String body = I18n.format(isMismatch() ? "enderlock.trust.body.mismatch" : "enderlock.trust.body.first");
        this.fontRendererObj.drawSplitString(body, centerX - wrapWidth / 2, y, wrapWidth, 0xDDDDDD);
        y += this.fontRendererObj.listFormattedStringToWidth(body, wrapWidth)
            .size() * (this.fontRendererObj.FONT_HEIGHT + 1) + 8;

        if (isMismatch()) {
            this.drawCenteredString(
                this.fontRendererObj,
                I18n.format("enderlock.trust.expected"),
                centerX,
                y,
                0xAAAAAA);
            y += 11;
            y = drawFingerprint(expectedFingerprint, centerX, y, 0x55FF55);
            y += 6;
            this.drawCenteredString(
                this.fontRendererObj,
                I18n.format("enderlock.trust.received"),
                centerX,
                y,
                0xAAAAAA);
            y += 11;
            drawFingerprint(handshake.getFingerprint(), centerX, y, 0xFF5555);
        } else {
            this.drawCenteredString(
                this.fontRendererObj,
                I18n.format("enderlock.trust.fingerprint"),
                centerX,
                y,
                0xAAAAAA);
            y += 11;
            drawFingerprint(handshake.getFingerprint(), centerX, y, 0x55FFFF);
        }

        super.drawScreen(mouseX, mouseY, partialTicks);
    }

    private int drawFingerprint(String fingerprint, int centerX, int y, int color) {
        for (String line : FingerprintUtil.splitFingerprint(fingerprint)) {
            this.drawCenteredString(this.fontRendererObj, line, centerX, y, color);
            y += 10;
        }
        return y;
    }
}
