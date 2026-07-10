package com.enn3developer.enderlock.mixins;

import net.minecraft.network.NetworkManager;

import org.spongepowered.asm.mixin.Mixin;
import org.spongepowered.asm.mixin.gen.Accessor;

import io.netty.channel.Channel;

@Mixin(NetworkManager.class)
public interface NetworkManagerAccessor {

    @Accessor("channel")
    Channel enderlock$getChannel();
}
