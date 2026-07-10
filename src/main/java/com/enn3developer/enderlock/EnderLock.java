package com.enn3developer.enderlock;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import com.enn3developer.enderlock.crypto.ServerKeyManager;

import cpw.mods.fml.common.Mod;
import cpw.mods.fml.common.SidedProxy;
import cpw.mods.fml.common.event.FMLInitializationEvent;
import cpw.mods.fml.common.event.FMLPostInitializationEvent;
import cpw.mods.fml.common.event.FMLPreInitializationEvent;
import cpw.mods.fml.common.event.FMLServerStartingEvent;

@Mod(modid = EnderLock.MODID, version = Tags.VERSION, name = "EnderLock", acceptedMinecraftVersions = "[1.7.10]")
public class EnderLock {

    public static final String MODID = "enderlock";
    public static final Logger LOG = LogManager.getLogger(MODID);

    @SidedProxy(
        clientSide = "com.enn3developer.enderlock.ClientProxy",
        serverSide = "com.enn3developer.enderlock.CommonProxy")
    public static CommonProxy proxy;

    @Mod.EventHandler
    // preInit "Run before anything else. Read your config, create blocks, items, etc, and register them with the
    // GameRegistry." (Remove if not needed)
    public void preInit(FMLPreInitializationEvent event) {
        proxy.preInit(event);
    }

    @Mod.EventHandler
    // load "Do your mod setup. Build whatever data structures you care about. Register recipes." (Remove if not needed)
    public void init(FMLInitializationEvent event) {
        proxy.init(event);
    }

    @Mod.EventHandler
    // postInit "Handle interaction with other mods, complete your setup based on this." (Remove if not needed)
    public void postInit(FMLPostInitializationEvent event) {
        proxy.postInit(event);
    }

    @Mod.EventHandler
    public void serverStarting(FMLServerStartingEvent event) {
        proxy.serverStarting(event);
        // Load (or create) the persistent server key eagerly on dedicated servers so problems surface
        // at boot and the fingerprint lands in the log for the admin to publish.
        if (Config.enabled && event.getServer()
            .isDedicatedServer()) {
            ServerKeyManager.warmUp();
        }
    }
}
