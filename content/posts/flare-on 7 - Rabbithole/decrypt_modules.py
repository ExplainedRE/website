
from pathlib import Path
from malduck import enhex, serpent, aplib

modules = ["CalTimer.bin",
    "Columncurrent/CaclibRegionmap.bin",
    "Columncurrent/CalccalcLogicnew.bin",
    "Columncurrent/CalciconLogicthre.bin",
    "Columncurrent/DatethrWorkscreen.bin",
    "Columncurrent/DiskproIdbui.bin",
    "Columncurrent/InflibExplorertru.bin",
    "Columncurrent/PrintsolutSavetheme.bin",
    "Columncurrent/ProtocolmagicWordeskt.bin",
    "Columncurrent/RowmapGuiprotocol.bin",
    "Columncurrent/ScreenserProtocolacces.bin",
    "Columncurrent/SoflogicMagiclink.bin",
    "Columncurrent/TasknetCharconso.bin",
    "Columncurrent/ThemespellDaytheme.bin",
    "Columncurrent/TimermagSelink.bin",
    "Columncurrent/WebmodeThemearchive.bin",
    "Columncurrent/WebsoftwareProcesstemplate.bin",
    "Columncurrent/WordlibSystemser.bin",
    "CurrentByte.bin",
    "DatNew.bin",
    "DayOld.bin",
    "D.bin",
    "DiMap.bin",
    "FalseLanguage.bin",
    "Languagetheme/CaclibRegionmap.bin",
    "Languagetheme/CalccalcLogicnew.bin",
    "Languagetheme/DatethrWorkscreen.bin",
    "Languagetheme/InfspellTimerver.bin",
    "Languagetheme/KeyboardtimerWolib.bin",
    "Languagetheme/MonitornewWarningmap.bin",
    "Languagetheme/NewinRegionsea.bin",
    "Languagetheme/PrintsolutSavetheme.bin",
    "Languagetheme/ProcesscharProtocomedia.bin",
    "Languagetheme/ProtocolmagicWordeskt.bin",
    "Languagetheme/RowmapGuiprotocol.bin",
    "Languagetheme/ScreenserProtocolacces.bin",
    "Languagetheme/SoflogicMagiclink.bin",
    "Languagetheme/ThemespellDaytheme.bin",
    "Languagetheme/ThemewebInnet.bin",
    "Languagetheme/TimerscreenClientsecur.bin",
    "Languagetheme/WebmodeThemearchive.bin",
    "Languagetheme/WebsoftwareProcesstemplate.bin",
    "Languagetheme/WordlibSystemser.bin",
    "ScaleThr.bin",
    "ScreenWeb.bin",
    "SoftwareColumn.bin",
    "SolutionDat.bin",
    "ThemeDay.bin",
    "TimerVersion.bin",
    "VersiScreen.bin",
    "WebFalse.bin",
    "WordTimer/MAIN.bin"]


output = Path("keys.txt")
timerpro_path = "PATH\\TO\\Timerpro"

decryption_function = 0x140010828
serpent_key_address = 0x14000CDDF

# Iterate over all the modules we extracted
for module in modules:
    path = Path(timerpro_path, module)
    # Read the module's bytes
    module_bytes = path.read_bytes()

    # Start execution until the decryption function
    ida_dbg.run_to(decryption_function)
    # Debugger is async so let's wait until the process is suspended
    ida_dbg.wait_for_next_event(ida_dbg.WFNE_SUSP, -1)
    # Replace the bytes in the original module ("WebsoftwareProcesstemplate") with
    # those of our loaded module
    ida_bytes.patch_bytes(get_reg_value("rcx"), module_bytes)
    # Set the length of the loaded module
    set_reg_value(len(module_bytes), "rdx")
    
    # Continue the execution twice until the address of the Serpent key
    # is in the memory. The function is called twice, only the second
    # time is our key. The first is used for decrypting an RSA key.
    ida_dbg.run_to(serpent_key_address)
    ida_dbg.wait_for_next_event(ida_dbg.WFNE_SUSP, -1)
    ida_dbg.run_to(serpent_key_address)
    ida_dbg.wait_for_next_event(ida_dbg.WFNE_SUSP, -1)

    # Read the serpent key that is pointed by RDX
    serpent_key = ida_bytes.get_bytes(get_reg_value("rdx"), 16)

    # Write the module name and its key to a file
    with output.open('a') as f:
        f.write(f"{module} : {enhex(serpent_key).decode()}\n")
    
    if serpent_key != b'\xff'*16:
        bin_path = path.with_suffix(".dec")
        decrypted = serpent.cbc.decrypt(serpent_key, module_bytes)
        if "MAIN" in module:
            decompressed = aplib(decrypted[4:])
        else:
            decompressed = aplib(decrypted[20:])
        bin_path.write_bytes(decompressed)

    # Quit debugging so we can start again
    ida_dbg.exit_process()
    ida_dbg.wait_for_next_event(ida_dbg.WFNE_ANY, -1)

