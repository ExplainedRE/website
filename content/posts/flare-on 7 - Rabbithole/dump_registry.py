from pathlib import Path
from Registry import Registry

# Open the NTUSER.DAT file
reg = Registry.Registry("NTUSER.DAT")

# Get the Timerpro key
key = reg.open("SOFTWARE\\Timerpro")

def recursive_dump(key):
    """Recursively dump keys from a given key, to a .bin file into the "keys" directory.
        keys/Timerpro/[subkey.bin]
        keys/Timerpro/[subkeykey]/[subkey.bin]
    """
    # Get the path of the key, remove its prefix and use forward slash
    name = key.path().split('ROOT\\SOFTWARE\\')[1].replace("\\", "/")

    # Create a Path object for the "keys" directory that will contain the dumped files
    key_path = Path("keys", name)
    key_path.mkdir(parents=True, exist_ok=False)

    for val in key.values():
        # Concat the name of the key to the Path
        file_path = (key_path / val.name()).with_suffix(".bin")

        # Dump the value of the key to a file
        file_path.write_bytes(val.raw_data())

    # Recursively call this function with all the subkeys
    list(map(recursive_dump, key.subkeys()))

if __name__ == "__main__":
    recursive_dump(key)