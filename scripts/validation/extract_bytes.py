import angr
import sys

def extract_entry_bytes(binary_path):
    try:
        p = angr.Project(binary_path, auto_load_libs=False)
        entry = p.entry
        # Read 16 bytes at entry
        # We can use the loader memory
        # But wait, if it's a packed binary, entry might be in a section not yet mapped?
        # angr loader maps the binary.
        
        # Check if entry is mapped
        try:
            bytes_at_entry = p.loader.memory.load(entry, 16)
            hex_bytes = bytes_at_entry.hex().upper()
            # Format as "AA BB CC ..."
            formatted_bytes = " ".join(hex_bytes[i:i+2] for i in range(0, len(hex_bytes), 2))
            
            print(f"Entry Address: {hex(entry)}")
            print(f"Architecture: {p.arch.name}")
            print(f"Bytes: {formatted_bytes}")
            
        except KeyError:
            print("Entry point not mapped in loader memory.")
            
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: extract_bytes.py <binary>")
        sys.exit(1)
    extract_entry_bytes(sys.argv[1])
