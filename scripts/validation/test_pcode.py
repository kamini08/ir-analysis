import angr
import archinfo
import sys

def test_pcode():
    try:
        from angr.engines import UberEnginePcode
        print("UberEnginePcode found")
    except ImportError:
        print("UberEnginePcode NOT found")
        return

    # Create a dummy project
    b = b"\x90\x90" # NOPs
    import tempfile
    import os
    with tempfile.NamedTemporaryFile(delete=False) as f:
        f.write(b)
        tmp_name = f.name
        
    try:
        p = angr.Project(tmp_name, main_opts={'backend': 'blob', 'arch': 'x86', 'base_addr': 0x1000, 'entry_point': 0x1000}, auto_load_libs=False)
        state = p.factory.entry_state(addr=0x1000)
        
        # Try to step using P-code engine
        # Note: P-code engine might need pypcode
        try:
            simgr = p.factory.simgr(state)
            # Force use of P-code engine?
            # Usually we can just pass the engine class
            simgr.step(engine=UberEnginePcode)
            if simgr.active:
                print("Stepped successfully with UberEnginePcode")
            else:
                print("Stepped but no active states (might be expected for NOPs if not handled?)")
        except Exception as e:
            print(f"Error stepping with UberEnginePcode: {e}")
            
    finally:
        os.unlink(tmp_name)

if __name__ == "__main__":
    test_pcode()
