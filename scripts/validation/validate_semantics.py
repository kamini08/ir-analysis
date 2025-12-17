import angr
import claripy
import archinfo
import json
import sys
import csv
import os

def get_arch(arch_str):
    """Map architecture string to angr architecture."""
    if "x86" in arch_str:
        if "64" in arch_str:
            return archinfo.ArchAMD64()
        else:
            return archinfo.ArchX86()
    elif "ARM" in arch_str and "32" in arch_str:
        return archinfo.ArchARM()
    # Add more mappings as needed
    return archinfo.ArchX86()



def parse_initial_state(state, initial_state_data, is_symbolic=False):
    """
    Sets up the state based on initial_state_data.
    If is_symbolic is True, creates symbolic variables for registers.
    Returns a map of {reg_name: symbolic_var} if is_symbolic is True.
    """
    symbolic_map = {}
    
    # Set registers
    for reg, val in initial_state_data.items():
        if reg == "memory" or reg == "flags":
            continue
            
        if is_symbolic:
            # Create symbolic variable
            # Determine size of register
            if reg in state.arch.registers:
                size = state.arch.registers[reg][1]
                sym_var = claripy.BVS(f"init_{reg}", size * 8)
                setattr(state.regs, reg, sym_var)
                symbolic_map[reg] = sym_var
            else:
                print(f"Warning: Register {reg} not found in architecture")
        else:
            # Concrete value
            if isinstance(val, str):
                try:
                    val = int(val, 0)
                except ValueError:
                    val = 0x10000 # Default
            setattr(state.regs, reg, val)

    # Set flags if present (Architecture specific)
    if "flags" in initial_state_data:
        pass

    # Set memory
    if "memory" in initial_state_data:
        for mem_block in initial_state_data["memory"]:
            addr = mem_block["address"]
            value = mem_block["value"]
            size = mem_block["size"]
            state.memory.store(addr, value, size, endness=state.arch.memory_endness)

    return symbolic_map

def get_concrete_ground_truth(arch_str, asm_bytes, initial_state_data, entry_addr=0x400000):
    """Executes the assembly concretely using an emulator to get the final state."""
    arch = get_arch(arch_str)
    base_addr = int(str(entry_addr), 0) if isinstance(entry_addr, str) else entry_addr
    
    import tempfile
    with tempfile.NamedTemporaryFile(delete=False) as f:
        f.write(bytes.fromhex(asm_bytes.replace(" ", "")))
        tmp_name = f.name
        
    try:
        # Fixed: Pass options directly to Project
        p = angr.Project(tmp_name, main_opts={'backend': 'blob', 'arch': arch, 'base_addr': base_addr, 'entry_point': base_addr}, auto_load_libs=False)
        
        # Use unicorn for concrete execution
        # add_options={angr.options.UNICORN} is correct if angr.options exists.
        # If not, try angr.sim_options.UNICORN
        try:
            unicorn_opt = angr.options.UNICORN
        except AttributeError:
            unicorn_opt = angr.sim_options.UNICORN

        state = p.factory.entry_state(addr=base_addr, add_options={unicorn_opt})
        
        parse_initial_state(state, initial_state_data, is_symbolic=False)
        
        simgr = p.factory.simgr(state)
        simgr.step()
        
        if simgr.active:
            return simgr.active[0]
        else:
            return None
    finally:
        if os.path.exists(tmp_name):
            os.unlink(tmp_name)

def lift_and_symbolize(arch_str, asm_bytes, initial_state_data, ir_type="VEX", entry_addr=0x400000):
    """Lifts assembly to IR and executes it symbolically."""
    
    arch = get_arch(arch_str)
    base_addr = int(str(entry_addr), 0) if isinstance(entry_addr, str) else entry_addr
    
    import tempfile
    with tempfile.NamedTemporaryFile(delete=False) as f:
        f.write(bytes.fromhex(asm_bytes.replace(" ", "")))
        tmp_name = f.name
        
    try:
        p = angr.Project(tmp_name, main_opts={'backend': 'blob', 'arch': arch, 'base_addr': base_addr, 'entry_point': base_addr}, auto_load_libs=False)
        state = p.factory.entry_state(addr=base_addr)
        
        symbolic_map = parse_initial_state(state, initial_state_data, is_symbolic=True)
        
        simgr = p.factory.simgr(state)
        
        if ir_type == "P-code":
            try:
                from angr.engines import UberEnginePcode
                # Instantiate the engine with the project
                pcode_engine = UberEnginePcode(p)
                simgr.step(engine=pcode_engine)
            except ImportError:
                print("Error: UberEnginePcode not available.")
                return None, None
            except Exception as e:
                print(f"Error during P-code execution: {e}")
                return None, None
        else:
            # Default VEX
            simgr.step()
        
        if simgr.active:
            return simgr.active[0], symbolic_map
        else:
            return None, None
    finally:
        if os.path.exists(tmp_name):
            os.unlink(tmp_name)

def check_equivalence(ground_truth_state, lifted_symbolic_state, symbolic_map, initial_state_data, target_registers=None):
    """
    Compares the final state of the lifted IR against the known concrete ground truth.
    """
    if ground_truth_state is None or lifted_symbolic_state is None:
        return 1 
        
    solver = lifted_symbolic_state.solver
    errors = 0
    
    for reg, sym_var in symbolic_map.items():
        concrete_val = initial_state_data.get(reg)
        if isinstance(concrete_val, str):
             try:
                concrete_val = int(concrete_val, 0)
             except:
                concrete_val = 0x10000 
        
        solver.add(sym_var == concrete_val)
        
    # Determine registers to check
    regs_to_check = []
    if target_registers:
        regs_to_check = target_registers
    else:
        regs_to_check = list(symbolic_map.keys())

    for reg in regs_to_check:
        # Handle case where reg might not be in symbolic_map (if target_registers has extra)
        # But we need to get it from state.regs
        try:
            if reg in ['zf', 'cf', 'sf', 'of', 'pf', 'af']:
                # Handle flags for x86/AMD64
                if "x86" in ground_truth_state.arch.name or "AMD64" in ground_truth_state.arch.name:
                    # Extract flag from eflags/rflags
                    # ZF is bit 6, CF is bit 0, etc.
                    # This is simplified; angr might have specific properties
                    flags_reg = 'eflags' if "x86" in ground_truth_state.arch.name else 'rflags'
                    sym_flags = getattr(lifted_symbolic_state.regs, flags_reg)
                    conc_flags = getattr(ground_truth_state.regs, flags_reg)
                    
                    bit_map = {'cf': 0, 'pf': 2, 'af': 4, 'zf': 6, 'sf': 7, 'of': 11}
                    bit = bit_map.get(reg, 0)
                    
                    final_sym_expr = (sym_flags >> bit) & 1
                    final_concrete_val = (conc_flags >> bit) & 1
                else:
                    # Try direct access for other archs
                    final_sym_expr = getattr(lifted_symbolic_state.regs, reg)
                    final_concrete_val = getattr(ground_truth_state.regs, reg)
            else:
                final_sym_expr = getattr(lifted_symbolic_state.regs, reg)
                final_concrete_val = getattr(ground_truth_state.regs, reg)
        except AttributeError:
            print(f"Warning: Register {reg} not found in state")
            # If we can't find it, count as error or just skip?
            # If it was explicitly requested in target_registers, it's an error if missing.
            errors += 1
            continue
        
        if solver.satisfiable(extra_constraints=(final_sym_expr != final_concrete_val,)):
            try:
                eval_val = solver.eval(final_sym_expr, cast_to=int)
                conc_val = solver.eval(final_concrete_val, cast_to=int)
                if eval_val != conc_val:
                    errors += 1
            except:
                errors += 1
                
    return errors

def main():
    if len(sys.argv) < 2:
        print("Usage: validate_semantics.py <test_cases.json>")
        sys.exit(1)
        
    test_cases_file = sys.argv[1]
    with open(test_cases_file, 'r') as f:
        test_cases = json.load(f)
        
    results_dir = "results"
    if not os.path.exists(results_dir):
        os.makedirs(results_dir)
        
    report_file = os.path.join(results_dir, "semantic_report.csv")
    
    with open(report_file, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(["Test_Case_ID", "Architecture", "Malware_Type", "Tool", "Semantic_Errors", "Total_Checks", "Error_Rate (%)"])
        
        for case in test_cases:
            case_id = case["id"]
            arch = case["architecture"]
            malware_type = case.get("malware_technique", case.get("malware_type", "Unknown"))
            asm_bytes = case["asm_bytes"]
            initial_state = case["initial_state"]
            entry_addr = case.get("entry_address", 0x400000)
            target_regs = case.get("target_registers", None)
            
            print(f"Testing {case_id} ({arch})...")
            
            gt_state = get_concrete_ground_truth(arch, asm_bytes, initial_state, entry_addr)
            
            vex_state, vex_sym_map = lift_and_symbolize(arch, asm_bytes, initial_state, ir_type="VEX", entry_addr=entry_addr)
            
            # Count checks
            if target_regs:
                total_checks = len(target_regs)
            else:
                total_checks = len(vex_sym_map) if vex_sym_map else 1
            
            vex_errors = check_equivalence(gt_state, vex_state, vex_sym_map, initial_state, target_regs)
            
            vex_error_rate = (vex_errors / total_checks * 100) if total_checks > 0 else 0
            
            writer.writerow([case_id, arch, malware_type, "VEX", vex_errors, total_checks, f"{vex_error_rate:.2f}%"])
            
            # P-code
            print(f"Testing {case_id} ({arch}) with P-code...")
            pcode_state, pcode_sym_map = lift_and_symbolize(arch, asm_bytes, initial_state, ir_type="P-code", entry_addr=entry_addr)
            
            if pcode_state:
                # Use the same symbolic map if possible, but lift_and_symbolize creates new one.
                # Actually, we need to use the map returned by lift_and_symbolize for P-code run.
                if target_regs:
                    pcode_checks = len(target_regs)
                else:
                    pcode_checks = len(pcode_sym_map) if pcode_sym_map else 1
                    
                pcode_errors = check_equivalence(gt_state, pcode_state, pcode_sym_map, initial_state, target_regs)
                pcode_error_rate = (pcode_errors / pcode_checks * 100) if pcode_checks > 0 else 0
                writer.writerow([case_id, arch, malware_type, "P-code", pcode_errors, pcode_checks, f"{pcode_error_rate:.2f}%"])
            else:
                 writer.writerow([case_id, arch, malware_type, "P-code", "Error", total_checks, "N/A"])

if __name__ == "__main__":
    main()
