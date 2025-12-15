# Ghidra Jython script: get_cfg_stats.py
# Extracts CFG statistics and P-code operation counts from analyzed binary
#@category Analysis

from ghidra.program.model.block import SimpleBlockModel
from ghidra.util.task import TaskMonitor

# Get current program and managers
prog = getCurrentProgram()
fm = prog.getFunctionManager()
bm = SimpleBlockModel(prog)
listing = prog.getListing()

# Handle monitor
try:
    monitor
except NameError:
    monitor = TaskMonitor.DUMMY

# Initialize counters
num_functions = fm.getFunctionCount()
num_blocks = 0
total_pcode_ops = 0

# Count all blocks in the program
block_iter = bm.getCodeBlocks(monitor)

while block_iter.hasNext():
    block = block_iter.next()
    num_blocks += 1
    
    # Get instructions in this block
    instr_iter = listing.getInstructions(block, True)
    
    while instr_iter.hasNext():
        instruction = instr_iter.next()
        pcode_ops = instruction.getPcode()
        if pcode_ops is not None:
            total_pcode_ops += len(pcode_ops)

# Print parseable statistics
print("GHIDRA_STATS:Functions={}".format(num_functions))
print("GHIDRA_STATS:BasicBlocks={}".format(num_blocks))
print("GHIDRA_STATS:TotalPcodeOps={}".format(total_pcode_ops))
