import collections
import hashlib
import signal

import angr

from .utils import _log

import logging
loggers = logging.Logger.manager.loggerDict

# Set logging level for all loggers to CRITICAL + 1
for logger in loggers.values():
    if isinstance(logger, logging.Logger):
        logger.setLevel(logging.CRITICAL + 1)


def get_assembly_code(func, debug=False) -> tuple[list[str], str]:

    asm = []

    # Get the disassembly for each basic block in the function
    for block in func.blocks:
        # Get the assembly code for the block
        assembly = block.capstone.insns

        # Print the assembly code for the block
        for insn in assembly:
            if debug: print("%s\t%s" % (insn.mnemonic, insn.op_str))
            asm.append("%s %s" % (insn.mnemonic, insn.op_str))

    h = hashlib.md5(" ".join(asm).encode('utf-8')).hexdigest()
    return asm, h

def get_code_vex(func, debug=False) -> list:

    vex = []

    # Get the disassembly for each basic block in the function
    for block in func.blocks:
        # Get the VEX IR for the block
        vex_block = block.vex

        # Print the assembly code for the block
        for stmt in vex_block.statements:
            if debug: print("%s\t%s" % (stmt.__class__.__name__, stmt))
            vex.append("%s %s" % (stmt.__class__.__name__, stmt))

    return vex

def extract_program_instruction_features(cfg) -> dict:
    # Initialize counters for instruction types and opcodes
    inst_types = collections.Counter()

    # Iterate over all basic blocks in the CFG
    for function in cfg.functions.values():
        for block in function.blocks:
            for ins in block.disassembly.insns:
                # Update counters for instruction types and opcodes
                inst_types[ins.mnemonic] += 1

    # Compute total number of instructions and unique instruction types
    num_insts = sum(inst_types.values())
    num_inst_types = len(inst_types)

    # Compute frequency of each instruction type and opcode
    inst_type_freq = {k: round(v / num_insts, 4) for k, v in inst_types.items()}

    # Return dictionary of instruction features
    return {
        'num_insts': num_insts,
        'num_inst_types': num_inst_types,
        'inst_type_freq': inst_type_freq,
    }

class TimeoutError(Exception):
    pass

def _timed_cfg(binary_path, timeout):

    def handler(signum, frame):
        raise TimeoutError("CFG timed out")

    signal.signal(signal.SIGALRM, handler)
    signal.alarm(timeout)

    project = angr.Project(binary_path, auto_load_libs=False)
    cfg = project.analyses.CFGFast(normalize=True, show_progressbar=True)

    signal.alarm(0)

    return cfg

def get_timed_cfg(timeout, binary):
    try:
        cfg = _timed_cfg(binary, timeout)
        return cfg
    except:
        raise Exception("CFG timeout")


def assemparse(binary, timeout) -> tuple[dict, bool]:
    """
    Extract features from binary using Angr.

    Extract features from program from functions, CFG.

    Args:
        binary (str): Path of the Binary file to parse.
        timeout (int): Max seconds to perform CFG


        dict: A dictionary containing all the extracted features.
    """

    features = {}
    project = angr.Project(binary, auto_load_libs = False)

    # Get CFG
    try:
        if timeout is None:
            cfg = project.analyses.CFGFast(normalize = True, show_progressbar = True)
        else:
            cfg = get_timed_cfg(timeout, binary)

        if cfg is None:
            raise Exception
    except angr.errors.AngrCFGError:
        return (features, True)
    except TimeoutError:
        return (features, True)
    except Exception:
        return (features, True)

    features["INSTS_STATS" ] = extract_program_instruction_features(cfg)
    # Function feature extraction
    features["FUNCTIONS"] = []
    for _, function in cfg.functions.items():
        if function.size == 0: continue
        foo_feature = {}
        foo_feature["name"] = function.name
        try:
            foo_feature["disassembled"], foo_feature["md5"] = get_assembly_code(function)
            foo_feature["VEX"] = get_code_vex(function)
        except:
            pass

        features["FUNCTIONS"].append(foo_feature)

    return (features, False)
