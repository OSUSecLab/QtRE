package Util;

import ghidra.app.services.ProgramManager;
import ghidra.program.model.address.Address;
import ghidra.program.model.block.BasicBlockModel;
import ghidra.program.model.block.CodeBlock;
import ghidra.program.model.block.CodeBlockReference;
import ghidra.program.model.block.CodeBlockReferenceIterator;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

import java.util.ArrayList;
import java.util.List;

public class BlockUtil {

    public static MemoryBlock external = null;
    public static MemoryBlock plt = null;

    public static CodeBlock[] locateBlockWithAddress(Program program, Address address) {
        BasicBlockModel basicBlockModel = new BasicBlockModel(program);
        try {
            CodeBlock[] codeBlocks = basicBlockModel.getCodeBlocksContaining(address, TaskMonitor.DUMMY);
            return codeBlocks;
        } catch (CancelledException e) {
            return null;
        }
    }

    /**
     * Get parent blocks of the current block
     */
    public static List<CodeBlockReference> getPreviousBlocks(CodeBlock codeBlock) {
        List<CodeBlockReference> result = new ArrayList<>();
        try {
            CodeBlockReferenceIterator codeBlockReferenceSourcesIterator = codeBlock.getSources(TaskMonitor.DUMMY);
            while (codeBlockReferenceSourcesIterator.hasNext()) {
                CodeBlockReference codeBlockReference = codeBlockReferenceSourcesIterator.next();
                // CodeBlock codeBlockSource = codeBlockReference.getSourceBlock();
                result.add(codeBlockReference);
            }
            return result;
        } catch (CancelledException e) {
            return null;
        }
    }

    /**
     * Get descendent blocks of the current block
     */
    public static List<CodeBlockReference> getDescentdentBlocks(CodeBlock codeBlock) {
        List<CodeBlockReference> result = new ArrayList<>();
        try {
            CodeBlockReferenceIterator codeBlockReferenceDestsIterator = codeBlock.getDestinations(TaskMonitor.DUMMY);
            while (codeBlockReferenceDestsIterator.hasNext()) {
                CodeBlockReference codeBlockReference = codeBlockReferenceDestsIterator.next();
                // CodeBlock codeBlockDest = codeBlockReference.getDestinationBlock();
                result.add(codeBlockReference);
            }
            return result;
        } catch (CancelledException e) {
            return null;
        }
    }

    public static boolean isExternalBlock(Program program, CodeBlock block) {

        if (external == null) {
            MemoryBlock[] blocks = program.getMemory().getBlocks();
            for (MemoryBlock b : blocks) {
                if (b.getName().equals("EXTERNAL")) {
                    external = b;
                    break;
                }
            }
        }

        Address add = block.getFirstStartAddress();

        if (add.toString().equals("ffff0fc0")) // special case
            return true;

        return external.contains(add);
    }

    public static boolean isExternalAddress(Program program, Address address) {

        if (external == null) {
            MemoryBlock[] blocks = program.getMemory().getBlocks();
            for (MemoryBlock b : blocks) {
                if (b.getName().equals("EXTERNAL")) {
                    external = b;
                    break;
                }
            }
        }

        if (address.toString().equals("ffff0fc0")) // special case
            return true;

        return external.contains(address);
    }


    public static boolean isPltBlock(Program program, CodeBlock block) {
        if (plt == null) {
            MemoryBlock[] blocks = program.getMemory().getBlocks();
            for (MemoryBlock b : blocks) {
                if (b.getName().equals(".plt")) {
                    plt = b;
                    break;
                }
            }
        }

        Address add = block.getFirstStartAddress();
        return plt.contains(add);
    }


    public static boolean isPltAddress(Program program, Address address) {
        if (plt == null) {
            MemoryBlock[] blocks = program.getMemory().getBlocks();
            for (MemoryBlock b : blocks) {
                if (b.getName().equals(".PLT")) {
                    plt = b;
                    break;
                }
            }
        }

        return plt.contains(address);
    }
}
