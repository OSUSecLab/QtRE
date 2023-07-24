package Util;

import Main.Decompiler;
import Main.Environment;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.PcodeOpAST;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.util.BigEndianDataConverter;
import ghidra.util.LittleEndianDataConverter;

import java.util.Iterator;
import java.util.List;

public class AddressUtil {

    public static Address getAddressFromLong(Program program, long val) {
        return program.getAddressFactory().getAddress(NumericUtil.longToHexString(val));
    }

    public static ReferenceIterator getReferenceToAddress(Program program, Address address) {
        ReferenceIterator iterator = program.getReferenceManager().getReferencesTo(address);
        return iterator;
    }

    public static int getReferenceCount(Program program, Address address) {
        return program.getReferenceManager().getReferenceCountTo(address);
    }

    public static Address findConnectionAddress(Program program, Address address, List<Address> allConnectAdd) {
        Function currentFunc = FunctionUtil.getFunctionWith(program, address);
        if (currentFunc == null)
            return null;
        DecompileResults results = Decompiler.decompileFuncRegister(program, currentFunc);
        if (results == null)
            return null;
        HighFunction highFunction = results.getHighFunction();
        Address current = address;
        while(current.next() != null) {
            Iterator<PcodeOpAST> pcodeOpASTIterator = highFunction.getPcodeOps(current);
            while (pcodeOpASTIterator.hasNext()) {
                PcodeOpAST ast = pcodeOpASTIterator.next();
                String mnem = ast.getMnemonic();
                if (mnem.equals("CALL")) {
                    Varnode inputNode = ast.getInputs()[0];
                    Address callAdd = inputNode.getAddress();
                    if (allConnectAdd.contains(callAdd))
                        return current;
                }
            }
            current = current.next();
            if (currentFunc.getBody().getMaxAddress().getUnsignedOffset() <= current.getUnsignedOffset())
                return null;
        }
        return null;
    }

    public static Address getAddressInNextIns(Program program, Address current) {
        Instruction currentIns = program.getListing().getInstructionAt(current);
        Address next = current;
        Instruction nextIns = null;
        do {
            next = next.next();
            nextIns = program.getListing().getInstructionAt(next);
        } while (nextIns == null);

        return next;
    }

}
