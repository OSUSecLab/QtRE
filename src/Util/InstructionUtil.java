package Util;

import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;

import java.util.ArrayList;
import java.util.List;

public class InstructionUtil {

    /**
     * Find instruction with pattern
     * @param pattern e.g., something like "blx r3" separated with space. user * to represent arbitrary operand
     */
    public static List<Instruction> findInstruction(Program program, String pattern) {
        List<Instruction> results = new ArrayList<>();

        // parse pattern
        String[] tokens = pattern.split(" ");
        int length = tokens.length;

        String opCode = "";
        List<String> operands = new ArrayList<>();

        for (int i=0; i<length; ++i) {
            if (i == 0)
                opCode = tokens[i];
            else
                operands.add(tokens[i]);
        }

        if (opCode.equals(" "))
            return results;


        // find instructions
        for (Instruction ins: program.getListing().getInstructions(true)) {
            String mnem = ins.getMnemonicString();
            if (mnem.equals(opCode)) {
                int operandNum = ins.getNumOperands();
                if (operandNum != operands.size())
                    continue;

                boolean tmpFlag = true;
                for (int i=0; i<operandNum; ++i) {
                    if (operands.get(i).equals("*"))  // don't check *
                        continue;
                    else {
                        String opName = ins.getOpObjects(i)[0].toString();
                        if (!operands.get(i).equals(opName))
                            tmpFlag = false;
                    }
                }
                if (tmpFlag)
                    results.add(ins);
            }
        }


        return results;
    }
}
