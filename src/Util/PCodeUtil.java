package Util;

import Main.Environment;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.Varnode;

public class PCodeUtil {


    public static String evaluateVarNode(Varnode node) {
        if (node == null)
            return null;
        try {
            Environment.PCODE_INS_COUNT += 1;
            return evaluate(node, new StringBuilder()).toString();
        } catch (StackOverflowError | OutOfMemoryError e) {
            return node.toString().trim();
        }
    }

    private static StringBuilder evaluate(Varnode node, StringBuilder expression) throws StackOverflowError, OutOfMemoryError{
        PcodeOp defNode = node.getDef();

        if (defNode == null) {
            // base case
            return new StringBuilder(node.toString().trim());
        }


        String mnem = defNode.getMnemonic();
        Varnode[] inputs = defNode.getInputs();

        switch (mnem) {
            case "CAST":
            case "COPY":
                // ignore mnem
                for (Varnode input: inputs) {
                    StringBuilder newExp = evaluate(input, new StringBuilder(""));
                    expression.append(newExp);
                    expression.append(" ");
                }
                return new StringBuilder(expression.toString().trim());

            case "INDIRECT":
                // continue to evaluate the first node
                return new StringBuilder(evaluate(inputs[0], new StringBuilder()));

            case "MULTIEQUAL":
                // select a non-zero input and evaluate it
                Varnode zeroNode = null;
                for (Varnode input: inputs) {
                    if (!(input.isConstant() && input.getAddress().getUnsignedOffset() == 0)) {
                        return new StringBuilder(evaluate(input, new StringBuilder()));
                    }
                    else {
                        zeroNode = input;
                    }
                }
                if (zeroNode != null)
                    return new StringBuilder(zeroNode.toString());
                else
                    return new StringBuilder();


            default:
                expression.append(defNode.getMnemonic());
                expression.append(" ");
                // append operands
                for (Varnode input: inputs) {
                    StringBuilder newExp = evaluate(input, new StringBuilder(""));
                    expression.append(newExp);
                    expression.append(" ");
                }

                return new StringBuilder(expression.toString().trim());
        }

    }

    public static boolean isVarNodeExpEqual(Varnode node, String exp) {
        return evaluateVarNode(node).equals(exp);
    }
}
