package Moc;

import Constant.Constants;
import Main.Decompiler;
import Main.Environment;
import Util.*;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.*;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

public class QtConnectSolver {

    Address startAdd; // address of bl connect
    Address connAdd; // address of the connection function

    public String signalFunction;
    public String signalClass;
    public String signalExp;
    public long signalAddress = -1;

    public String slotFunction;
    public String slotClass;
    public String slotExp;
    public long slotAddress = -1;

    public String signalClassType = null;
    public String slotClassType = null;

    public boolean allSolved = false;
    public boolean invalid = false;
    public int connectType = -1;

    public HighFunction highFunction;

    public QtConnectSolver(Address start) {
        this.startAdd = start;
        this.slotFunction = null;
        this.signalFunction = null;
        this.signalExp = null;
        this.slotExp = null;
        this.slotClass = null;
    }

    public void setConnectAddr(Address connectAddr) {
        this.connAdd = connectAddr;
    }

    public void solve() {

        Function func = FunctionUtil.getFunctionWith(Environment.getProgram(), connAdd);
        Parameter[] params = func.getParameters();
        int paramLen = params.length;

        if (paramLen < 2) {
            System.out.println("Invalid length " + paramLen + " of the Qt connect function, skipping");
            return;
        }

        // we determine type 1 or type 2 Qt connect based on the second parameter
        String p1Type = params[1].getDataType().getName();
        // System.out.println("param[1] type " + p1Type);
        if (p1Type.equals("char *")) {
            this.connectType = 2;
            if (Environment.LANGUAGE_NAME.contains("x86:LE:64") || Environment.LANGUAGE_NAME.contains("x86:LE:32"))
                solveType2_x86();
            else if (Environment.LANGUAGE_NAME.contains("ARM:LE:32:v8"))
                solveType2_arm();
        }
        else {
            this.connectType = 1;
            solveType1();
        }

    }

    public void solveType2_arm() {
        Program program = Environment.getProgram();

        // decompile
        DecompileResults results = Decompiler.decompileFuncNormalize(program, FunctionUtil.getFunctionWith(program, startAdd));
        if (results == null)
            return;

        highFunction = results.getHighFunction();
        Iterator<PcodeOpAST> pcodeOpASTIterator = highFunction.getPcodeOps(startAdd);


        // analyze the decompiled code at bl connect
        PcodeOpAST pcodeAST = null;
        while (pcodeOpASTIterator.hasNext()) {
            PcodeOpAST tmp = pcodeOpASTIterator.next();
            if (tmp.getMnemonic().equals("CALL")) {
                pcodeAST = tmp;
                break;
            }
        }
        if (pcodeAST == null) {
            System.out.println("Error: CALL instruction not found in " + startAdd);
            return;
        }

        Function connectFunc = FunctionUtil.getFunctionWith(program, pcodeAST.getInputs()[0].getAddress());
        String funcSig = FunctionUtil.getFunctionSignature(connectFunc);

        Varnode[] varnodes = pcodeAST.getInputs();

        // iterate each parameters in the connect function call
        for (int i = 0; i < varnodes.length; ++i) {
            Varnode currentNode = varnodes[i];

            if (i == 1) {
                // sender
                signalExp = PCodeUtil.evaluateVarNode(currentNode);
                String[] classRes = solveClassName(currentNode);
                signalClass = classRes[0];
                signalClassType = classRes[1];

            } else if (i == 2) {
                // sender signal
                Address signalStrAddr = currentNode.getAddress();
                String tmp = PCodeUtil.evaluateVarNode(currentNode);
                signalFunction = StringUtil.getStringFromAddress(program, signalStrAddr);
                signalFunction = removeSlotFunctionPrefix(signalFunction);
                // remove parameters
                //if (signalFunction.contains("("))
                //    signalFunction = signalFunction.substring(0, signalFunction.indexOf("("));

                if (signalClass == null)
                    signalClass = resolveIfOneFunc(signalFunction);

            } else if (i == 3) {
                // receiver class instance
                slotExp = PCodeUtil.evaluateVarNode(currentNode);
                String[] classRes = solveClassName(currentNode);
                slotClass = classRes[0];
                slotClassType = classRes[1];

            } else if (i == 4) {
                // receiver slot function
                if (currentNode.isConstant()) {
                    Address slotStrAddr = currentNode.getAddress();
                    slotFunction = StringUtil.getStringFromAddress(program, slotStrAddr);
                    slotFunction = removeSlotFunctionPrefix(slotFunction);
                    // remove parameters
                    //if (slotFunction.contains("("))
                    //    slotFunction = slotFunction.substring(0, slotFunction.indexOf("("));

                    if (slotClass == null)
                        slotClass = resolveIfOneFunc(slotFunction);
                }
            }
        }
        checkSolvedType2();
        if (allSolved)
            System.out.println("Solved Qt connect: " + signalFunction + "\t" + slotFunction);

    }

    // ARM solving is slightly different from x86 due to shift of parameters
    public void solveType2_x86() {
        Program program = Environment.getProgram();

        // decompile
        DecompileResults results = Decompiler.decompileFuncNormalize(program, FunctionUtil.getFunctionWith(program, startAdd));
        if (results == null)
            return;

        highFunction = results.getHighFunction();
        Iterator<PcodeOpAST> pcodeOpASTIterator = highFunction.getPcodeOps(startAdd);


        // analyze the decompiled code at bl connect
        PcodeOpAST pcodeAST = null;
        while (pcodeOpASTIterator.hasNext()) {
            PcodeOpAST tmp = pcodeOpASTIterator.next();
            if (tmp.getMnemonic().equals("CALL")) {
                pcodeAST = tmp;
                break;
            }
        }
        if (pcodeAST == null) {
            System.out.println("Error: CALL instruction not found in " + startAdd);
            return;
        }

        Function connectFunc = FunctionUtil.getFunctionWith(program, pcodeAST.getInputs()[0].getAddress());
        String funcSig = FunctionUtil.getFunctionSignature(connectFunc);

        Varnode[] varnodes = pcodeAST.getInputs();
        
        // iterate each parameters in the connect function call
        for (int i = 0; i < varnodes.length; ++i) {
            Varnode currentNode = varnodes[i];

            if (i == 2) {
                // sender instance
                if (signalExp == null) {
                    signalExp = PCodeUtil.evaluateVarNode(currentNode);
                    String[] classRes = solveClassName(currentNode);
                    signalClass = classRes[0];
                    signalClassType = classRes[1];
                }

            } else if (i == 3) {
                // signal function
                Address signalStrAddr = currentNode.getAddress();
                String tmp = PCodeUtil.evaluateVarNode(currentNode);
                signalFunction = StringUtil.getStringFromAddress(program, signalStrAddr);
                signalFunction = removeSlotFunctionPrefix(signalFunction);
                // remove parameters
                //if (signalFunction.contains("("))
                //    signalFunction = signalFunction.substring(0, signalFunction.indexOf("("));

                if (signalClass == null)
                    signalClass = resolveIfOneFunc(signalFunction);
            }
            else if (i == 4) {
                // slot class instance
                if (slotClass == null) {
                    slotExp = PCodeUtil.evaluateVarNode(currentNode);
                    String[] classRes = solveClassName(currentNode);
                    slotClass = classRes[0];
                    slotClassType = classRes[1];
                }
            }
            else if (i == 5) {
                // receiver slot function
                if (currentNode.isConstant()) {
                    Address slotStrAddr = currentNode.getAddress();
                    slotFunction = StringUtil.getStringFromAddress(program, slotStrAddr);
                    slotFunction = removeSlotFunctionPrefix(slotFunction);
                    // remove parameters
                    //if (slotFunction.contains("("))
                    //    slotFunction = slotFunction.substring(0, slotFunction.indexOf("("));

                    if (slotClass == null)
                        slotClass = resolveIfOneFunc(slotFunction);
                }
            }
        }
        checkSolvedType2();
        if (allSolved)
            System.out.println("Solved Qt connect: " + signalFunction + "\t" + slotFunction);
    }

    public void solveType1() {
        Program program = Environment.getProgram();

        // decompile
        DecompileResults results = Decompiler.decompileFuncNormalize(program, FunctionUtil.getFunctionWith(program, startAdd));
        if (results == null)
            return;

        highFunction = results.getHighFunction();
        Iterator<PcodeOpAST> pcodeOpASTIterator = highFunction.getPcodeOps(startAdd);


        // analyze the decompiled code at connect CALL
        PcodeOpAST pcodeAST = null;
        while (pcodeOpASTIterator.hasNext()) {
            PcodeOpAST tmp = pcodeOpASTIterator.next();
            if (tmp.getMnemonic().equals("CALL")) {
                pcodeAST = tmp;
                break;
            }
        }
        if (pcodeAST == null) {
            System.out.println("Error: CALL instruction not found in " + startAdd);
            return;
        }

        Function connectFunc = FunctionUtil.getFunctionWith(program, pcodeAST.getInputs()[0].getAddress());
        String funcSig = FunctionUtil.getFunctionSignature(connectFunc);

        Varnode[] varnodes = pcodeAST.getInputs();

        if (funcSig.contains("connectImpl")) {
            if (varnodes.length < 6) {
                System.out.println("Unsupported param length " + varnodes.length + " of connectImpl at address: " + startAdd);
                return;
            }
            // only need to resolve function pointer at 1 and 3. This is shifted to varnode[3] and varnode[5]
            Varnode signalNode = varnodes[3];
            Varnode slotNode = varnodes[5];

            if (signalNode.isConstant() && signalNode.getAddress().getUnsignedOffset() == 0) {
                invalid = true;
                return;
            }
            if (slotNode.isConstant() && slotNode.getAddress().getUnsignedOffset() == 0) {
                invalid = true;
                return;
            }

            String signalExp = PCodeUtil.evaluateVarNode(signalNode);
            String slotExp = PCodeUtil.evaluateVarNode(slotNode);

            // System.out.println("\nSignal: " + signalExp);
            // System.out.println("Slot: " + slotExp);

            DecompileResults decompileResults = Decompiler.decompileFuncNormalize(Environment.getProgram(), FunctionUtil.getFunctionWith(Environment.getProgram(), startAdd));
            Iterator<PcodeOpAST> asts = decompileResults.getHighFunction().getPcodeOps();
            while (asts.hasNext()) {
                PcodeOpAST ast = asts.next();
                if (ast.getMnemonic().equals("COPY")) {

                    if (ast.getSeqnum().getTarget().getUnsignedOffset() >= startAdd.getUnsignedOffset())
                        break; // exit loop when reach the connect statement

                    Varnode[] inputs = ast.getInputs();
                    Varnode output = ast.getOutput();
                    String srcExp = PCodeUtil.evaluateVarNode(inputs[0]);
                    String dstExp = output.toString();

                    if (dstExp.contains("(stack")) {
                        String constExp = dstExp.replace("stack", "const");
                        if (signalExp.contains(constExp)) {
                            if (inputs[0].isConstant()) {
                                Address srcAddr = inputs[0].getAddress();
                                Function f = program.getFunctionManager().getFunctionAt(program.getAddressFactory().getAddress(NumericUtil.longToHexString(srcAddr.getUnsignedOffset())));
                                if (f != null)
                                    signalFunction = f.toString();
                                else {
                                    if (srcAddr.getUnsignedOffset() != 0)
                                        signalFunction = "FUN_" + NumericUtil.longToHexString(srcAddr.getUnsignedOffset()).replace("0x", "");
                                }
                                signalAddress = srcAddr.getUnsignedOffset();
                                signalClassType = "funptr";
                            }
                        }
                        else if (slotExp.contains(constExp)) {
                            if (inputs[0].isConstant()) {
                                Address srcAddr = inputs[0].getAddress();
                                Function f = program.getFunctionManager().getFunctionAt(program.getAddressFactory().getAddress(NumericUtil.longToHexString(srcAddr.getUnsignedOffset())));
                                if (f != null)
                                    slotFunction = f.toString();
                                else {
                                    if (srcAddr.getUnsignedOffset() != 0)
                                        slotFunction = "FUN_" + NumericUtil.longToHexString(srcAddr.getUnsignedOffset()).replace("0x", "");
                                }
                                slotAddress = srcAddr.getUnsignedOffset();
                                slotClassType = "funptr";
                            }
                        }
                    }
                }
            }
            
            checkSolvedType1();
            if (allSolved)
                System.out.println("Solved Qt connect: " + signalFunction + "\t" + slotFunction);
        }
    }

    private void checkSolvedType1() {
        if (slotFunction != null && signalFunction != null && signalAddress != -1 && slotAddress != -1) {
            allSolved = true;
        }
    }

    private void checkSolvedType2() {
        if (slotFunction != null && signalFunction != null && slotClass != null && signalClass != null) {
            allSolved = true;
        }
    }

    public String[] solveClassName (Varnode node) {

        Program program = Environment.getProgram();
        String className = null;
        Function currentFunc = FunctionUtil.getFunctionWith(program, startAdd);

        if (node.getDef() == null) {
            // node has no defs

            // 1. the node is a this pointer
            if (node.toString().equals(Environment.EXP_R0)) {
                className = FunctionUtil.getClassFromFuncName(currentFunc.toString());
                if (className == null) {
                    // TODO if function name not contain class name
                    className = currentFunc.getName();
                }
                return new String[] {className, "this"};
            }
            else {

                try {
                    if (node.isRegister()) {
                        // 2. the node is a function parameter
                        for (Parameter param: highFunction.getFunction().getParameters()) {
                            Varnode paramNode = param.getVariableStorage().getFirstVarnode();
                            if (paramNode.toString().equals(node.toString())) {
                                // parameter match
                                DataType type = param.getDataType();
                                className = type.getName().replace("*", "").strip();
                                return new String[] {className, "funcParam"};
                            }
                        }
                    }
                    else {
                        if (node.isConstant()) {
                            // 3. the node represents a symbol address
                            Symbol[] syms = program.getSymbolTable().getSymbols(AddressUtil.getAddressFromLong(program, node.getAddress().getUnsignedOffset()));
                            if (syms.length != 0) {
                                className = syms[0].getName();

                                return new String[] {className, "globalObj"};
                            }
                        }
                    }
                } catch (NullPointerException e) {

                }
            }
        }
        else {

            // 4. constructor function
            Iterator<PcodeOp> des = node.getDescendants();
            while (des.hasNext()) {
                // iterate to find constructor functions
                PcodeOp p = des.next();
                if (p.getMnemonic().equals("CALL")) {
                    Address callAdd = p.getInputs()[0].getAddress();
                    Function f = FunctionUtil.getFunctionWith(Environment.getProgram(), callAdd);
                    if (FunctionUtil.isConstructor(f)) {
                        className = f.getName();
                        return new String[] {className, "headObj"};
                    }
                }
            }


            // continue to trace to definition
            PcodeOp o = node.getDef();
            if (o.getMnemonic().equals("CALL")) {
                // 5. function return value
                Function callingFunc = FunctionUtil.getFunctionWith(program, o.getInputs()[0].getAddress());
                if (callingFunc.getThunkedFunction(true) != null)
                    callingFunc = callingFunc.getThunkedFunction(true);
                String sig = FunctionUtil.getFunctionSignature(callingFunc);
                List<Address> funcs = FunctionUtil.locateFunctionWithSig(program, sig, true);
                for (Address a: funcs) {
                    Function f = FunctionUtil.getFunctionWith(program, a);
                    if (f.getName().contains("instance")) {
                        String cn = FunctionUtil.getClassFromFuncName(FunctionUtil.getFunctionWith(program, this.startAdd).toString());
                        if (cn != null) {
                            return new String[] {cn, "retVal"};
                        }
                    }
                    DecompileResults res = Decompiler.decompileFunc(program, f);
                    try {
                        String s = res.getDecompiledFunction().getSignature();
                        String type = s.split(" ")[0]; // return type
                        className = type;
                        return new String[] {className, "retVal"};
                    }
                    catch (Exception e) {
                        // external function
                        DataType type = f.getReturnType();
                        if (type != null) {
                            className = type.getName().replace("*", "").strip();
                            return new String[] {className, "retVal"};
                        }
                    }
                }
            }
            else {
                // 6. implicit store
                // remove load
                String exp = PCodeUtil.evaluateVarNode(node);
                String targetExp = exp.replace("LOAD (const, 0x1a1, 4) ", "");

                DecompileResults decompileResults = Decompiler.decompileFuncNormalize(Environment.getProgram(), FunctionUtil.getFunctionWith(Environment.getProgram(), startAdd));
                Iterator<PcodeOpAST> asts = decompileResults.getHighFunction().getPcodeOps();
                while (asts.hasNext()) {
                    PcodeOpAST ast = asts.next();
                    if (ast.getMnemonic().equals("STORE")) {
                        Varnode[] inputs = ast.getInputs();
                        //String srcExp = PCodeUtil.evaluateVarNode(inputs[2]);
                        String dstExp = PCodeUtil.evaluateVarNode(inputs[1]);
                        if (dstExp.equals(targetExp)) {
                            Varnode srcNode = inputs[2];
                            // trace from source node
                            String cn = solveClassName(srcNode)[0];
                            if (cn != null) {
                                className = cn;
                                return new String[] {className, "stackObj"};
                            }
                        }
                    }
                }
            }


        }

        return new String[] {className, null};

    }


    public String resolveIfOneFunc(String functionName) {
        if (functionName == null)
            return null;
        List<Address> addrs = FunctionUtil.locateFunctionWithSig(Environment.getProgram(), functionName, false);
        List<String> classNames = new ArrayList<>();
        for (Address add: addrs) {
            Function f = FunctionUtil.getFunctionWith(Environment.getProgram(), add);
            if (f == null)
                continue;
            else {
                if (f.getThunkedFunction(true) != null)
                    f = f.getThunkedFunction(true);

                if (f.toString().contains("::")) {
                    String cName = FunctionUtil.getClassFromFuncName(f.toString());
                    if (!classNames.contains(cName))
                        classNames.add(cName);
                }
            }
        }

        if (classNames.size() == 1)
            return classNames.get(0);
        return null;
    }

    public String removeSlotFunctionPrefix(String fun) {
        if (fun == null)
            return "";
        if (fun.startsWith("1") || fun.startsWith("2"))
            return fun.substring(1, fun.length());

        return fun;
    }
}
