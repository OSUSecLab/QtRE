package Taint;

import Constant.Configs;
import Main.Decompiler;
import Main.Environment;
import Moc.QtConnectSolver;
import Util.FunctionUtil;
import Util.NumericUtil;
import Util.PCodeUtil;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.PcodeOpAST;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.Symbol;
import ghidra.util.task.TimeoutTaskMonitor;

import java.util.*;
import java.util.concurrent.TimeUnit;

public class InputExpSolver {

    String slotClass;
    Function slotConstructor;
    Function slotFunction;

    String signalClass;
    String signalExp;
    Set<Function> calledConstructors;

    public String inputExp = "";

    public InputExpSolver() {

    }

    public InputExpSolver(QtConnectSolver solver) {
        this.slotFunction = FunctionUtil.getFunctionWithName(Environment.getProgram(), solver.slotFunction);
        if (slotFunction == null)
            slotFunction = slotFunction.getThunkedFunction(true);
        this.slotClass = getClassNameFromFunctionName(slotFunction.toString());
        this.slotConstructor = FunctionUtil.getFunctionWithName(Environment.getProgram(), getConstructorName(this.slotClass));
        this.signalExp = solver.signalExp;
        this.signalClass = solver.signalClass;
    }

    // INT_ADD LOAD (const, 0x1a1, 4) INT_ADD (register, 0x20, 4) (const, 0x360, 4) (const, 0x784, 4)

    public void solve () {
        String inputBase = signalExp;
        switch (this.signalClass) {
            case "PasswordTextField":
            case "TextField":
            case "WebEntryField":
            case "NavigationSearchBox":
            case "CompleterTextField":
            case "ExtEntryField":
                inputExp = "LOAD (const, 0x1a1, 4) INT_ADD " + inputBase + " (const, 0x31c, 4)";
                break;
        }
    }


    public List<String> getInitNullExpAtFunction(Program program, Function fun) {
        List<String> result = new ArrayList<>();
        DecompileResults decompileResults = Decompiler.decompileFuncNormalize(program, fun);
        HighFunction highFunction = decompileResults.getHighFunction();
        Iterator<PcodeOpAST> asts = highFunction.getPcodeOps();
        while (asts.hasNext()) {
            PcodeOpAST ast = asts.next();
            if (ast.getMnemonic().equals("STORE")) {
                Varnode[] inputs = ast.getInputs();
                String srcExp = PCodeUtil.evaluateVarNode(inputs[2]);
                String dstExp = PCodeUtil.evaluateVarNode(inputs[1]);
                if (inputs[2].isConstant()) {
                    Address a = inputs[2].getAddress();
                    a = program.getAddressFactory().getAddress(NumericUtil.longToHexString(a.getUnsignedOffset()));
                    Symbol[] symbols = program.getSymbolTable().getSymbols(a);
                    if (symbols != null && symbols.length != 0) {
                        for (Symbol symbol: symbols) {
                            if (symbol.toString().contains("QString11shared_null")) {
                                if (dstExp != null)
                                    result.add(dstExp);
                            }
                        }
                    }
                }
            }
        }
        return result;
    }

    public List<String> checkExpInSlot(Function fun, List<String> exp) {
        List<String> result = new ArrayList<>();
        DecompileResults decompileResults = Decompiler.decompileFuncNormalize(Environment.getProgram(), fun);
        HighFunction highFunction = decompileResults.getHighFunction();
        Iterator<PcodeOpAST> asts = highFunction.getPcodeOps();
        while (asts.hasNext()) {
            PcodeOpAST ast = asts.next();
            Varnode[] inputs = ast.getInputs();
            Varnode output = ast.getOutput();
            if (output != null) {
                String outputExp = PCodeUtil.evaluateVarNode(output);
                if (exp.contains(outputExp) && !result.contains(outputExp)) {
                    result.add(outputExp);
                }
            }
        }
        return result;
    }

    public Function getConstructor(String className) {
        if (className == null)
            return null;

        for (Function constructor: calledConstructors) {
            if (constructor == null)
                continue;
            if (constructor.getName().contains(className))
                return constructor;
        }

        return null;
        /*
        String name = getConstructorName(className);
        Function func = FunctionUtil.getFunctionWithName(Environment.getProgram(), name);
        if (func != null)
            return func;
        else {
            name = "<EXTERNAL>::" + name;
            return FunctionUtil.getFunctionWithName(Environment.getProgram(), name);
        }
        */
    }

    public String getConstructorName(String className) {
        return className + "::" + className;
    }
    
    public String getClassNameFromFunctionName(String funcName) {
        if (funcName.contains("::"))
            return funcName.split("::")[0];
        else
            return null;
    }



    public void getAllCalledConstructors() {

        calledConstructors = new HashSet<>();
        calledConstructors.add(slotConstructor);

        Set<Function> calledFunctions = slotConstructor.getCalledFunctions(TimeoutTaskMonitor.timeoutIn(Configs.DISASSEMBLE_TIMEOUT, TimeUnit.SECONDS));

        for (Function f: calledFunctions) {
            if (!f.getName().contains("::")) {
                Function thunkedFunc = f.getThunkedFunction(true);
                if (thunkedFunc != null && thunkedFunc.toString().contains("::")) {
                    if (FunctionUtil.isConstructor(thunkedFunc)) {
                        calledConstructors.add(thunkedFunc);
                    }
                }
            }
            else {
                if (FunctionUtil.isConstructor(f))
                    calledConstructors.add(f);
            }
        }
    }
}
