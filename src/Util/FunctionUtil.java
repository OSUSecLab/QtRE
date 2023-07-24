package Util;

import Constant.Configs;
import Constant.Constants;
import Main.Environment;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.util.task.TimeoutTaskMonitor;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.concurrent.TimeUnit;

public class FunctionUtil {


    public static List<Function> getAllFunctions(Program program) {
        // load all function if not done
        FunctionIterator funcIt = program.getFunctionManager().getFunctions(true);
        List<Function> functions = new ArrayList<>();

        for (Function extfun : funcIt) {
            functions.add(extfun);
        }

        return functions;
    }

    public static String getClassFromFuncName(String name) {
        name = name.replace("<EXTERNAL>::", "");
        if (name.contains("::")) {
            String[] tokens = name.split("::");
            int lastIndex = tokens.length - 1;
            return tokens[lastIndex - 1];
        }
        else
            return null;
    }

    public static Function getFunctionWithName(Program program, String funcName) {

        // remove parameters
        if (funcName.contains("("))
            funcName = funcName.substring(0, funcName.indexOf("("));

        for (Function function: getAllFunctions(program)) {
            if (function.toString().equals(funcName))
                return function;
        }

        return null;
    }

    public static List<Function> getAllExternalFunctions(Program program) {

        MemoryBlock[] blocks = program.getMemory().getBlocks();
        MemoryBlock external = null;
        for (MemoryBlock block : blocks) {
            if (block.getName().equals("EXTERNAL")) {
                external = block;
                break;
            }
        }

        List<Function> externalFunc = new ArrayList<>();

        if (external == null)
            return externalFunc;


        for (Function fun: program.getFunctionManager().getFunctions(true)) {
            if (external.contains(fun.getEntryPoint()))
                externalFunc.add(fun);
        }

        /*
        FunctionIterator externalFuncIt = program.getFunctionManager().getExternalFunctions();

        for (Function extfun: externalFuncIt) {
            externalFunc.add(extfun);
        }*/

        return externalFunc;
    }


    public static String getFunctionSignature(Function f) {
        StringBuilder signature = new StringBuilder();
        String name = f.toString();
        String returnType = f.getReturnType().toString();
        StringBuilder params = new StringBuilder();

        for (Parameter p: f.getParameters()) {
            if (p.getDataType().toString().contains("\n")) {
                // special case
                try {
                    params.append(p.toString().split(" ")[0].substring(1));
                    params.append("*");
                } catch (Exception e) {

                }
            }
            else {
                params.append(p.getDataType().toString().replace(" ", ""));
            }
            params.append(",");

        }

        if (params.length() > 0)
            params.deleteCharAt(params.length()-1); // remove the last comma

        // signature.append(returnType);
        // signature.append(" ");
        name = name.replace("<EXTERNAL>::", "");
        name = name.replace("\n", "");
        signature.append(name);
        signature.append("(");
        signature.append(params);
        signature.append(")");

        return signature.toString();
    }


    public static Function getFunctionWith(Program program, Address address) {
        return program.getFunctionManager().getFunctionContaining(address);
    }

    public static Set<Function> getCallingFunction(Function function) {
        try {
            return function.getCallingFunctions(TimeoutTaskMonitor.timeoutIn(500, TimeUnit.SECONDS));
        } catch (NullPointerException e) {
            return null;
        }
    }

    public static Set<Function> getCalledFunction(Function function) {
        try {
            return function.getCalledFunctions(TimeoutTaskMonitor.timeoutIn(500, TimeUnit.SECONDS));
        } catch (NullPointerException e) {
            return null;
        }
    }

    public static List<Address> getConnectAddress(Program program) {
        List<Address> results = new ArrayList<>();
        for (Function f: program.getFunctionManager().getFunctions(true)) {
            String funcName = FunctionUtil.getFunctionSignature(f);
            if (funcName.startsWith("connect(") || funcName.startsWith("connect<") ||
                funcName.startsWith("QObject::connect(") || funcName.startsWith("QObject::connect<") ||
                funcName.startsWith("connectImpl(")) {
                if (!results.contains(f.getEntryPoint())) {
                    results.add(f.getEntryPoint());
                }
            }
        }
        return results;
    }

    public static List<Address> locateFunctionWithSig(Program program, String signature, boolean exactlyEqual) {
        List<Address> results = new ArrayList<>();
        for (Function f: program.getFunctionManager().getFunctions(true)) {
            Function thunkedFunc = f.getThunkedFunction(true);
            if (thunkedFunc != null)
                f = thunkedFunc;
            if (exactlyEqual) {
                if (getFunctionSignature(f).equals(signature) || (thunkedFunc != null && getFunctionSignature(thunkedFunc).equals(signature))) {
                    if (!results.contains(f.getEntryPoint()))
                        results.add(f.getEntryPoint());
                }
            }
            else {
                if (getFunctionSignature(f).contains(signature) || (thunkedFunc != null && getFunctionSignature(thunkedFunc).contains(signature))) {
                    if (!results.contains(f.getEntryPoint()))
                        results.add(f.getEntryPoint());
                }
            }
        }

        return results;
    }

    public static List<Function> getFunctionWithoutCaller(Program program) {
        List<Function> results = new ArrayList<>();
        for (Function f: program.getFunctionManager().getFunctions(true)) {
            try {
                if (f.getCallingFunctions(TimeoutTaskMonitor.timeoutIn(500, TimeUnit.SECONDS)).size() == 0)
                    results.add(f);
            }
            catch (NullPointerException e) {
                results.add(f);
            }
        }
        return results;
    }

    public static void recursiveGetCalledFunc(Function function, Set<Function> res) {

        String className = function.toString().split("::")[0];

        if (function == null)
            return;

        Set<Function> callingFunc = function.getCalledFunctions(TimeoutTaskMonitor.timeoutIn(Configs.DISASSEMBLE_TIMEOUT, TimeUnit.SECONDS));

        if (callingFunc == null)
            return;

        for (Function des: callingFunc) {
            if (des.toString().contains("::")) {
                if (des.toString().split("::")[0].equals(className)) {
                    // class name match
                    res.add(des);
                    recursiveGetCalledFunc(des, res);
                }
            }
            else if (des.getThunkedFunction(true) != null && des.getThunkedFunction(true).toString().contains("::")
                    && des.getThunkedFunction(true).toString().split("::")[0].equals(className)) {
                // class name of thunked function match
                res.add(des.getThunkedFunction(true));
                recursiveGetCalledFunc(des.getThunkedFunction(true), res);
            }
        }
    }


    public static boolean isConstructor(Function func) {
        if (func == null)
            return false;

        if (!func.toString().contains("::")) {
            if (func.getThunkedFunction(true) != null) {
                func = func.getThunkedFunction(true); // handle thunked function
                if (!func.toString().contains("::"))
                    return false;
            }
            else
                return false;
        }

        String[] tokens = func.toString().split("::");
        int lastIndex = tokens.length - 1;
        int lastButTwo = lastIndex - 1;

        return tokens[lastIndex].equals(tokens[lastButTwo]);

        /*
        if (tokens.length == 2 && tokens[0].equals(tokens[1]) ||
                (tokens.length == 3 && tokens[1].equals(tokens[2]))) {
            return true;
        }
        return false;*/
    }


    public static Function getParentConstructor(Program program, Function func) {
        ReferenceManager referenceManager = program.getReferenceManager();

        for (Address add: func.getBody().getAddresses(true)) {
            Reference[] references = referenceManager.getReferencesFrom(add);
            for (Reference ref: references) {
                Function targetFunc = program.getFunctionManager().getFunctionAt(ref.getToAddress());
                if (targetFunc != null) {
                    if (FunctionUtil.isConstructor(targetFunc)) {
                        // return the first constructor that gets called
                        if (targetFunc.getThunkedFunction(true) != null)
                            return targetFunc.getThunkedFunction(true);
                        else
                            return targetFunc;
                    }
                }
            }
        }

        return null;
    }


    public static boolean isSignalFunction(Function function) {
        Set<Function> calledFunc = function.getCalledFunctions(TimeoutTaskMonitor.timeoutIn(Configs.DISASSEMBLE_TIMEOUT, TimeUnit.SECONDS));
        for (Function f: calledFunc) {
            String sig = getFunctionSignature(f);
            if (sig.equals(Constants.ACTIVATE))
                return true;
        }
        return false;
    }
}
