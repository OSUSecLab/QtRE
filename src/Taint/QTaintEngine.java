package Taint;

import Constant.Configs;
import Constant.Constants;
import Main.Decompiler;
import Main.Environment;
import Util.BlockUtil;
import Util.FunctionUtil;
import Util.PCodeUtil;
import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.block.CodeBlock;
import ghidra.program.model.block.CodeBlockReference;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.*;
import org.json.JSONArray;
import org.json.JSONObject;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;

/**
 * Taint analysis engine running of Ghidra's PCode level
 * Input: inputLocations (HashMap)
 */
public class QTaintEngine {

    Address start;
    Function taintFunction;
    String taintExpression;
    List<TaintPath> paths;
    HashMap<Address, String> inputLocations;
    public JSONObject jsonResult = new JSONObject();
    public String outputStr = "";


    public QTaintEngine(Address startAdd, String taintExp) {
        start = startAdd;
        taintExpression = taintExp;
        paths = new ArrayList<>();
        inputLocations = new HashMap<>();

    }

    public void taint() {

        if (taintExpression.equals(""))
            return;

        Program program = Environment.getProgram();
        Function startFunc = FunctionUtil.getFunctionWith(program, start);

        // locate block at the target function
        CodeBlock[] currentBlocks = BlockUtil.locateBlockWithAddress(program, startFunc.getEntryPoint());
        if (currentBlocks == null || currentBlocks.length == 0) {
            System.out.println("Error: block not found for address: " + startFunc.getEntryPoint());
            return;
        }

        identifyInputLoc();
        identifyIndirectInputLoc();
        startTaint();
        evaluateResult();

        /*
        QTaintPath taintPath = new QTaintPath();
        taintPath.addTaintVar(taintExpression);
        CodeBlock currentBlock = currentBlocks[0];
        recursiveTaint(currentBlock, taintPath, new ArrayList<>());

        for (QTaintPath path: allPaths) {
            evaluateEqualExp(path);
        }
        */
    }


    public void identifyInputLoc() {
        Program program = Environment.getProgram();

        taintFunction = FunctionUtil.getFunctionWith(program, start);
        DecompileResults decompileResults = Decompiler.decompileFunc(Environment.getProgram(), taintFunction);
        HighFunction highFunction = decompileResults.getHighFunction();


        Iterator<PcodeOpAST> asts = highFunction.getPcodeOps();

        while (asts.hasNext()) {
            PcodeOpAST ast = asts.next();
            long a = ast.getSeqnum().getTarget().getUnsignedOffset();
            if (ast.getSeqnum().getTarget().getUnsignedOffset() < start.getUnsignedOffset())
                continue; // loop until we reach the starting point
            Iterator<PcodeOpAST> o = highFunction.getPcodeOps(ast.getSeqnum().getTarget());
            Varnode[] inputs = ast.getInputs();
            Varnode output = ast.getOutput();

            String exp = PCodeUtil.evaluateVarNode(output);
            if (exp != null && exp.equals(taintExpression)) {
                if (ast.getOutput() == null)
                    continue;
                inputLocations.put(ast.getSeqnum().getTarget(), output.toString());
            }

        }
    }

    // deal with load/store indirect reference
    public void identifyIndirectInputLoc() {
        Program program = Environment.getProgram();

        Function currentFunc = FunctionUtil.getFunctionWith(program, start);
        DecompileResults decompileResults = Decompiler.decompileFuncRegister(Environment.getProgram(), currentFunc);
        HighFunction highFunction = decompileResults.getHighFunction();

        Iterator<PcodeOpAST> asts = highFunction.getPcodeOps();

        List<String> stackExp = new ArrayList<>();

        while (asts.hasNext()) {
            PcodeOpAST ast = asts.next();
            if (ast.getSeqnum().getTarget().getUnsignedOffset() < start.getUnsignedOffset())
                continue; // loop until we reach the starting point
            Varnode[] inputs = ast.getInputs();
            for (int i=0; i<inputs.length; ++i) {
                String mnem = ast.getMnemonic();

                if (mnem.equals("STORE")) {
                    String expOfSrc = PCodeUtil.evaluateVarNode(inputs[2]);
                    if (expOfSrc!= null && expOfSrc.contains(taintExpression)) {
                        String expToAdd = PCodeUtil.evaluateVarNode(inputs[1]);
                        if (!stackExp.contains(expToAdd))
                            stackExp.add(expToAdd);
                    }
                }
                else if (stackExp.size() != 0) {
                    String outputExp = PCodeUtil.evaluateVarNode(ast.getOutput());
                    if (stackExp.contains(outputExp)) {
                        if (!inputLocations.containsKey(ast.getSeqnum().getTarget()))
                            inputLocations.put(ast.getSeqnum().getTarget(), ast.getOutput().toString());
                    }
                }

            }
        }
    }



    private void startTaint() {
        Program program = Environment.getProgram();

        Function currentFunc = FunctionUtil.getFunctionWith(program, start);
        DecompileResults decompileResults = Decompiler.decompileFunc(Environment.getProgram(), currentFunc);
        HighFunction highFunction = decompileResults.getHighFunction();

        for (Address add: inputLocations.keySet()) {
            Iterator<PcodeOpAST> asts = highFunction.getPcodeOps(add);
            String targetReg = inputLocations.get(add);
            while (asts.hasNext()) {
                PcodeOpAST ast = asts.next();
                if (ast.getOutput() == null)
                    continue;
                if (ast.getOutput().toString().equals(targetReg)) {
                    // start to taint descendants
                    Iterator<PcodeOp> descendants = ast.getOutput().getDescendants();
                    while (descendants.hasNext()) {
                        Environment.PCODE_INS_COUNT ++;
                        PcodeOp des = descendants.next();
                        TaintPath path = new TaintPath();
                        path.addToPath(ast);
                        path.addToPath(des);
                        recursiveTraverse(des, path);
                    }
                }
            }
        }
    }

    public void evaluateResult() {
        jsonResult.put("Function", taintFunction.toString());
        jsonResult.put("TaintExpression", taintExpression);

        JSONObject allPaths = new JSONObject();
        for (TaintPath p: paths) {
            int count = paths.indexOf(p);
            JSONArray jsonArray = new JSONArray();
            for (PcodeOp op: p.path) {
                String mnem = op.getMnemonic();
                Varnode[] inputs = op.getInputs();
                if (mnem.equals("CALL")) {
                    Function func = FunctionUtil.getFunctionWith(Environment.getProgram(), inputs[0].getAddress());
                    StringBuilder tmp = new StringBuilder();
                    tmp.append(op);
                    tmp.append("  ");
                    tmp.append(func.getName());
                    if (func.getName().equals("operator==")) {
                        tmp.append(" ==> ");
                        String exp1 = PCodeUtil.evaluateVarNode(inputs[1]);
                        String exp2 = PCodeUtil.evaluateVarNode(inputs[2]);
                        tmp.append(exp1);
                        tmp.append("=");
                        tmp.append(exp2);
                    }
                    jsonArray.put(tmp.toString());
                }
                else if (mnem.equals("INT_EQUAL")) {
                    StringBuilder tmp = new StringBuilder();
                    tmp.append(op);
                    String exp1 = PCodeUtil.evaluateVarNode(inputs[0]);
                    String exp2 = PCodeUtil.evaluateVarNode(inputs[1]);
                    tmp.append(" ==> ");
                    tmp.append(exp1);
                    tmp.append("=");
                    tmp.append(exp2);
                    jsonArray.put(tmp.toString());
                }
                else {
                    jsonArray.put(op.toString());
                }

            }
            allPaths.put(String.valueOf(count), jsonArray);
        }
        jsonResult.put("paths", allPaths);
        outputStr = jsonResult.toString(4);
    }


    public void recursiveTraverse(PcodeOp current, TaintPath currentPath) {

        if (current == null || current.getOutput() == null) {
            // no outputStr, search ends
            paths.add(currentPath);
            return;
        }

        Iterator<PcodeOp> descendants = current.getOutput().getDescendants();

        if (!descendants.hasNext()) {
            // no descendants, search ends
            paths.add(currentPath);
            return;
        }

        while (descendants.hasNext()) {
            PcodeOp des = descendants.next();
            if (des.getMnemonic().equals("MULTIEQUAL"))
                continue;
            TaintPath newPath = currentPath.clone();
            newPath.addToPath(des);
            recursiveTraverse(des, newPath);
        }
    }



}
