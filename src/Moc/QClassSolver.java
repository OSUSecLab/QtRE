package Moc;

import Constant.Configs;
import Main.Decompiler;
import Main.Environment;
import Util.*;
import ghidra.app.emulator.EmulatorHelper;
import ghidra.pcode.emulate.UnimplementedCallOtherException;
import ghidra.pcode.emulate.UnimplementedInstructionException;
import ghidra.pcode.memstate.MemoryFaultHandler;
import ghidra.pcode.utils.Utils;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.pcode.HighFunction;
import ghidra.program.model.pcode.PcodeOpAST;
import ghidra.program.model.symbol.*;
import ghidra.program.util.string.FoundString;
import ghidra.util.LittleEndianDataConverter;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TimeoutTaskMonitor;
import org.json.JSONObject;

import java.math.BigInteger;
import java.util.*;
import java.util.concurrent.TimeUnit;

public class QClassSolver {

    public Program program;
    public String className;

    public Address metaObject;
    public Function metaCall;

    public String parentClassName;
    public Address parentMetaObject;

    public Address metaStringData;
    public Address metaDataCounter;
    public Function staticMetaCall;

    public List<String> strings = new ArrayList<>();
    public StringBuilder stringConcat = new StringBuilder();

    public JSONObject propertyIndexMap = new JSONObject();
    public JSONObject signalMap = new JSONObject();
    public JSONObject slotMap = new JSONObject();

    // meta data
    public int revision;
    public int methodCount;
    public int propertyCount;
    public int signalCount;

    public int methodStartIndex;
    public int propertyStartIndex;

    public JSONObject result;
    
    // This config enable whether to fork a branch when encountering conditional branches during emulation
    // Disabled by default for performance concern
    public boolean enableBranchFork = false;


    public QClassSolver(Program program, String className) {
        this.program = program;
        this.className = className;
    }

    public void solve() {
        // find meta call function
        List<Address> metaAddrs = FunctionUtil.locateFunctionWithSig(program, className + "::qt_metacall(typedefCalldword,int,void**)", true);
        if (metaAddrs.size() == 0) {
            // try fuzzy search...
            for (Function f: FunctionUtil.getAllFunctions(program)) {
                String sig = FunctionUtil.getFunctionSignature(f);
                if (sig.contains(className) && sig.contains("qt_metacall")) {
                    metaCall = f;
                    break;
                }
            }

            if (metaCall == null) {
                System.out.println("qt_metacall not found for " + className);
                return;
            }

        }
        else {
            metaCall = FunctionUtil.getFunctionWith(program, metaAddrs.get(0));
        }

        // find meta object
        metaObject = null;
        SymbolTable symbolTable = program.getSymbolTable();

        for (Symbol symbol: symbolTable.getAllSymbols(true)) {
            if (symbol.getName().equals("staticMetaObject")) {
                Namespace ns = symbol.getParentNamespace();
                if (ns.getName().equals(className)) {
                    metaObject = symbol.getAddress();
                    break;
                }
            }
        }

        if (metaObject == null) { // not found
            System.out.println("staticMetaObject not found for " + className);
            return;
        }

        // parent class
        Address current = metaObject;
        byte[] bytes = new byte[Environment.POINTER_SIZE];
        try {
            program.getMemory().getBytes(current, bytes);
        } catch (MemoryAccessException e) {
            e.printStackTrace();
            return;
        }

        long addVal = NumericUtil.byteToLongLittleEndian(bytes);
        parentMetaObject = program.getAddressFactory().getAddress(NumericUtil.longToHexString(addVal));

        if (parentMetaObject == null) {
            System.out.println("Parent meta object not an address type: " + className);
        }

        Symbol[] symbols = symbolTable.getSymbols(parentMetaObject);
        for (Symbol sym: symbols) {
            Namespace ns = sym.getParentNamespace();
            if (!ns.getName().equals("Global")) {
                parentClassName = ns.getName();
                break;
            }
        }


        // meta string data
        current = current.add(Environment.POINTER_SIZE);
        if (current != null) {
            bytes = new byte[Environment.POINTER_SIZE];
            try {
                program.getMemory().getBytes(current, bytes);
            } catch (MemoryAccessException e) {
                e.printStackTrace();
                return;
            }

            addVal = NumericUtil.byteToLongLittleEndian(bytes);
            metaStringData = program.getAddressFactory().getAddress(NumericUtil.longToHexString(addVal));

            if (metaStringData == null) {
                System.out.println("Meta string data not an address type: " + className);
            }
        }

        // meta data counter
        current = current.add(Environment.POINTER_SIZE);
        if (current != null) {
            bytes = new byte[Environment.POINTER_SIZE];
            try {
                program.getMemory().getBytes(current, bytes);
            } catch (MemoryAccessException e) {
                e.printStackTrace();
                return;
            }

            addVal = NumericUtil.byteToLongLittleEndian(bytes);
            metaDataCounter = program.getAddressFactory().getAddress(NumericUtil.longToHexString(addVal));

            if (metaDataCounter == null) {
                System.out.println("Meta string data not an address type: " + className);
            }
        }

        // static meta call
        current = current.add(Environment.POINTER_SIZE);
        if (current != null) {
            bytes = new byte[Environment.POINTER_SIZE];
            try {
                program.getMemory().getBytes(current, bytes);
            } catch (MemoryAccessException e) {
                e.printStackTrace();
                return;
            }

            addVal = NumericUtil.byteToLongLittleEndian(bytes);
            Address staticMetaCallAddress = program.getAddressFactory().getAddress(NumericUtil.longToHexString(addVal));
            if (staticMetaCallAddress.getUnsignedOffset() == 0) {
                // static_metacall not exist
                System.out.println("Meta string data not an address type: " + className);
                staticMetaCall = null;
            }
            else {
                staticMetaCall = FunctionUtil.getFunctionWith(program, staticMetaCallAddress);
            }
        }

        // construct string array
        analyzeString();

        try {
            analyzeMetaData();
            analyzeMethodMeta();
            analyzePropertyMeta();
            analyzeMetaCall();
        }
        catch (MemoryAccessException e) {
            e.printStackTrace();
        }

        processResult();
    }


    public void analyzeString() {

        Address current = metaStringData;
        Address start, end;

        byte[] bytes = new byte[this.className.length()];

        // find the start of the string table
        while (true) {
            try {
                program.getMemory().getBytes(current, bytes);
                String s = new String(bytes);
                if (s.startsWith(this.className)) {
                    start = current;
                    break;
                }
                current = current.next();
            }
            catch (MemoryAccessException e) {
                return;
            }
        }


        SymbolTable symboltable = program.getSymbolTable();
        // find the end of the string table
        do {
            current = current.next();
        }
        while (symboltable.getSymbols(current).length == 0); // loop until next string table is reached, which ends the current table
        end = current;


        if (start == null || end == null)
            return;

        AddressSetView addressSetView = new AddressSet(start, end);
        List<FoundString> foundStrings = StringUtil.findStrings(program, addressSetView, 1, 1, true, true);

        for (int i=0; i<foundStrings.size(); ++i) {

            String str = foundStrings.get(i).getString(program.getMemory());
            strings.add(str);
            stringConcat.append(str);
            stringConcat.append(" ");
            if (i < foundStrings.size() - 1) {
                FoundString nextStr = foundStrings.get(i+1);
                if (nextStr.getAddress().getUnsignedOffset() - foundStrings.get(i).getEndAddress().getUnsignedOffset() != 1) {
                    // space exists
                    strings.add(" ");
                    stringConcat.append(" ");
                }
            }
        }

    }


    public void analyzeMetaData() throws MemoryAccessException {
        if (metaDataCounter == null)
            return;

        Address current = metaDataCounter;
        byte[] bytes = new byte[4];

        // revision
        program.getMemory().getBytes(current, bytes);
        revision = (int) NumericUtil.byteToLongLittleEndian(bytes);
        current = current.add(4);

        // classname
        current = current.add(4);

        // classinfo
        current = current.add(8);

        // methods
        program.getMemory().getBytes(current, bytes);
        methodCount = (int) NumericUtil.byteToLongLittleEndian(bytes);
        current = current.add(4);
        program.getMemory().getBytes(current, bytes);
        methodStartIndex = (int) NumericUtil.byteToLongLittleEndian(bytes);
        current = current.add(4);

        // properties
        program.getMemory().getBytes(current, bytes);
        propertyCount = (int) NumericUtil.byteToLongLittleEndian(bytes);
        current = current.add(4);
        program.getMemory().getBytes(current, bytes);
        propertyStartIndex = (int) NumericUtil.byteToLongLittleEndian(bytes);
        current = current.add(4);

        // enums/sets
        current = current.add(8);

        // constructors
        current = current.add(8);

        // flags
        current = current.add(4);

        // signalCount
        program.getMemory().getBytes(current, bytes);
        signalCount = (int) NumericUtil.byteToLongLittleEndian(bytes);
        current = current.add(4);

    }


    public void analyzeMethodMeta() throws MemoryAccessException {
        if (signalCount == 0 || methodStartIndex == 0)
            return;

        Address current = metaDataCounter.add(methodStartIndex*4);
        // parse signal
        for (int i=0; i<signalCount; ++i) {
            byte[] bytes = new byte[4];

            // name
            program.getMemory().getBytes(current.add(0), bytes);
            int index = (int) NumericUtil.byteToLongLittleEndian(bytes);

            // argc
            program.getMemory().getBytes(current.add(4), bytes);
            int argc = (int) NumericUtil.byteToLongLittleEndian(bytes);
            String argc_str = getStringFromMeta(argc);

            // param index
            program.getMemory().getBytes(current.add(8), bytes);
            int paramIndex = (int) NumericUtil.byteToLongLittleEndian(bytes);

            // tag
            program.getMemory().getBytes(current.add(12), bytes);
            int tag = (int) NumericUtil.byteToLongLittleEndian(bytes);

            // flags
            program.getMemory().getBytes(current.add(16), bytes);
            int flags = (int) NumericUtil.byteToLongLittleEndian(bytes);


            // get signal name
            String signalName = parseName(index);

            // parse args
            JSONObject args = parseArgs(paramIndex, argc);

            JSONObject tmp = new JSONObject();
            tmp.put("name", signalName);
            //tmp.put("argc", argc);
            tmp.put("args", args);
            signalMap.put(i + "", tmp);

            current = current.add(20); // entry size = 20
        }

        // parse slots
        int slotCount = methodCount - signalCount;
        for (int i=0; i<slotCount; ++i) {

            byte[] bytes = new byte[4];

            // name
            program.getMemory().getBytes(current.add(0), bytes);
            int index = (int) NumericUtil.byteToLongLittleEndian(bytes);

            // argc
            program.getMemory().getBytes(current.add(4), bytes);
            int argc = (int) NumericUtil.byteToLongLittleEndian(bytes);

            // param index
            program.getMemory().getBytes(current.add(8), bytes);
            int paramIndex = (int) NumericUtil.byteToLongLittleEndian(bytes);

            // tag
            program.getMemory().getBytes(current.add(12), bytes);
            int tag = (int) NumericUtil.byteToLongLittleEndian(bytes);

            // flags
            program.getMemory().getBytes(current.add(16), bytes);
            int flags = (int) NumericUtil.byteToLongLittleEndian(bytes);

            // get slot name
            String slotName = parseName(index);

            // parse args
            JSONObject args = parseArgs(paramIndex, argc);

            JSONObject tmp = new JSONObject();
            tmp.put("name", slotName);
            //tmp.put("argc", argc);
            tmp.put("args", args);
            slotMap.put(i + "", tmp);

            current = current.add(20);
        }
    }

    public JSONObject parseArgs(int startIndex, int argc) throws MemoryAccessException{

        JSONObject result = new JSONObject();

        if (this.revision <= 5) {
            // in old version, the string at argc represents the arguments
            String args = getStringFromMeta(argc);
            if (args.equals(""))
                return result;
            else {
                String[] tokens = args.split(",");
                for (int i=0; i<tokens.length; ++i) {
                    result.put(i + "", new JSONObject());
                    result.getJSONObject(i + "").put("name", tokens[i]);
                }
                return result;
            }
        }
        else {
            Address current = metaDataCounter.add(startIndex * 4);


            byte[] bytes = new byte[4];

            // return type
            program.getMemory().getBytes(current, bytes);
            int retType = (int) NumericUtil.byteToLongLittleEndian(bytes);
            result.put("retType", retType);
            current = current.add(4);

            // arg type
            for (int i = 0; i < argc; ++i) {
                program.getMemory().getBytes(current, bytes);
                int typeIndex = (int) NumericUtil.byteToLongLittleEndian(bytes);
                String type = parseType(typeIndex);
                result.put(i + "", new JSONObject());
                result.getJSONObject(i + "").put("type", type);
                current = current.add(4);
            }

            // arg index
            for (int i = 0; i < argc; ++i) {
                program.getMemory().getBytes(current, bytes);
                int index = (int) NumericUtil.byteToLongLittleEndian(bytes);
                String name = parseName(index);
                result.getJSONObject(i + "").put("name", name);
                current = current.add(4);
            }

            return result;
        }

    }


    public void analyzePropertyMeta() throws MemoryAccessException{
        if (propertyCount == 0 || propertyStartIndex == 0)
            return;

        Address properyStart = metaDataCounter.add(propertyStartIndex*4);
        for (int i=0; i<propertyCount; ++i) {

            JSONObject tmp = new JSONObject();

            Address propertyAddress = properyStart.add(i*12); // entry size = 12
            // string index
            byte[] bytes = new byte[4];
            program.getMemory().getBytes(propertyAddress, bytes);
            int index = (int) NumericUtil.byteToLongLittleEndian(bytes);
            String propertyName = parseName(index);
            tmp.put("name", propertyName);

            // type
            program.getMemory().getBytes(propertyAddress.add(4), bytes);
            int typeIndex = (int) NumericUtil.byteToLongLittleEndian(bytes);
            String type = parseType(typeIndex);
            tmp.put("type", type);

            // flags
            program.getMemory().getBytes(propertyAddress.add(8), bytes);
            int flags = (int) NumericUtil.byteToLongLittleEndian(bytes);
            tmp.put("flags", flags);

            // add to result
            propertyIndexMap.put(i + "", tmp);

        }
    }


    public void analyzeMetaCall() {

        // analyze the property-memory mapping in the meta call function
        if (metaCall == null && staticMetaCall == null)
            return;

        Set<String> propKeySet = propertyIndexMap.keySet();
        Function funcToExec = null;


        if (staticMetaCall != null) {
            // emulate static meta call if possible
            funcToExec = staticMetaCall;
        }
        else if (metaCall != null) {
            funcToExec = metaCall;
        }


        for (String key: propKeySet) {

            int index = Integer.valueOf(key);

            // execute meta call function with emulation
            //List<Long> symbolicOffset = emulate(index, funcToExec);
            List<String> exps = new ArrayList<>();

            Map<Long, Boolean> unexploredBranch = new HashMap<>();
            String resultExp = emulate(index, funcToExec, unexploredBranch);
            exps.add(resultExp);

            int maxExploreAttempt = 5;
            int attempt = 0;
            while (!checkAllExplored(unexploredBranch) && attempt < maxExploreAttempt) {
                resultExp = emulate(index, funcToExec, unexploredBranch);
                exps.add(resultExp);
                attempt ++;
            }


            /*
            // construct property expression
            Node head = null;
            for (int i = 0; i < symbolicOffset.size(); ++i) {
                int offset = (int) (long) symbolicOffset.get(i);
                String hex = "0x" + Integer.toHexString(offset);
                if (i == 0) {
                    Node currentNode = new ExpNode("INT_ADD", new LeafNode(Environment.EXP_R0), new LeafNode(String.format("(const, %s, 4)", hex)));
                    Node parent = new ExpNode("LOAD", new LeafNode("(const, 0x1a1, 4)"), currentNode);
                    head = parent;
                }
                else {
                    Node currentNode = new ExpNode("INT_ADD", head, new LeafNode(String.format("(const, %s, 4)", hex)));
                    head = new ExpNode("LOAD", new LeafNode("(const, 0x1a1, 4)"), currentNode);
                }
            }

            String exp = "";
            if (head != null) {
                try {
                    exp = Node.evaluate(head);
                } catch (StackOverflowError e) {

                }
            }
            */

            // put expression
            for (int i=0; i<exps.size(); ++i) {
                propertyIndexMap.getJSONObject(key).put("expression" + i, exps.get(i));
            }
        }

    }

    private boolean checkAllExplored(Map<Long, Boolean> map) {
        for (Boolean b: map.values()) {
            if (!b)
                return false;
        }
        return true;
    }

    public String emulate(int index, Function function, Map<Long, Boolean> unexploredBranch) {
        // r1 = 0: QMetaObject::InvokeMetaMethod
        // r1 = 1: QMetaObject::ReadProperty
        // r1 = 2: QMetaObject::WriteProperty
        // r1 = 10:QMetaObject::IndexOfMethod

        // r1 = 1 (READ), r2 = index, r3 stores the result

        EmulatorHelper emulatorHelper = new EmulatorHelper(program);

        HighFunction currentDecompileFunc = Decompiler.decompileFuncRegister(program, function).getHighFunction();

        long probeLRVal = 0xFFFE; // we assign lr with a value that marks the end of the function execution
        long symbolicVal = 0xE0; // assign a value at high memory as a symbolic value
        long symbolicRegionLimit = 0x1000; // symbolic region size
        long symbolicRegionSize = 0x1000;
        long indexBase = 0xE0;
        int resultRegion = 0x2000;

        // hope the symbolic computation region does not overlap with the code...
        long baseAddr = Environment.getProgram().getImageBase().getUnsignedOffset();
        if (baseAddr > resultRegion + 0x100) {
            // as long as the base address is larger than the symbolic computation region then we're fine
        }
        else {
            System.out.println("Image base has conflict with the symbolic computation region, cannot safely proceed, exiting...");
            return "";
        }

        Map<Long, String> symbolicMap = new HashMap<>();

        List<String> exps = new ArrayList<>();
        String resultExp = null;

        // initialize registers
        if (Environment.LANGUAGE_NAME.contains("ARM")) {
            emulatorHelper.writeRegister("r0", symbolicVal);
            emulatorHelper.writeRegister("r1", 1);
            emulatorHelper.writeRegister("r2", index);
            emulatorHelper.writeRegister("r3", resultRegion);
            emulatorHelper.writeRegister("lr", probeLRVal); // return address
        }
        else if (Environment.LANGUAGE_NAME.contains("x86")) {
            emulatorHelper.writeRegister("RDI", symbolicVal);
            emulatorHelper.writeRegister("ESI", 1);
            emulatorHelper.writeRegister("EDX", index);
            emulatorHelper.writeRegister("RCX", resultRegion);
            //emulatorHelper.writeMemory(emulatorHelper.getStackPointerRegister().getAddress(), DataConverter.getInstance(false).getBytes(probeLRVal));
        }


        // result Region: a: 0x2000, *a: 0x2008, **a: 0x2010
        emulatorHelper.writeMemory(AddressUtil.getAddressFromLong(program, resultRegion), NumericUtil.intToBytes(resultRegion+8, true));
        emulatorHelper.writeMemory(AddressUtil.getAddressFromLong(program, resultRegion+8), NumericUtil.intToBytes(0, true));


        // set starting point
        Address startingPoint = function.getEntryPoint();
        emulatorHelper.writeRegister(emulatorHelper.getPCRegister(), startingPoint.getUnsignedOffset());

        List<Long> symbolicOffset = new ArrayList<>();

        Map<Long, List<Long>> symbolicRegions = new HashMap<>();

        // define memory read handler to intercept memory reads
        emulatorHelper.setMemoryFaultHandler(new MemoryFaultHandler() {
            @Override
            public boolean uninitializedRead(Address address, int i, byte[] bytes, int i1) {
                if (address.getUnsignedOffset() >= symbolicVal && address.getUnsignedOffset() < (symbolicVal + symbolicRegionLimit)) {
                    // falls into the symbolic value region
                    Function f = FunctionUtil.getFunctionWith(program, emulatorHelper.getExecutionAddress());
                    HighFunction highFunction = Decompiler.decompileFuncRegister(program, f).getHighFunction();
                    Iterator<PcodeOpAST> asts = highFunction.getPcodeOps(emulatorHelper.getExecutionAddress());

                    String exp = "";
                    while (asts.hasNext()) {
                        PcodeOpAST ast = asts.next();
                        if (ast.getMnemonic().equals("INT_ADD")) {
                            exp = PCodeUtil.evaluateVarNode(ast.getOutput());
                            break;
                        }
                    }
                    if (exp.contains(Environment.EXP_R0)) {
                        exps.add(exp);

                        // assigns new symbolic value
                        long newSymbolicIndex = indexBase + symbolicMap.keySet().size();
                        symbolicMap.put(newSymbolicIndex, exp);
                        emulatorHelper.writeMemory(address, Utils.longToBytes(newSymbolicIndex, Environment.POINTER_SIZE, false));
                    }
                }
                return true;
            }

            @Override
            public boolean unknownAddress(Address address, boolean b) {
                return false;
            }
        });


        TaskMonitor monitor = TimeoutTaskMonitor.timeoutIn(Configs.EMULATION_TIMEOUT, TimeUnit.SECONDS);

        Function currentFunction = function;
        if (currentFunction.getThunkedFunction(true) != null)
            currentFunction = currentFunction.getThunkedFunction(true);


        // start emulation
        while (!monitor.isCancelled()) {
            Address currentAdd = emulatorHelper.getExecutionAddress();
            //System.out.println(currentAdd);

            try {
                boolean success = emulatorHelper.step(monitor);

                if (!success) {
                    String error = emulatorHelper.getLastError();
                    if (error.contains("Unimplemented")) {
                        emulatorHelper.writeRegister(emulatorHelper.getPCRegister(), AddressUtil.getAddressInNextIns(program, currentAdd).getUnsignedOffset());
                    }
                    System.out.println(emulatorHelper.getLastError());
                }
            } catch (CancelledException e) {
                break;
            } catch (UnimplementedCallOtherException | UnimplementedInstructionException e) {
                e.printStackTrace();
                // skip unknown ops
                emulatorHelper.writeRegister(emulatorHelper.getPCRegister(), AddressUtil.getAddressInNextIns(program, currentAdd).getUnsignedOffset());
            }

            Address next = AddressUtil.getAddressFromLong(program, emulatorHelper.readRegister(emulatorHelper.getPCRegister()).longValue());
            if (next.getUnsignedOffset() != currentAdd.getUnsignedOffset()) {
                Environment.PCODE_INS_COUNT += 1;
            }

            if (currentFunction.getBody().contains(next)) {
                Iterator<PcodeOpAST> asts = currentDecompileFunc.getPcodeOps(currentAdd);
                boolean branchFlag = false;
                Address branchAddr = null;
                // detect conditional branch
                while (asts.hasNext()) {
                    PcodeOpAST ast = asts.next();
                    if (ast.getMnemonic().equals("CBRANCH")) { // conditional branch happens
                        if (enableBranchFork)
                            branchFlag = true;
                        branchAddr = ast.getInputs()[0].getAddress();
                        break;
                    }
                }

                if (branchFlag) {
                    if (!currentFunction.toString().contains("qt_metacall") && currentFunction.getEntryPoint().getUnsignedOffset() != function.getEntryPoint().getUnsignedOffset()) {
                        // jump happens (not in metacall function), fork another branch
                        long branch1 = AddressUtil.getAddressInNextIns(program, currentAdd).getUnsignedOffset();
                        long branch2 = branchAddr.getUnsignedOffset();

                        // decide which branch to go
                        if (!unexploredBranch.containsKey(branch1) || !unexploredBranch.get(branch1)) {
                            // go to branch 1
                            emulatorHelper.writeRegister(emulatorHelper.getPCRegister(), branch1);
                            unexploredBranch.put(branch1, true);
                            next = AddressUtil.getAddressFromLong(program, branch1);

                            if (!unexploredBranch.containsKey(branch2) || !unexploredBranch.get(branch2)) {
                                // explore branch2 in later execution
                                unexploredBranch.put(branch2, false);
                            }
                        }
                        else {
                            // branch 1 has been explored, check branch 2
                            if (!unexploredBranch.containsKey(branch2) || !unexploredBranch.get(branch2)) {
                                // explore branch2
                                emulatorHelper.writeRegister(emulatorHelper.getPCRegister(), branch2);
                                unexploredBranch.put(branch2, true);
                                next = AddressUtil.getAddressFromLong(program, branch2);
                            }
                            else {
                                // both branch have been explored, randomly choose a branch
                                long choice = System.currentTimeMillis() % 2;
                                if (choice == 0) {
                                    // explore branch 1
                                    emulatorHelper.writeRegister(emulatorHelper.getPCRegister(), branch1);
                                    next = AddressUtil.getAddressFromLong(program, branch1);
                                }
                                else {
                                    // explore branch 2
                                    emulatorHelper.writeRegister(emulatorHelper.getPCRegister(), branch2);
                                    next = AddressUtil.getAddressFromLong(program, branch2);
                                }
                            }
                        }
                    }
                }
            }
            else { 
                // jump to another function detected
                if (next.getUnsignedOffset() == probeLRVal || next.toString().equals("00000000")) {
                    // emulation ends, select results
                    byte[] bytes = emulatorHelper.readMemory(AddressUtil.getAddressFromLong(program, resultRegion+8), 4);
                    long val = NumericUtil.byteToLongLittleEndian(bytes);
                    if (val == 0)
                        resultExp = "NULL";
                    else {
                        if (symbolicMap.get(val) != null)
                            resultExp = symbolicMap.get(val);
                        else
                            resultExp = "NULL";
                    }
                    break;
                }

                // jumping to other functions
                try {
                    Function nextFunction = FunctionUtil.getFunctionWith(program, next);
                    if (nextFunction.getThunkedFunction(true) != null)
                        nextFunction = nextFunction.getThunkedFunction(true);
                    String nextFuncName = nextFunction.getName();
                    if (nextFuncName.equals("qt_metacall") && nextFunction.toString().contains(parentClassName)) {
                        // skip invoking parent meta call function
                        //emulatorHelper.writeRegister(emulatorHelper.getPCRegister(), currentAdd.add(Environment.POINTER_SIZE).getUnsignedOffset());
                        emulatorHelper.writeRegister(emulatorHelper.getPCRegister(), AddressUtil.getAddressInNextIns(program, currentAdd).getUnsignedOffset());

                        // replace return value as the index
                        emulatorHelper.writeRegister(Environment.RETURN_REG, index);
                    }
                    else if (nextFunction.isExternal()) {
                        // skip external function
                        emulatorHelper.writeRegister(emulatorHelper.getPCRegister(), AddressUtil.getAddressInNextIns(program, currentAdd).getUnsignedOffset());
                    }
                    else {

                        Function currentFunc = FunctionUtil.getFunctionWith(program, currentAdd);
                        if (currentFunc.getThunkedFunction(true) != null)
                            currentFunc = currentFunc.getThunkedFunction(true);
                        Namespace currentNs = currentFunc.getParentNamespace();
                        Namespace nextNs = nextFunction.getParentNamespace();
                        if (currentFunc.getEntryPoint().getUnsignedOffset() == function.getEntryPoint().getUnsignedOffset() ||
                            nextFunction.getEntryPoint().getUnsignedOffset() == function.getEntryPoint().getUnsignedOffset()) {
                            // jump to next function
                            currentFunction = nextFunction;
                            currentDecompileFunc = Decompiler.decompileFuncRegister(program, currentFunction).getHighFunction();
                        }
                        else if (!currentNs.getName().equals(nextNs.getName())) {
                            // do not execute functions in other class's context
                            emulatorHelper.writeRegister(emulatorHelper.getPCRegister(), AddressUtil.getAddressInNextIns(program, currentAdd).getUnsignedOffset());
                        }
                        else {
                            // jump to next function
                            currentFunction = nextFunction;
                            currentDecompileFunc = Decompiler.decompileFuncRegister(program, currentFunction).getHighFunction();
                        }

                    }

                } catch (NullPointerException e) {
                    if (next.toString().equals("ffff0fc0")) {
                        // TODO skip this shit
                        emulatorHelper.writeRegister(Environment.RETURN_REG, 0); // set return value as 0
                    }
                    emulatorHelper.writeRegister(emulatorHelper.getPCRegister(), AddressUtil.getAddressInNextIns(program, currentAdd).getUnsignedOffset());
                }
            }

        }


        return resultExp;
    }


    public String getStringFromMeta(int startIndex) {
        try {
            String result = "";
            for (int j = startIndex; j < stringConcat.length(); ++j) {
                if (stringConcat.charAt(j) != ' ') {
                    result = result + stringConcat.charAt(j);
                } else
                    break;
            }
            return result;
        }
        catch (Exception e) {
            return "";
        }
    }

    public String parseType(int index) {
        if (this.revision <= 5) {
            return getStringFromMeta(index);
        }
        else {
            switch (index) {
                // Based on https://codebrowser.dev/qt5/qtbase/src/corelib/kernel/qmetatype.h.html
                case 0:
                    return "UnknownType";
                case 1:
                    return "Bool";
                case 2:
                    return "Int";
                case 3:
                    return "UInt";
                case 4:
                    return "LongLong";
                case 5:
                    return "ULongLong";
                case 6:
                    return "Double";
                case 7:
                    return "QChar";
                case 8:
                    return "QVariantMap";
                case 9:
                    return "QVariantList";
                case 10:
                    return "QString";
                case 11:
                    return "QStringList";
                case 12:
                    return "QByteArray";
                case 13:
                    return "QBitArray";
                case 14:
                    return "QDate";
                case 15:
                    return "QTime";
                case 16:
                    return "QDateTime";
                case 17:
                    return "QUrl";
                case 18:
                    return "QLocale";
                case 19:
                    return "QRect";
                case 20:
                    return "QRectF";
                case 21:
                    return "QSize";
                case 22:
                    return "QSizeF";
                case 23:
                    return "QLine";
                case 24:
                    return "QLineF";
                case 25:
                    return "QPoint";
                case 26:
                    return "QPointF";
                case 27:
                    return "QRegExp";
                case 28:
                    return "QVariantHash";
                case 29:
                    return "QEasingCurve";
                case 30:
                    return "QUuid";
                case 32:
                    return "Long";
                case 33:
                    return "Short";
                case 34:
                    return "Char";
                case 35:
                    return "ULong";
                case 36:
                    return "UShort";
                case 37:
                    return "UChar";
                case 38:
                    return "Float";
                case 41:
                    return "QVariant";
                case 42:
                    return "QModelIndex";
                case 43:
                    return "Void";
                case 44:
                    return "QRegularExpression";
                case 45:
                    return "QJsonValue";
                case 46:
                    return "QJsonObject";
                case 47:
                    return "QJsonArray";
                case 48:
                    return "QJsonDocument";
                case 51:
                    return "Nullptr";
                case 52:
                    return "QCborSimpleType";
                case 53:
                    return "QCborValue";
                case 54:
                    return "QCborArray";
                case 55:
                    return "QCborMap";
                case 64:
                    return "QFont";
                case 65:
                    return "QPixmap";
                case 66:
                    return "QBrush";
                case 67:
                    return "QColor";
                case 68:
                    return "QPalette";
                case 69:
                    return "QIcon";
                case 70:
                    return "QImage";
                case 71:
                    return "QPolygon";
                case 72:
                    return "QRegion";
                case 73:
                    return "QBitmap";
                case 74:
                    return "QCursor";
                case 75:
                    return "QKeySequence";
                case 76:
                    return "QPen";
                case 77:
                    return "QTextLength";
                case 78:
                    return "QTextFormat";
                case 79:
                    return "QMatrix";
                case 80:
                    return "QTransform";
                case 81:
                    return "QMatrix4x4";
                case 82:
                    return "QVector2D";
                case 83:
                    return "QVector3D";
                case 84:
                    return "QVector4D";
                case 85:
                    return "QQuaternion";
                case 86:
                    return "QPolygonF";
                case 121:
                    return "QSizePolicy";
                default:
                    return "" + index;
            }
        }
    }

    public String parseName(int index) {
        if (this.revision <= 5) {
            return getStringFromMeta(index);
        }
        else {
            try {
                return strings.get(index);
            } catch (Exception e) {
                return null;
            }
        }
    }


    public void processResult() {
        if (metaCall == null && staticMetaCall == null)
            return;

        result = new JSONObject();
        result.put("parent", parentClassName);
        result.put("metaCall", metaCall.getEntryPoint());
        if (staticMetaCall != null) {
            result.put("staticMetaCall", staticMetaCall.getEntryPoint());
        }
        result.put("stringData", metaStringData);
        result.put("methodCount", methodCount);
        result.put("propertyCount", propertyCount);
        result.put("signalCount", signalCount);

        result.put("property", propertyIndexMap);
        result.put("signal", signalMap);
        result.put("slot", slotMap);
    }


}
