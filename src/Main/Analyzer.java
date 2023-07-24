package Main;

import Constant.Configs;
import Constant.Constants;
import Moc.QClassSolver;
import Taint.InputExpSolver;
import Taint.QTaintEngine;
import Moc.QtConnectSolver;
import Util.*;
import ghidra.app.plugin.core.analysis.AutoAnalysisManager;
import ghidra.app.plugin.processors.sleigh.SleighLanguageProvider;
import ghidra.base.project.GhidraProject;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.util.GhidraProgramUtilities;
import ghidra.test.TestProgramManager;
import ghidra.util.InvalidNameException;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.VersionException;
import ghidra.util.task.TimeoutTaskMonitor;
import org.json.JSONArray;
import org.json.JSONObject;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.*;
import java.util.concurrent.TimeUnit;

public class Analyzer {

    public TestProgramManager programManager;
    public List<Address> connectionPoints = new ArrayList<>();
    public long size;
    public long analysisTime;

    public Analyzer(GhidraProject project, String programName) throws VersionException, CancelledException, DuplicateNameException, InvalidNameException, IOException {

        // Load binary file
        File file = new File(programName);
        size = file.length();
        if (!file.exists()) {
            throw new FileNotFoundException("Can not find Program: " + programName);
        }

        LanguageProvider languageProvider;
        try {
            languageProvider = new SleighLanguageProvider();
        } catch (Exception e) {
            System.out.println("Unable to build language provider.");
            return;
        }

        Language language = languageProvider.getLanguage(new LanguageID(Environment.LANGUAGE_NAME));

        CompilerSpec compilerSpec;
        if (Environment.COMPILER_SPEC.equals("default"))
            compilerSpec = language.getDefaultCompilerSpec();
        else
            compilerSpec = language.getCompilerSpecByID(new CompilerSpecID(Environment.COMPILER_SPEC));

        programManager = new TestProgramManager();

        String appName = programName.substring(programName.lastIndexOf("/")+1);
        Program program;
        try {
            // open analyzed program if exists
            program = project.openProgram("/", appName, false);
        }
        catch (FileNotFoundException e) {
            // import program if not exists
            program = project.importProgram(file, language, compilerSpec);
        }

        long base = program.getImageBase().getUnsignedOffset();

        // Initialize environment variables
        Environment.initProgram(program);
        Environment.initTag(program.getName()); // + "@" + program.getExecutableMD5());
        Environment.initProject(project);

        // Display the Processor used by Ghidra
        System.out.println("Processor used : " + program.getLanguage().getProcessor().toString());

        long startTime = System.currentTimeMillis();
        if (GhidraProgramUtilities.shouldAskToAnalyze(program)) { // if the program has not been analyzed yet...
            // Use the Ghidra headless analyzer to analyze the loaded binary file
            int txId = program.startTransaction("Analysis");
            AutoAnalysisManager mgr = AutoAnalysisManager.getAnalysisManager(program);

            mgr.initializeOptions();
            mgr.reAnalyzeAll(null);

            // The analysis will take sometime.
            System.out.println("Analyzing...");
            mgr.startAnalysis(TimeoutTaskMonitor.timeoutIn(Configs.DISASSEMBLE_TIMEOUT, TimeUnit.SECONDS));

            // Marked as analyzed
            GhidraProgramUtilities.setAnalyzedFlag(program, true);
        }
        analysisTime = System.currentTimeMillis() - startTime;
    }


    public void analyzeInputSignals() {
        Program program = Environment.getProgram();

        List<Function> results = new ArrayList<>();

        List<String> eventHandlers = new ArrayList<>();
        eventHandlers.add(Constants.DO_KEY_PRESS);
        eventHandlers.add(Constants.PROCESS_KEY_EVENT);

        for (String sig: eventHandlers) {
            List<Address> handlerAdds = FunctionUtil.locateFunctionWithSig(program, sig, false);
            for (Address handlerAdd: handlerAdds) {
                Function func = FunctionUtil.getFunctionWith(program, handlerAdd);
                Set<Function> calledFuncs = new HashSet<>();
                FunctionUtil.recursiveGetCalledFunc(func, calledFuncs);
                for (Function call: calledFuncs) {
                    if (FunctionUtil.isSignalFunction(call)) {
                        results.add(call);
                    }
                }
                System.out.println();
            }
        }

        FileUtil.writeToFile(Environment.OUTPUT_DIR + "signal", "", false);

        JSONArray output = new JSONArray();
        for (Function func: results) {
            JSONObject object = new JSONObject();
            String sig = FunctionUtil.getFunctionSignature(func);
            String className = sig.split("::")[0];
            String methodSig = sig.split("::")[1];
            String signalStr = "2" + methodSig;

            object.put("class", className);
            object.put("signal", signalStr);
            output.put(object);
        }

        FileUtil.writeToFile(Environment.OUTPUT_DIR + "signal", output.toString(4), true);

        programManager.release(program);
    }


    public void startAnalyzing() {

        // start the analysis
        // startTimeoutWatcher(Constants.TIMEOUT); // set timeout
        System.out.println("\n------------------ Starting Analysis ----------------\n");

        Program program = Environment.getProgram();

        System.out.println(program.getName());
        
        if (Configs.ANALYZE_CONNECT) {
            System.out.println("Start analyzing Qt connects...");
            solveAllConnect();
        }
        
        if (Configs.ANALYZE_META) {
            System.out.println("Start analyzing Qt metadata...");
            analyzeProperty();
        }

        // taint
        //identifyInputVarFromFunc();
        //identifyConnections();
        //startTaint();

        // Release Program
        System.out.println("\n------------------ Ending Analysis ----------------\n");
        programManager.release(program);

    }

    /**
     * Entry function to analyze class metadata by reversing the Qt metacall functions
     */
    public void analyzeProperty() {

        Program program = Environment.getProgram();

        long startTime = System.currentTimeMillis();

        JSONObject result = new JSONObject();

        List<String> classNames = new ArrayList<>();
        classNames = StringUtil.getAllClassNames(program);

        for (String cn: classNames) {
            QClassSolver classSolver = new QClassSolver(Environment.getProgram(), cn);
            classSolver.solve();

            result.put(cn, classSolver.result);
        }

        if (!result.isEmpty()) {

            long endTime = System.currentTimeMillis();
            long elapseTime = endTime - startTime;

            result.put("ClassCount", classNames.size());
            result.put("FunctionCount", program.getFunctionManager().getFunctionCount());
            result.put("Time", elapseTime);
            result.put("Size", size);

            FileUtil.writeToFile(Environment.META_DIR + Environment.tag + ".json", result.toString(4), false);
        }
    }

    /**
     * Entry function to solve Qt connect functions and resolve call relationships
     */
    public void solveAllConnect() {
        Program program = Environment.getProgram();

        long startTime = System.currentTimeMillis();

        List<Address> allConnectAdds = FunctionUtil.getConnectAddress(program);
        if (allConnectAdds.size() == 0)
            return;

        JSONObject allConnectResults = new JSONObject();

        for (Address connectAddr: allConnectAdds) {
            ReferenceIterator refs = AddressUtil.getReferenceToAddress(program, connectAddr);
            for (Reference ref : refs) {
                Address connectAdd = AddressUtil.findConnectionAddress(program, ref.getFromAddress(), allConnectAdds);
                if (connectAdd == null)
                    continue;

                QtConnectSolver solver = new QtConnectSolver(connectAdd);
                solver.setConnectAddr(connectAddr);
                solver.solve();

                if (!solver.invalid) {
                    JSONObject currentResult = new JSONObject();
                    currentResult.put("QtConnectType", solver.connectType);
                    currentResult.put("allSolved", solver.allSolved);
                    currentResult.put("signalExp", solver.signalExp);
                    currentResult.put("signalFunction", solver.signalFunction);
                    currentResult.put("slotExp", solver.slotExp);
                    currentResult.put("slotFunction", solver.slotFunction);
                    currentResult.put("signalClassType", solver.signalClassType);
                    currentResult.put("slotClassType", solver.slotClassType);
                    currentResult.put("address", connectAdd);

                    if (solver.connectType == 1) {
                        currentResult.put("signalAddress", solver.signalAddress);
                        currentResult.put("slotAddress", solver.slotAddress);
                    }
                    else if (solver.connectType == 2) {
                        currentResult.put("signalClass", solver.signalClass);
                        currentResult.put("slotClass", solver.slotClass);
                    }

                    int currentIndex = allConnectResults.keySet().size();
                    allConnectResults.put(currentIndex + "", currentResult);
                }
            }
        }

        long endTime = System.currentTimeMillis();
        long elapseTime = endTime - startTime;

        allConnectResults.put("ClassCount", StringUtil.getAllClassNames(program).size());
        allConnectResults.put("FunctionCount", program.getFunctionManager().getFunctionCount());
        allConnectResults.put("Time", elapseTime + analysisTime);
        allConnectResults.put("Size", size);

        // output result
        if (!allConnectResults.isEmpty())
            FileUtil.writeToFile(Environment.CONNECT_DIR + Environment.tag + ".json", allConnectResults.toString(4), false);
    }


    /** Below are examples of using the Taint analysis engine on PCode (not being called), feel free to tweak them for your own purposes **/

    public void identifyInputVarFromFunc() {
        Program program = Environment.getProgram();
        List<Address> funcAddrs = FunctionUtil.locateFunctionWithSig(program, Constants.SIG_QLINEEDIT_TEXT, true);

        ReferenceIterator referenceIterator = AddressUtil.getReferenceToAddress(program, funcAddrs.get(0));
        for (Reference ref: referenceIterator) {
            Address entry = ref.getFromAddress();
            // Taint return value of getText()
            QTaintEngine taintEngine = new QTaintEngine(entry, Environment.EXP_R0);
            taintEngine.taint();
            System.out.println();
        }
    }


    public void identifyConnections() {

        Program program = Environment.getProgram();
        List<Address> allConnectAdds = FunctionUtil.getConnectAddress(program);

        List<String> signals = new ArrayList<>(List.of(Constants.SIGNAL_EDITING_END, Constants.SIGNAL_KEY_EVENT, Constants.SIGNAL_RETURN_PRESSED));
        List<String> funSigs = new ArrayList<>(List.of(Constants.SIG_RETURN_PRESSED));

        for (String signal: signals) {
            List<Address> adrs = StringUtil.getRefToString(program, signal);
            for (Address adr: adrs) {
                ReferenceIterator sets = AddressUtil.getReferenceToAddress(program, adr);
                for (Reference ref: sets) {
                    Address connectAdd = AddressUtil.findConnectionAddress(program, ref.getFromAddress(), allConnectAdds);
                    if (connectAdd != null && !connectionPoints.contains(connectAdd))
                        connectionPoints.add(connectAdd);
                }
            }
        }

        for (String funSig: funSigs) {
            List<Address> funAdd = FunctionUtil.locateFunctionWithSig(program, funSig, true);
            for (Address adr: funAdd) {
                ReferenceIterator sets = AddressUtil.getReferenceToAddress(program, adr);
                for (Reference ref: sets) {
                    Address connectAdd = AddressUtil.findConnectionAddress(program, ref.getFromAddress(), allConnectAdds);
                    if (connectAdd != null && !connectionPoints.contains(connectAdd))
                        connectionPoints.add(connectAdd);
                }
            }
        }

    }

    public void startTaint() {

        Program program = Environment.getProgram();

        JSONObject result = new JSONObject();

        long startTime = System.currentTimeMillis();

        for (Address ad: connectionPoints) {

            // solve sender and receiver
            QtConnectSolver connectSolver = new QtConnectSolver(ad);
            connectSolver.solve();
            String slot = connectSolver.slotClass + "::" + connectSolver.slotFunction;


            Function slotFunc = FunctionUtil.getFunctionWithName(program, slot);

            if (slotFunc == null) {
                System.out.println("slot not found! " + slot);
                continue;
            }

            // get all descendant functions
            Set<Function> descendants = new HashSet<>();
            FunctionUtil.recursiveGetCalledFunc(slotFunc, descendants);
            descendants.add(slotFunc);


            // start to taint
            for (Function f: descendants) {

                // identify inputs
                InputExpSolver inputSolver = new InputExpSolver(connectSolver);
                inputSolver.solve();

                String taintExp = inputSolver.inputExp;

                QTaintEngine taintEngine = new QTaintEngine(f.getEntryPoint(), taintExp);
                taintEngine.taint();

                if (!taintEngine.jsonResult.isEmpty()) {
                    taintEngine.jsonResult.put("Signal", connectSolver.signalClass);
                    result.put(f.getEntryPoint().toString(), taintEngine.jsonResult);
                }
            }
        }

        long elapseTime = System.currentTimeMillis() - startTime;
        long iteratedIns = Environment.PCODE_INS_COUNT;

        result.put("Time", elapseTime);
        result.put("Ins", iteratedIns);

        FileUtil.writeToFile(Environment.OUTPUT_DIR + "result.json", result.toString(4), false);

    }

    public static void startTimeoutWatcher(int sec) {
        Thread t = new Thread() {
            public void run() {
                try {
                    Thread.sleep(sec * 1000);
                } catch (InterruptedException e) {
                    e.printStackTrace();
                }
                // Logger.printOutput("TimeOut");
                System.exit(1);
            }
        };
        t.setDaemon(true);
        t.start();
    }
}
