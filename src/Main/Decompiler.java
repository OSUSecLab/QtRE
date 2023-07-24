package Main;

import Constant.Configs;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileException;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TimeoutTaskMonitor;

import java.util.concurrent.TimeUnit;

public class Decompiler {

    private static DecompInterface ifc;

    private static void initIfc () {
        if (ifc == null) {
            DecompileOptions options = new DecompileOptions();
            ifc = new DecompInterface();
            ifc.setOptions(options);
        }
    }

    private static DecompileResults decompile(Program program, String decompileMode, Function function) {

        initIfc(); // init decompile interface

        if ( !ifc.openProgram(program)) {
            // fail to open program
            return null;
        }
        ifc.setSimplificationStyle(decompileMode);
        DecompileResults res = ifc.decompileFunction(function, Configs.DECOMPILE_TIMEOUT, TimeoutTaskMonitor.timeoutIn(Configs.DECOMPILE_TIMEOUT, TimeUnit.SECONDS));
        if (res == null || !res.decompileCompleted()) {
            ifc.closeProgram();
            return null; // decompile failed
        }
        else {
            ifc.closeProgram();
            return res;
        }
    }


    public static DecompileResults decompileFunc(Program program, Function function) {
        return decompile(program, Configs.DECOMPILE_MODE, function);
    }

    // for solving function call params
    public static DecompileResults decompileFuncNormalize(Program program, Function function) {
        return decompile(program, "normalize", function);
    }


    public static DecompileResults decompileFuncRegister(Program program, Function function) {
        return decompile(program, "register", function);
    }
}
