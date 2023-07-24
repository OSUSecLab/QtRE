package Main;

import ghidra.base.project.GhidraProject;
import ghidra.program.model.listing.Program;

// Global environment to store program information
public class Environment {

    public static Program program;

    public static String tag;

    public static GhidraProject project;

    public static String LANGUAGE_NAME; // https://github.com/NationalSecurityAgency/ghidra/blob/master/Ghidra/Processors

    // For ARM binaries, use default compiler spec
    // For x86 binaries, use gcc compiler spec
    public static String COMPILER_SPEC; // https://ghidra.re/ghidra_docs/api/ghidra/program/model/lang/CompilerSpecID.html

    public static String BINARY_FILE_LIST;

    public static int POINTER_SIZE;

    // File location
    public static String OUTPUT_DIR;
    public static String META_DIR;
    public static String CONNECT_DIR;

    // registers
    public static String EXP_R0 = "(register, 0x20, 4)";
    public static String EXP_R1 = "(register, 0x24, 4)";
    public static String EXP_R2 = "(register, 0x28, 4)";
    public static String EXP_R3 = "(register, 0x2c, 4)";
    public static String EXP_R4 = "(stack, 0x0, 4)";
    public static String EXP_R5 = "(stack, 0x4, 4)";

    public static String RETURN_REG = "r0";


    // global stats
    public static int PCODE_INS_COUNT = 0;


    // initProgram must be called before analysis!!
    public static void initProgram(Program p) {
        program = p;
    }

    public static void initTag(String s) {
        tag = s;
    }

    public static void initProject(GhidraProject p) {
        project = p;
    }

    public static Program getProgram() {
        return program;
    }

    public static String getTag() {
        return tag;
    }

    public static GhidraProject getProject() {
        return project;
    }
}
