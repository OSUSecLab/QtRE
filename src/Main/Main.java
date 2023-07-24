package Main;

import Constant.Configs;
import Constant.Constants;
import Util.FileUtil;
import ghidra.GhidraJarApplicationLayout;
import ghidra.base.project.GhidraProject;
import ghidra.framework.Application;
import ghidra.framework.ApplicationConfiguration;
import ghidra.framework.HeadlessGhidraApplicationConfiguration;
import ghidra.util.InvalidNameException;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.VersionException;
import org.json.JSONObject;

import java.io.*;
import java.util.ArrayList;
import java.util.List;
import java.lang.UnsupportedOperationException;

public class Main {

    private static long startTime;
    private static long endTime;

    /**
     * args[0]: path to json config file
     * args[1]: enable Qt connect analysis
     * args[2]: enable Qt meta analysis
     */
    public static void main(String[] args) throws
            IOException, VersionException, CancelledException, DuplicateNameException, InvalidNameException {
        
        if (args.length < 1) {
            System.out.println("You must provde a config json file as argument. See env.json for details.");
            return;
        }

        String configFile = args[0];

        // runtime config
        if (args.length >= 2)
            Configs.ANALYZE_CONNECT = (args[1].equals("1"));
        else
            Configs.ANALYZE_CONNECT = true; // enabled by default

        if (args.length >= 3)
            Configs.ANALYZE_META = (args[2].equals("1"));
        else
            Configs.ANALYZE_META = true; // enabled by default

        if (!loadConfig(configFile)) {
            System.out.println("Unable to load config from env.json");
            return;
        }

        // startTime = System.currentTimeMillis();

        // Define Ghidra components
        String projectDirectoryName = Constants.DIRECTORY_NAME;

        GhidraProject ghidraProject;

        // Initialize application
        if (!Application.isInitialized()) {
            ApplicationConfiguration configuration = new HeadlessGhidraApplicationConfiguration();
            configuration.setInitializeLogging(false);
            Application.initializeApplication(new GhidraJarApplicationLayout(), configuration);
        }

        // Create a Ghidra project
        String projectName = Constants.PROJECT_NAME;
        try {
            ghidraProject = GhidraProject.openProject(projectDirectoryName, projectName);
        }
        catch (IOException e) {
            // create a new project if not exist
            // throw e;
            ghidraProject = GhidraProject.createProject(projectDirectoryName, projectName, false);
        }

        List<String> programs = new ArrayList<>();
        initLanguage();


        //////////////////////////
        // init folders
        Environment.META_DIR = Environment.OUTPUT_DIR + "/Meta/";
        Environment.CONNECT_DIR = Environment.OUTPUT_DIR + "/Connect/";

        System.out.println("Output directory at: " + Environment.OUTPUT_DIR);

        File directory = new File(Environment.OUTPUT_DIR);
        if (!directory.exists()) {
            directory.mkdir();
        }
        directory = new File(Environment.META_DIR);
        if (!directory.exists()) {
            directory.mkdir();
        }
        directory = new File(Environment.CONNECT_DIR);
        if (!directory.exists()) {
            directory.mkdir();
        }

        programs = FileUtil.readListFromFile(Environment.BINARY_FILE_LIST);


        // Load and analyze binary file
        for (String p: programs) {
            String fileName = p.substring(p.lastIndexOf("/")+1);
            //if (FileUtil.isResultExist(fileName))
            //    continue; // skip finished tasks
            Analyzer analyzer = new Analyzer(ghidraProject, p);
            analyzer.startAnalyzing();
        }

        // endTime = System.currentTimeMillis();

        // Close project
        ghidraProject.setDeleteOnClose(false);
        ghidraProject.close();

    }

    public static boolean loadConfig(String f) {
        String configPath = f;
        try {
            String config = FileUtil.readFromFile(configPath);
            if (config == null)
                return false;
            JSONObject configJson = new JSONObject(config);
            // project meta configs
            Constants.DIRECTORY_NAME = configJson.getString("DIRECTORY_NAME");
            Environment.OUTPUT_DIR = configJson.getString("OUTPUT_DIR");
            Constants.PROJECT_NAME = configJson.getString("PROJECT_NAME");
            Environment.LANGUAGE_NAME = configJson.getString("LANGUAGE_NAME");
            Environment.BINARY_FILE_LIST = configJson.getString("BINARY_FILE_LIST");
            // timeout settings
            Configs.DISASSEMBLE_TIMEOUT = configJson.getInt("DISASSEMBLE_TIMEOUT");
            Configs.DECOMPILE_TIMEOUT = configJson.getInt("DECOMPILE_TIMEOUT");
            Configs.DECOMPILE_MODE = configJson.getString("DECOMPILE_MODE");
            Configs.EMULATION_TIMEOUT = configJson.getInt("EMULATION_TIMEOUT");

        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
        return true;
    }


    // Init necessary registers in PCode expressions
    public static void initLanguage() {
        if (Environment.LANGUAGE_NAME.contains("32")) {
            Environment.POINTER_SIZE = 4;
        }
        else if (Environment.LANGUAGE_NAME.contains("64")){
            Environment.POINTER_SIZE = 8;
        }
        else {
            throw new UnsupportedOperationException();
        }

        if (Environment.LANGUAGE_NAME.contains("ARM:LE:32:v8")) {
            Environment.EXP_R0 = "(register, 0x20, 4)"; // this
            Environment.EXP_R1 = "(register, 0x24, 4)";
            Environment.EXP_R2 = "(register, 0x28, 4)";
            Environment.EXP_R3 = "(register, 0x2c, 4)";
            Environment.RETURN_REG = "r0";
            Environment.COMPILER_SPEC = "default";
        }
        else if (Environment.LANGUAGE_NAME.contains("x86:LE:64")) {
            Environment.EXP_R0 = "(register, 0x38, 8)";      // this
            Environment.EXP_R1 = "(register, 0x10, 8)";     // RDX
            Environment.EXP_R2 = "(register, 0x80, 8)";     // R8
            Environment.EXP_R3 = "(register, 0x88, 8)";     // R9
            Environment.RETURN_REG = "AL";  // (register, 0x0, 8)
            Environment.COMPILER_SPEC = "gcc"; // set gcc compiler style fo x86
        }
        else if (Environment.LANGUAGE_NAME.contains("x86:LE:32")) {
            Environment.EXP_R0 = "(register, 0x0, 4)";      // RCX, this
            Environment.EXP_R1 = "(register, 0x10, 4)";     // RDX
            Environment.EXP_R2 = "(register, 0x80, 4)";     // R8
            Environment.EXP_R3 = "(register, 0x88, 4)";     // R9
            Environment.RETURN_REG = "AL";  // (register, 0x0, 8)
            Environment.COMPILER_SPEC = "gcc"; // set gcc compiler style fo x86
        }
        else {
            throw new UnsupportedOperationException();
        }
    }



}
