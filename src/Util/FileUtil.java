package Util;

import Constant.Constants;
import Main.Environment;
import ghidra.program.model.listing.Function;
import org.apache.commons.io.IOUtils;

import java.io.*;
import java.util.ArrayList;
import java.util.List;
import java.util.Scanner;

public class FileUtil {
    public static void writeToFile(String path, String content, boolean append) {
        try {
            PrintWriter out = new PrintWriter(new BufferedWriter(new FileWriter(path, append)));
            if (!append && content.equals("")) {
                out.print(content);
            }
            else {
                out.println(content);
            }
            out.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }


    public static void writeListToFile(String path, List<?> list, boolean append) {
        try {
            PrintWriter out = new PrintWriter(new BufferedWriter(new FileWriter(path, append)));
            for (int i=0; i<list.size(); ++i)
                out.println(list.get(i).toString());
            out.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public static boolean isResultExist(String name) {
        File file = new File(Environment.CONNECT_DIR);
        String[] files = file.list();
        if (files == null)
            return false;

        for (String fname : files) {
            if (fname.contains(name))
                return true;
        }

        file = new File(Environment.META_DIR);
        files = file.list();
        if (files == null)
            return false;

        for (String fname : files) {
            if (fname.contains(name))
                return true;
        }

        return false;
    }

    public static List<String> readListFromFile(String fileName) {
        BufferedReader reader;
        List<String> results = new ArrayList<>();
        try {
            reader = new BufferedReader(new FileReader(fileName));
            String line = reader.readLine();
            while (line != null) {
                results.add(line.replace("\n", ""));
                line = reader.readLine();
            }
            reader.close();
        }
        catch (IOException e) {
            e.printStackTrace();
        }
        return results;
    }


    public static String readFromFile(String path) throws FileNotFoundException {
        InputStream is = new FileInputStream(path);
        try {
            return IOUtils.toString(is, "UTF-8");
        } catch (IOException e) {
            e.printStackTrace();
            return null;
        }
    }


    public static File[] listFilesForFolder(String dir) {
        File folder = new File(dir);
        return folder.listFiles();
    }

    public static boolean fileContainsString(File file, String str) {
        try {
            Scanner scanner = new Scanner(file);
            while (scanner.hasNextLine()) {
                if (scanner.nextLine().contains(str)) {
                    return true;
                }
            }
            scanner.close();
        }
        catch (FileNotFoundException e) {
            e.printStackTrace();
        }

        return false;
    }

}
