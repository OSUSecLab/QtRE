package Util;

import Constant.Configs;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.data.StringDataType;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.DataIterator;
import ghidra.program.model.listing.GhidraClass;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.symbol.Namespace;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.program.util.string.FoundString;
import ghidra.program.util.string.FoundStringCallback;
import ghidra.program.util.string.StringSearcher;
import ghidra.util.task.TimeoutTaskMonitor;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.concurrent.TimeUnit;

public class StringUtil {

    public static List<Address> getRefToString(Program program, String str) {
        List<Address> results = new ArrayList<>();

        DataIterator dataIterator = program.getListing().getDefinedData(true);
        while (dataIterator.hasNext()) {
            Data data = dataIterator.next();
            if (data.getDataType().toString().equals("string")) {
                if (data.toString().contains(str)) {
                    results.add(data.getAddress());
                }
            }
        }

        return results;
    }

    public static String getStringFromAddress(Program program, Address address) {

        String addrStr = NumericUtil.longToHexString(address.getUnsignedOffset());
        Data data = program.getListing().getDataAt(program.getAddressFactory().getAddress(addrStr));
        if (data == null)
            return null;

        if (data.getDataType() instanceof StringDataType) {
            return data.getValue().toString();
        }

        return data.toString();
    }

    public static List<FoundString> findStrings(Program program, AddressSetView addressSet, int minimumStringLength,
                                         int alignment, boolean requireNullTermination, boolean includeAllCharWidths) {

        final List<FoundString> list = new ArrayList<>();
        FoundStringCallback foundStringCallback = foundString -> list.add(foundString);

        StringSearcher searcher = new StringSearcher(program, minimumStringLength, alignment,
                includeAllCharWidths, requireNullTermination);

        searcher.search(addressSet, foundStringCallback, true, TimeoutTaskMonitor.timeoutIn(Configs.DISASSEMBLE_TIMEOUT, TimeUnit.SECONDS));

        return list;
    }

    public static List<String> getAllClassNames(Program program) {
        List<String> classNames = new ArrayList<>();
        SymbolTable symbolTable = program.getSymbolTable();
        Iterator<GhidraClass> igc = symbolTable.getClassNamespaces();
        while (igc.hasNext()) {
            GhidraClass c = igc.next();
            String className = c.getName();
            if (!classNames.contains(className))
                classNames.add(className);
        }

        return classNames;
    }


    public static int countCharInStr(String s, char c) {
        int cnt = 0;
        for (int i=0; i<s.length(); ++i) {
            if (s.charAt(i) == c)
                cnt++;
        }

        return cnt;
    }

    public static boolean isRegisterExp(String s) {
        if (s.contains("(register,") && countCharInStr(s, '(') == 1)
            return true;

        return false;
    }

    public static boolean isInterExp(String s) {
        if (s.contains("(unique,") && countCharInStr(s, '(') == 1)
            return true;

        return false;
    }
}
