package Util;

import Main.Environment;
import ghidra.util.BigEndianDataConverter;
import ghidra.util.LittleEndianDataConverter;

import java.nio.ByteBuffer;
import java.util.*;
import java.lang.UnsupportedOperationException;

public class NumericUtil {

    public static String longToHexString(long val) {return String.format("0x%X", val); }

    public static long byteToLongLittleEndian(byte[] data) {
        if (Environment.LANGUAGE_NAME.contains("LE") && data.length == 4) {
            long b0 = ((long) data[0]) & 0xFF;
            long b1 = ((long) data[1] & 0xFF) << 8;
            long b2 = ((long) data[2] & 0xFF) << 16;
            long b3 = ((long) data[3] & 0xFF) << 24;
            long res = b0 + b1 + b2 + b3;
            return res;
        }
        else if (Environment.LANGUAGE_NAME.contains("LE") && data.length == 8){
            long b0 = ((long) data[0]) & 0xFF;
            long b1 = ((long) data[1] & 0xFF) << 8;
            long b2 = ((long) data[2] & 0xFF) << 16;
            long b3 = ((long) data[3] & 0xFF) << 24;
            long b4 = ((long) data[4] & 0xFF) << 32;
            long b5 = ((long) data[5] & 0xFF) << 40;
            long b6 = ((long) data[6] & 0xFF) << 44;
            long b7 = ((long) data[7] & 0xFF) << 48;
            return b0 + b1 + b2 + b3 + b4 + b5 + b6 + b7;
        }
        else
            throw new UnsupportedOperationException();
    }

    public static byte[] intToBytes(int x, boolean littleEndian) {
        if (littleEndian) {
            LittleEndianDataConverter converter = new LittleEndianDataConverter();
            return converter.getBytes(x);
        }
        else {
            BigEndianDataConverter converter = new BigEndianDataConverter();
            return converter.getBytes(x);
        }
    }

    public static HashMap sortByValues(HashMap map, boolean descendant) {
        List list = new LinkedList(map.entrySet());
        // Defined Custom Comparator here
        if (descendant) {
            Collections.sort(list, new Comparator() {
                public int compare(Object o1, Object o2) {
                    return ((Comparable) ((Map.Entry) (o2)).getValue())
                            .compareTo(((Map.Entry) (o1)).getValue());
                }
            });
        }
        else {
            Collections.sort(list, new Comparator() {
                public int compare(Object o1, Object o2) {
                    return ((Comparable) ((Map.Entry) (o1)).getValue())
                            .compareTo(((Map.Entry) (o2)).getValue());
                }
            });
        }

        // Here I am copying the sorted list in HashMap
        // using LinkedHashMap to preserve the insertion order
        HashMap sortedHashMap = new LinkedHashMap();
        for (Iterator it = list.iterator(); it.hasNext();) {
            Map.Entry entry = (Map.Entry) it.next();
            sortedHashMap.put(entry.getKey(), entry.getValue());
        }
        return sortedHashMap;
    }

}
