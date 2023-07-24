package Taint;

import Util.StringUtil;
import ghidra.program.model.address.Address;
import ghidra.program.model.pcode.PcodeOp;
import ghidra.program.model.pcode.PcodeOpAST;

import java.util.ArrayList;
import java.util.List;

public class TaintPath {

    public List<PcodeOp> path;
    public List<Address> trace;

    public TaintPath() {
        path = new ArrayList<>();
        trace = new ArrayList<>();
    }

    public void addToPath(PcodeOp p) {
        path.add(p);
    }


    public boolean containsPath(PcodeOp p) {
        for (PcodeOp op: path) {
            if (p.toString().equals(op.toString()))
                return true;
        }
        return false;
    }

    public boolean pathEmpty() {
        return path.size() == 0;
    }


    @Override
    public TaintPath clone() {

        TaintPath p = new TaintPath();
        p.path = new ArrayList<>(this.path);
        return p;
    }
}
