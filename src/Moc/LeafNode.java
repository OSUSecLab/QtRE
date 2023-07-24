package Moc;

public class LeafNode extends Node {

    public String value;
    public TYPE type;

    public LeafNode(String val) {
        operandNum = 1;
        isLeaf = true;
        value = val;

        if (val.contains("register"))
            type = TYPE.REGISTER;
        else if (val.contains("const"))
            type = TYPE.CONST;
    }
}