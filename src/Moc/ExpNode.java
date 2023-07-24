package Moc;

public class ExpNode extends Node {

    public String op;
    public Node left;
    public Node mid;
    public Node right;

    public ExpNode (String op, Node l, Node r) {
        this.op = op;
        isLeaf = false;
        switch (op) {
            case "LOAD":
                operandNum = 2;
                left = l;
                right = r;
                break;

            case "INT_ADD":
                operandNum = 2;
                left = l;
                right = r;
                break;

            default:
                // TODO implement others if needed
                operandNum = 2;
        }
    }


}
