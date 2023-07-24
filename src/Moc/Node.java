package Moc;

public abstract class Node {

    int operandNum;
    boolean isLeaf;

    enum TYPE {
        REGISTER, CONST
    }


    public static String evaluate(Node node) throws StackOverflowError{
        if (node.isLeaf)
            return ((LeafNode) node).value;
        else {
            String leftExp = evaluate(((ExpNode) node).left);
            String rightExp = evaluate(((ExpNode) node).right);
            String op = ((ExpNode) node).op;
            return String.format("%s %s %s", op, leftExp, rightExp);
        }
    }
}

