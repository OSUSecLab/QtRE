package Constant;

public class Constants {

    // These configs should be overwritten by env.json
    public static String DIRECTORY_NAME;
    public static String PROJECT_NAME;

    // Signature
    public final static String SIG_CONNECT = "connect(QObject*,char*,QObject*,char*,typedefConnectionTypedword)";
    public final static String ACTIVATE = "activate(QObject*,QMetaObject*,int,void**)";
    public final static String SIG_RETURN_PRESSED = "returnPressed()";

    public final static String SIG_QLINEEDIT_TEXT = "QLineEdit::text()";
    public final static String SIG_QLINEEDIT_EDIT_FINISH = "QLineEdit::editingFinished()";
    public final static String SIG_QLINEEDIT_RETURN = "QLineEdit::returnPressed()";

    public final static String SIG_TEXTFIELD_GETTEXT = "TextField::getText(int,int)";
    public final static String SIG_TEXTFIELD_EDIT_FINISH = "TextField::editingFinished()";

    public final static String SIG_TEXTAREA_GETTEXT = "TextArea::getText(int,int)";
    public final static String SIG_TEXTAREA_EDIT_FINISH = "TextArea::editingFinished()";

    public final static String SIG_QINPUTDIALOG_GETTEXT = "QInputDialog::getText(QWidget*,QString*,QString*,typedefEchoModedword,QString*,bool*,typedefQFlagsdword)";
    public final static String SIG_QINPUTDIALOG_GETINT = "QInputDialog::getInt(QWidget*,QString*,QString*,int,int,int,int,bool*,typedefQFlagsdword)";
    public final static String SIG_QINPUTDIALOG_GETDOUBLE = "QInputDialog::getDouble(QWidget*,QString*,QString*,double,double,double,int,bool*,typedefQFlagsdword)";
    public final static String SIG_QINPUTDIALOG_GETITEM = "QInputDialog::getItem(QWidget*,QString*,QString*,QStringList*,int,bool,bool*,typedefQFlagsdword)";

    // Signals and Slots
    public final static String SIGNAL_EDITING_END = "2editingEnded(TextField*)";
    public final static String EDITING_OFFSET = "0x314";

    public final static String SIGNAL_KEY_EVENT = "2keyEvent(QKeyEvent)";
    public final static String KEY_OFFSET = "0x304";

    public final static String SIGNAL_RELEASE = "2released(ControlBase*)";

    public final static String SIGNAL_RETURN_PRESSED = "2returnPressed()";

    public final static String SIGNAL_EDIT_FINISH = "2editingFinished()";

    // Events
    public final static String PROCESS_KEY_EVENT = "processKeyEvent(QKeyEvent*)";
    public final static String DO_KEY_PRESS = "doKeyPress(QKeyEvent*)";


    public static int PCODE_R0 = 0x20;

}
