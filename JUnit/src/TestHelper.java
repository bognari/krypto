import de.tubs.cs.iti.jcrypt.chiffre.Launcher;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.util.LinkedList;
import java.util.List;

public class TestHelper {

    public static final long TEST_TIMEOUT = 1000;
    private static final InputStream in = System.in;

    private static final String TEXT_INPUT_PATH = "../text/";
    private static final String ALPHABET_PATH = "../alphabet/";

    private static final String TEST_PATH = "../test/";
    private static final String TEXT_OUTPUT_ENC_PATH = "/enc/";
    private static final String TEXT_OUTPUT_DEC_PATH = "/dec/";
    private static final String TEXT_OUTPUT_BREAK_PATH = "/break/";
    private static final String KEY_PATH = "/key/";

    public static final String[]

    public static void makeKey(String task) throws IOException {
        Launcher.main(new String[] {"-execute", task, "-action", "makekey", "-key", TEST_PATH + task + KEY_PATH + "key.txt"});
    }

    public static void encipher(String task, String text, String alphabet) throws IOException {
        Launcher.main(new String[] {"-execute", task, "-action", "encipher", "-key", TEST_PATH + task + KEY_PATH + "key.txt", "-cleartext", TEXT_INPUT_PATH + text, "-ciphertext", TEST_PATH + task + TEXT_OUTPUT_ENC_PATH + text, "-alphabet", ALPHABET_PATH + alphabet});
    }

    public static void decipher(String task, String text, String alphabet) throws IOException {
        Launcher.main(new String[] {"-execute", task, "-action", "decipher", "-key", TEST_PATH + task + KEY_PATH + "key.txt", "-cleartext", TEST_PATH + task + TEXT_OUTPUT_DEC_PATH + text, "-ciphertext", TEST_PATH + task + TEXT_OUTPUT_ENC_PATH + text, "-alphabet", ALPHABET_PATH + alphabet});
    }

    public static void breakChipher(String task, String text, String alphabet) throws IOException {
        Launcher.main(new String[] {"-execute", task, "-action", "break", "-key", TEST_PATH + task + KEY_PATH + "key_break.txt", "-cleartext", TEST_PATH + task + TEXT_OUTPUT_BREAK_PATH + text, "-ciphertext", TEXT_INPUT_PATH + text, "-ciphertext", TEST_PATH + task + TEXT_OUTPUT_ENC_PATH + text, "-alphabet", ALPHABET_PATH + alphabet});
    }

    public static void sign(String task, String text) throws IOException {
        Launcher.main(new String[] {"-execute", task, "-action", "sign", "-key", TEST_PATH + task + KEY_PATH + "key.txt", "-cleartext", TEXT_INPUT_PATH + text, "-ciphertext", TEST_PATH + task + TEXT_OUTPUT_ENC_PATH + text});
    }

    public static void verify(String task, String text) throws IOException {
        Launcher.main(new String[] {"-execute", task, "-action", "verify", "-key", TEST_PATH + task + KEY_PATH + "key.txt", "-cleartext", TEST_PATH + task + TEXT_OUTPUT_DEC_PATH + text, "-ciphertext", TEST_PATH + task + TEXT_OUTPUT_ENC_PATH + text});
    }

    public static void makeparam(String task) throws IOException {
        Launcher.main(new String[] {"-execute", task, "-action", "makeparam", "-param", TEST_PATH + task + KEY_PATH + "param.txt"});
    }

    public static void hash(String task, String text) throws IOException {
        Launcher.main(new String[] {"-execute", task, "-action", "hash", "-param", TEST_PATH + task + KEY_PATH + "param.txt", "-cleartext", TEXT_INPUT_PATH + text, "-ciphertext", TEST_PATH + task + TEXT_OUTPUT_ENC_PATH + text});
    }

    public static void verify_hash(String task, String text) throws IOException {
        Launcher.main(new String[] {"-execute", task, "-action", "verify", "-param", TEST_PATH + task + KEY_PATH + "param.txt", "-cleartext", TEST_PATH + task + TEXT_OUTPUT_DEC_PATH + text, "-ciphertext", TEST_PATH + task + TEXT_OUTPUT_ENC_PATH + text});
    }

    public static void emulateInput(String input) {
        System.setIn(new ByteArrayInputStream(input.getBytes()));
    }

    public static void restoreInput() {
        System.setIn(in);
    }

    public List<String> getInputTextFiles() {
        List<String> list = new LinkedList<>();
        File folder = new File(TEXT_INPUT_PATH);
        for (File file : folder.listFiles()) {
            if (file.isFile() && file.getName().endsWith(".txt")) {
                list.add(file.getName());
            }
        }
        return list;
    }
}
