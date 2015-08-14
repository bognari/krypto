/*
 * jCrypt - Programmierumgebung für das Kryptologie-Praktikum
 * Studienarbeit am Institut für Theoretische Informatik der
 * Technischen Universität Braunschweig
 * 
 * Datei:        IDEA.java
 * Beschreibung: Dummy-Implementierung des International Data Encryption
 *               Algorithm (IDEA)
 * Erstellt:     30. März 2010
 * Autor:        Martin Klußmann
 */

package task3;

import de.tubs.cs.iti.jcrypt.chiffre.BlockCipher;

import java.io.*;
import java.math.BigInteger;
import java.util.Scanner;

/**
 * Dummy-Klasse für den International Data Encryption Algorithm (IDEA).
 *
 * @author Martin Klußmann
 * @version 1.1 - Sat Apr 03 21:57:35 CEST 2010
 */


public final class IDEA extends BlockCipher {

    private String myKey;
    private BigInteger[][] k;
    private BigInteger[][] dk;

    private static final BigInteger MOD = BigInteger.valueOf(65536L);
    private static final BigInteger MUL_MOD = MOD.add(BigInteger.ONE);

    private static final BigInteger MAT_25BIT = BigInteger.valueOf(33554431L);
    private static final BigInteger MAT_16BIT_1 = MOD.subtract(BigInteger.ONE);
    private static final BigInteger MAT_16BIT_2 = MAT_16BIT_1.shiftLeft(16);
    private static final BigInteger MAT_16BIT_3 = MAT_16BIT_2.shiftLeft(16);
    private static final BigInteger MAT_16BIT_4 = MAT_16BIT_3.shiftLeft(16);
    private static final BigInteger MAT_16BIT_5 = MAT_16BIT_4.shiftLeft(16);
    private static final BigInteger MAT_16BIT_6 = MAT_16BIT_5.shiftLeft(16);
    private static final BigInteger MAT_16BIT_7 = MAT_16BIT_6.shiftLeft(16);
    private static final BigInteger MAT_16BIT_8 = MAT_16BIT_7.shiftLeft(16);
    private static final BigInteger MAT_64BIT = MAT_16BIT_1.or(MAT_16BIT_2.or(MAT_16BIT_3.or(MAT_16BIT_4)));
    private static final BigInteger MAT_128BIT = MAT_64BIT.or(MAT_16BIT_5.or(MAT_16BIT_6.or(MAT_16BIT_7.or(MAT_16BIT_8))));

    private static BigInteger xor(BigInteger f1, BigInteger f2) {
        assert f1.mod(MOD).equals(f1);
        assert f2.mod(MOD).equals(f2);

        return f1.xor(f2).mod(MOD);
    }

    private static BigInteger add(BigInteger f1, BigInteger f2) {
        assert f1.mod(MOD).equals(f1);
        assert f2.mod(MOD).equals(f2);

        return f1.add(f2).mod(MOD);
    }

    private static BigInteger mul(BigInteger f1, BigInteger f2) {
        assert f1.mod(MOD).equals(f1);
        assert f2.mod(MOD).equals(f2);

        return f1.multiply(f2).mod(MUL_MOD);
    }

    private static void switchMid(BigInteger[] m) {
        assert m.length == 4;

        BigInteger s = m[1];
        m[1] = m[2];
        m[2] = s;
    }

    private static void upperHalf(BigInteger[] m, BigInteger[] k) {
        assert m.length == 4;
        assert k.length == 6;

        m[0] = mul(m[0], k[0]);
        m[1] = add(m[1], k[1]);
        m[2] = add(m[2], k[2]);
        m[3] = mul(m[3], k[3]);
    }

    private static void lowerHalf(BigInteger[] m, BigInteger[] k) {
        assert m.length == 4;
        assert k.length == 6;

        BigInteger t1 = xor(m[0], m[2]);
        BigInteger t2 = xor(m[1], m[3]);

        t1 = mul(t1, k[4]);
        t2 = add(t2, t1);

        t2 = mul(t2, k[5]);
        t1 = add(t1, t2);

        m[0] = xor(m[0], t2);
        m[2] = xor(m[2], t2);
        m[1] = xor(m[1], t1);
        m[3] = xor(m[3], t1);

        switchMid(m);
    }

    private void runBlock(BigInteger[] m) {
        for (int i = 0; i < 8; i++) {
            upperHalf(m, k[i]);
            lowerHalf(m, k[i]);
        }
        switchMid(m);
        upperHalf(m, k[8]);
    }

    private BigInteger string2BigInt(String string) {
        BigInteger integer = BigInteger.ZERO;

        for (char c : string.toCharArray()) {
            assert c >= 33 && c <= 176;
            integer = integer.shiftLeft(8);
            integer = integer.add(BigInteger.valueOf(c));
        }

        return integer.and(MAT_128BIT);
    }

    private void makeEnchipherKey() {
        BigInteger[] temp = new BigInteger[56]; // 52 + 6 = 8 * 7
        BigInteger key = string2BigInt(myKey);

        for (int i = 0; i < 7; i++) {
            temp[(i * 8)] = key.and(MAT_16BIT_8).shiftRight(16 * 7).mod(MOD);
            temp[i * 8 + 1] = key.and(MAT_16BIT_7).shiftRight(16 * 6).mod(MOD);
            temp[i * 8 + 2] = key.and(MAT_16BIT_6).shiftRight(16 * 5).mod(MOD);
            temp[i * 8 + 3] = key.and(MAT_16BIT_5).shiftRight(16 * 4).mod(MOD);
            temp[i * 8 + 4] = key.and(MAT_16BIT_4).shiftRight(16 * 3).mod(MOD);
            temp[i * 8 + 5] = key.and(MAT_16BIT_3).shiftRight(16 * 2).mod(MOD);
            temp[i * 8 + 6] = key.and(MAT_16BIT_2).shiftRight(16).mod(MOD);
            temp[i * 8 + 7] = key.and(MAT_16BIT_1).mod(MOD);

            key = key.shiftLeft(25).add(key.and(MAT_25BIT)).and(MAT_128BIT);
        }

        k = new BigInteger[9][6];

        for (int r = 0; r < 9; r++) {
            System.arraycopy(temp, r * 6, k[r], 0, 6);
        }
    }

    private void makeDecipherKey() {
        dk = new BigInteger[9][6];
        dk[0][0] = k[8][0].modInverse(MUL_MOD);
        dk[0][1] = MOD.subtract(k[8][1]).mod(MOD);
        dk[0][2] = MOD.subtract(k[8][2]).mod(MOD);
        dk[0][3] = k[8][3].modInverse(MUL_MOD);
        dk[0][4] = k[7][4];
        dk[0][5] = k[7][5];

        for (int i = 1; i < 8; i++) {
            dk[i][0] = k[8-i][0].modInverse(MUL_MOD);
            dk[i][1] = MOD.subtract(k[8-i][2]).mod(MOD);
            dk[i][2] = MOD.subtract(k[8-i][1]).mod(MOD);
            dk[i][3] = k[8-i][3].modInverse(MUL_MOD);
            dk[i][4] = k[7-i][4];
            dk[i][5] = k[7-i][5];
        }

        dk[8][0] = k[0][0].modInverse(MUL_MOD);
        dk[8][1] = MOD.subtract(k[0][1]).mod(MOD);
        dk[8][2] = MOD.subtract(k[0][2]).mod(MOD);
        dk[8][3] = k[0][3].modInverse(MUL_MOD);
    }

    /**
     * Entschlüsselt den durch den FileInputStream <code>ciphertext</code>
     * gegebenen Chiffretext und schreibt den Klartext in den FileOutputStream
     * <code>cleartext</code>.
     *
     * @param ciphertext Der FileInputStream, der den Chiffretext liefert.
     * @param cleartext  Der FileOutputStream, in den der Klartext geschrieben werden soll.
     */
    public void decipher(FileInputStream ciphertext, FileOutputStream cleartext) {
        makeEnchipherKey();
        makeDecipherKey();

        k = dk;

        BigInteger clear;

        BigInteger clear_old = readCipher(ciphertext);

        while ((clear = readCipher(ciphertext)) != null) {
            System.out.println("clear = " + clear + " " + clear.bitLength());

            BigInteger[] m = new BigInteger[4];
            m[0] = clear.and(MAT_16BIT_4).shiftRight(48).and(MAT_16BIT_1);
            m[1] = clear.and(MAT_16BIT_3).shiftRight(32).and(MAT_16BIT_1);
            m[2] = clear.and(MAT_16BIT_2).shiftRight(16).and(MAT_16BIT_1);
            m[3] = clear.and(MAT_16BIT_1).and(MAT_16BIT_1);

            runBlock(m);

            BigInteger out = m[0];
            out = out.shiftLeft(16);
            out = out.add(m[1]);
            out = out.shiftLeft(16);
            out = out.add(m[2]);
            out = out.shiftLeft(16);
            out = out.add(m[3]);
            out = out.and(MAT_64BIT);

            out = out.xor(clear_old);

            clear_old = clear;

            System.out.println("out = " + out + " " + out.bitLength());

            writeClear(cleartext, out);
        }
    }

    /**
     * Verschlüsselt den durch den FileInputStream <code>cleartext</code>
     * gegebenen Klartext und schreibt den Chiffretext in den FileOutputStream
     * <code>ciphertext</code>.
     *
     * @param cleartext  Der FileInputStream, der den Klartext liefert.
     * @param ciphertext Der FileOutputStream, in den der Chiffretext geschrieben werden soll.
     */
    public void encipher(FileInputStream cleartext, FileOutputStream ciphertext) {
        makeEnchipherKey();

        BigInteger clear;
        BigInteger out_old = string2BigInt(randomString(8));

        System.out.println("out_old = " + out_old);
        System.out.println("out_old.bitLength() = " + out_old.bitLength());
        
        writeCipher(ciphertext, out_old);

        while ((clear = readClear(cleartext, 9)) != null) {

            clear = clear.xor(out_old);

            System.out.println("clear = " + clear + " " + clear.bitLength());

            BigInteger[] m = new BigInteger[4];
            m[0] = clear.and(MAT_16BIT_4).shiftRight(48).and(MAT_16BIT_1);
            m[1] = clear.and(MAT_16BIT_3).shiftRight(32).and(MAT_16BIT_1);
            m[2] = clear.and(MAT_16BIT_2).shiftRight(16).and(MAT_16BIT_1);
            m[3] = clear.and(MAT_16BIT_1);

            runBlock(m);

            BigInteger out = m[0];
            out = out.shiftLeft(16);
            out = out.add(m[1]);
            out = out.shiftLeft(16);
            out = out.add(m[2]);
            out = out.shiftLeft(16);
            out = out.add(m[3]);
            out = out.and(MAT_64BIT);

            out_old = out;

            System.out.println("out = " + out + " " + out.bitLength());
            
            writeCipher(ciphertext, out);
        }
    }

    private boolean isKeyValid(String key) {
        if (key.length() != 16) {
            return false;
        }
        for (char c : key.toCharArray()) {
            if (c < 33 || c > 176) {
                return false;
            }
        }
        return true;
    }

    private String randomString(int size) {
        StringBuilder stringBuilder = new StringBuilder(16);
        for (int i = 0; i < size; i++) {
            stringBuilder.append((char) (Math.random() * 94 + 33));
        }
        return stringBuilder.toString();
    }

    /**
     * Erzeugt einen neuen Schlüssel.
     *
     * @see #readKey readKey
     * @see #writeKey writeKey
     */
    public void makeKey() {
        System.out.println("Soll der Key automatisch generiert werden?");
        Scanner scanner = new Scanner(System.in);
        if (scanner.nextLine().equalsIgnoreCase("nein")) {
            String inputKey;
            do {
                System.out.println("Geben Sie einen 16 Zeichen langen ASCII String ein.");
                inputKey = scanner.nextLine();
            } while (!isKeyValid(inputKey));
            myKey = inputKey;
        } else {
            myKey = randomString(16);
        }

        System.out.printf("Der Key ist: \"%s\"%n", myKey);
    }

    /**
     * Liest den Schlüssel mit dem Reader <code>key</code>.
     *
     * @param key Der Reader, der aus der Schlüsseldatei liest.
     * @see #makeKey makeKey
     * @see #writeKey writeKey
     */
    public void readKey(BufferedReader key) {
        try {
            myKey = key.readLine();
            key.close();
        } catch (IOException e) {
            System.err.println("Abbruch: Fehler beim Lesen oder Schließen der "
                + "Schlüsseldatei.");
            e.printStackTrace();
            System.exit(1);
        }
        if (!isKeyValid(myKey)) {
            System.err.printf("Der Key ist: \"%s\" ist invalid %n", myKey);
        }
    }

    /**
     * Schreibt den Schlüssel mit dem Writer <code>key</code>.
     *
     * @param key Der Writer, der in die Schlüsseldatei schreibt.
     * @see #makeKey makeKey
     * @see #readKey readKey
     */
    public void writeKey(BufferedWriter key) {
        try {
            key.write(myKey);
            key.newLine();
            key.close();
        } catch (IOException e) {
            System.out.println("Abbruch: Fehler beim Schreiben oder Schließen der "
                + "Schlüsseldatei.");
            e.printStackTrace();
            System.exit(1);
        }
    }
}

