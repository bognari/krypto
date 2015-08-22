/*
 * jCrypt - Programmierumgebung für das Kryptologie-Praktikum
 * Studienarbeit am Institut für Theoretische Informatik der
 * Technischen Universität Braunschweig
 * 
 * Datei:        Fingerprint.java
 * Beschreibung: Dummy-Implementierung der Hash-Funktion von Chaum, van Heijst
 *               und Pfitzmann
 * Erstellt:     30. März 2010
 * Autor:        Martin Klußmann
 */

package task5;

import de.tubs.cs.iti.jcrypt.chiffre.BigIntegerUtil;
import de.tubs.cs.iti.jcrypt.chiffre.HashFunction;

import java.io.*;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Objects;
import java.util.Random;
import java.util.Scanner;

/**
 * Dummy-Klasse für die Hash-Funktion von Chaum, van Heijst und Pfitzmann.
 *
 * @author Martin Klußmann
 * @version 1.1 - Sat Apr 03 22:20:18 CEST 2010
 */
public final class Fingerprint extends HashFunction {

    private BigInteger prime;
    private BigInteger q;
    private BigInteger g1;
    private BigInteger g2;

    private void genSafePrime() {
        Random random = new SecureRandom();
        do {
            prime = BigInteger.probablePrime(512, random);
            q = prime.subtract(BigInteger.ONE).divide(BigInteger.valueOf(2L));
        } while (!q.isProbablePrime(42));

        assert Objects.equals(q.multiply(BigInteger.valueOf(2L)).add(BigInteger.ONE), prime);
    }

    private BigInteger genG() {
        BigInteger g;
        do {
            g = BigIntegerUtil.randomBetween(BigInteger.valueOf(2L), prime.subtract(BigInteger.ONE));
        } while (!Objects.equals(g.modPow(q, prime), prime.subtract(BigInteger.ONE)));

        assert Objects.equals(g.modPow(q, prime), prime.subtract(BigInteger.ONE));

        return g;
    }

    private BigInteger cphash(BigInteger x1, BigInteger x2) {
        assert prime.compareTo(x1) > 0;
        assert prime.compareTo(x2) > 0;
        return g1.modPow(x1, prime).multiply(g2.modPow(x2, prime)).mod(prime);
    }

    public BigInteger hash(BigInteger x1, BigInteger x2) {
        if(x1.compareTo(q) >= 0) {
            int bl = x1.bitLength();
            x1 = hash(x1.xor(x1.shiftRight(bl / 2).shiftLeft(bl / 2)), x1.shiftRight(bl / 2));
        }
        if(x2.compareTo(q) >= 0) {
            int bl = x2.bitLength();
            x2 = hash(x2.xor(x2.shiftRight(bl / 2).shiftLeft(bl / 2)), x2.shiftRight(bl / 2));
        }

        return cphash(x1, x2);
    }

    /**
     * Berechnet den Hash-Wert des durch den FileInputStream <code>cleartext</code> gegebenen Klartextes und schreibt
     * das Ergebnis in den FileOutputStream <code>ciphertext</code>.
     *
     * @param cleartext  Der FileInputStream, der den Klartext liefert.
     * @param ciphertext Der FileOutputStream, in den der Hash-Wert geschrieben werden soll.
     */
    public void hash(FileInputStream cleartext, FileOutputStream ciphertext) {
        Scanner scanner = new Scanner(cleartext);
        scanner.useDelimiter("\\Z");
        String clear = scanner.next();

        BigInteger text = new BigInteger(clear.getBytes());


        BigInteger cipher = hash(text);

        try {
            ciphertext.write(cipher.toString(16).getBytes());
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public BigInteger hash(BigInteger m) {
        int size = m.bitLength();
        return  hash(m.xor(m.shiftRight(size / 2).shiftLeft(size / 2)), m.shiftRight(size / 2));
    }

    /**
     * Erzeugt neue Parameter.
     *
     * @see #readParam readParam
     * @see #writeParam writeParam
     */
    public void makeParam() {
        genSafePrime();
        assert prime.isProbablePrime(42);
        g1 = genG();
        assert Objects.equals(g1.modPow(q, prime), prime.subtract(BigInteger.ONE));
        do {
            g2 = genG();
        } while (Objects.equals(g1, g2));
        assert Objects.equals(g2.modPow(q, prime), prime.subtract(BigInteger.ONE));
        assert !Objects.equals(g1, g2);
    }

    /**
     * Liest die Parameter mit dem Reader <code>param</code>.
     *
     * @param param Der Reader, der aus der Parameterdatei liest.
     *
     * @see #makeParam makeParam
     * @see #writeParam writeParam
     */
    public void readParam(BufferedReader param) {
        try {
            prime = new BigInteger(param.readLine());
            assert prime.isProbablePrime(42);
            q = prime.subtract(BigInteger.ONE).divide(BigInteger.valueOf(2L));
            g1 = new BigInteger(param.readLine());
            assert Objects.equals(g1.modPow(q, prime), prime.subtract(BigInteger.ONE));
            g2 = new BigInteger(param.readLine());
            assert Objects.equals(g2.modPow(q, prime), prime.subtract(BigInteger.ONE));
            assert !Objects.equals(g1, g2);
            param.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    /**
     * Berechnet den Hash-Wert des durch den FileInputStream <code>cleartext</code> gegebenen Klartextes und vergleicht
     * das Ergebnis mit dem durch den FileInputStream <code>ciphertext</code> gelieferten Wert.
     *
     * @param ciphertext Der FileInputStream, der den zu prüfenden Hash-Wert liefert.
     * @param cleartext  Der FileInputStream, der den Klartext liefert, dessen Hash-Wert berechnet werden soll.
     */
    public void verify(FileInputStream ciphertext, FileInputStream cleartext) {
        Scanner scanner = new Scanner(cleartext);
        scanner.useDelimiter("\\Z");
        String clear = scanner.next();

        scanner = new Scanner(ciphertext);
        scanner.useDelimiter("\\Z");
        String cipher = scanner.next();

        BigInteger text = new BigInteger(clear.getBytes());

        int bl = text.bitLength();
        BigInteger hash = hash(text.xor(text.shiftRight(bl / 2).shiftLeft(bl / 2)), text.shiftRight(bl / 2));

        if (Objects.equals(cipher, hash.toString(16))) {
            System.out.println("hash is correct");
        } else {
            System.out.println("hash is incorrect");
        }
    }

    /**
     * Schreibt die Parameter mit dem Writer <code>param</code>.
     *
     * @param param Der Writer, der in die Parameterdatei schreibt.
     *
     * @see #makeParam makeParam
     * @see #readParam readParam
     */
    public void writeParam(BufferedWriter param) {
        try {
            param.write(prime.toString());
            param.newLine();
            param.write(g1.toString());
            param.newLine();
            param.write(g2.toString());
            param.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
