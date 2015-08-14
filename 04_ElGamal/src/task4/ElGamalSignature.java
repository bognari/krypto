/*
 * jCrypt - Programmierumgebung für das Kryptologie-Praktikum
 * Studienarbeit am Institut für Theoretische Informatik der
 * Technischen Universität Braunschweig
 * 
 * Datei:        ElGamalSignature.java
 * Beschreibung: Dummy-Implementierung des ElGamal-Public-Key-Signaturverfahrens
 * Erstellt:     30. März 2010
 * Autor:        Martin Klußmann
 */

package task4;

import de.tubs.cs.iti.jcrypt.chiffre.BigIntegerUtil;
import de.tubs.cs.iti.jcrypt.chiffre.Signature;

import java.io.*;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.SecureRandom;
import java.util.Objects;
import java.util.Random;

/**
 * Dummy-Klasse für das ElGamal-Public-Key-Signaturverfahren.
 *
 * @author Martin Klußmann
 * @version 1.1 - Sat Apr 03 22:14:47 CEST 2010
 */
public final class ElGamalSignature extends Signature {

    private BigInteger prime = BigInteger.ZERO;
    private BigInteger g = BigInteger.ZERO;
    private BigInteger y = BigInteger.ZERO;
    private BigInteger privateKey = BigInteger.ZERO;

    private BigInteger signBlock(BigInteger clear) {
        BigInteger k;
        do {
          k = BigIntegerUtil.randomBetween(BigInteger.valueOf(2L), prime.subtract(BigInteger.valueOf(2L)));
        } while (!Objects.equals(k.gcd(prime.subtract(BigInteger.ONE)), BigInteger.ONE));
        BigInteger kInv = k.modInverse(prime.subtract(BigInteger.ONE));
        BigInteger r = g.modPow(k, prime);

        BigInteger s = clear.subtract(privateKey.multiply(r)).multiply(kInv).mod(prime.subtract(BigInteger.ONE));

        return r.add(s.multiply(prime));
    }

    private boolean verifyBlock(BigInteger clear, BigInteger cipher) {
        BigInteger r = cipher.mod(prime);
        BigInteger s = cipher.divide(prime);

        if (BigInteger.ONE.compareTo(r) <= 0 && r.compareTo(prime.subtract(BigInteger.ONE)) <= 0) {

            BigInteger v1 = y.modPow(r, prime).multiply(r.modPow(s, prime)).mod(prime);
            BigInteger v2 = g.modPow(clear, prime);
            return Objects.equals(v1, v2);
        }

        return false;
    }

    private int genL() {
        return Math.min((int) Math.floor((prime.bitLength() - 1) / 8.0), 255);
    }

    private void genG(BigInteger q) {
        do {
            g = BigIntegerUtil.randomBetween(BigInteger.valueOf(2L), prime.subtract(BigInteger.ONE));
        } while (!Objects.equals(g.modPow(q, prime), prime.subtract(BigInteger.ONE)));
    }

    /**
     * Erzeugt einen neuen Schlüssel.
     *
     * @see #readKey readKey
     * @see #writeKey writeKey
     */
    public void makeKey() {
        Random random = new SecureRandom();
        do {
            prime = BigInteger.probablePrime(512, random);
        } while (prime.subtract(BigInteger.ONE).testBit(0)); // form: 2*q+1
        assert prime.isProbablePrime(42 * 42 * 42);
        BigInteger q = prime.subtract(BigInteger.ONE).divide(BigInteger.valueOf(2L));
        assert Objects.equals(prime, q.multiply(BigInteger.valueOf(2L)).add(BigInteger.ONE));
        genG(q);
        assert Objects.equals(g.modPow(q, prime), prime.subtract(BigInteger.ONE));
        privateKey = BigIntegerUtil.randomBetween(BigInteger.valueOf(2L), prime.subtract(BigInteger.valueOf(2L)));
        y = g.modPow(privateKey, prime);
        assert Objects.equals(y, g.modPow(privateKey, prime));
    }

    /**
     * Liest den Schlüssel mit dem Reader <code>key</code>.
     *
     * @param key Der Reader, der aus der Schlüsseldatei liest.
     *
     * @see #makeKey makeKey
     * @see #writeKey writeKey
     */
    public void readKey(BufferedReader key) {
        try {
            String in_public = key.readLine();
            try (BufferedReader in = Files.newBufferedReader(Paths.get(in_public))) {
                prime = new BigInteger(in.readLine());
                g = new BigInteger(in.readLine());
                y = new BigInteger(in.readLine());
            }

            String in_private = key.readLine();
            try (BufferedReader inReaderPrivate = Files.newBufferedReader(Paths.get(in_private))) {
                privateKey = new BigInteger(inReaderPrivate.readLine());
            }

            assert prime.isProbablePrime(42 * 42 * 42);
            BigInteger q = prime.subtract(BigInteger.ONE).divide(BigInteger.valueOf(2L));

            assert Objects.equals(prime, q.multiply(BigInteger.valueOf(2L)).add(BigInteger.ONE));
            assert Objects.equals(g.modPow(q, prime), prime.subtract(BigInteger.ONE));
            assert Objects.equals(y, g.modPow(privateKey, prime));

            key.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    /**
     * Signiert den durch den FileInputStream <code>cleartext</code> gegebenen Klartext und schreibt die Signatur in den
     * FileOutputStream <code>ciphertext</code>. <p>Das blockweise Lesen des Klartextes soll mit der Methode {@link
     * #readClear readClear} durchgeführt werden, das blockweise Schreiben der Signatur mit der Methode {@link
     * #writeCipher writeCipher}.</p>
     *
     * @param cleartext  Der FileInputStream, der den Klartext liefert.
     * @param ciphertext Der FileOutputStream, in den die Signatur geschrieben werden soll.
     */
    public void sign(FileInputStream cleartext, FileOutputStream ciphertext) {
        int l = genL();

        BigInteger clear;
        while ((clear = readClear(cleartext, l)) != null) {
            BigInteger sign = signBlock(clear);
            writeCipher(ciphertext, sign);
            assert verifyBlock(clear, sign);
        }
    }

    /**
     * Überprüft die durch den FileInputStream <code>ciphertext</code> gegebene Signatur auf den vom FileInputStream
     * <code>cleartext</code> gelieferten Klartext. <p>Das blockweise Lesen der Signatur soll mit der Methode {@link
     * #readCipher readCipher} durchgeführt werden, das blockweise Lesen des Klartextes mit der Methode {@link
     * #readClear readClear}.</p>
     *
     * @param ciphertext Der FileInputStream, der die zu prüfende Signatur liefert.
     * @param cleartext  Der FileInputStream, der den Klartext liefert, auf den die Signatur überprüft werden soll.
     */
    public void verify(FileInputStream ciphertext, FileInputStream cleartext) {
        int l = genL();

        BigInteger clear;
        BigInteger chipher;
        while ((clear = readClear(cleartext, l)) != null && (chipher = readCipher(ciphertext)) != null) {
            System.out.println(clear);
            if (!verifyBlock(clear, chipher)) {
                System.out.println("incorrect signature");
                return;
            }
        }
        /*if (clear != null || chipher != null) {
            System.out.println("incorrect signature");
            return;
        }*/
        System.out.println("correct signature");
    }

    /**
     * Schreibt den Schlüssel mit dem Writer <code>key</code>.
     *
     * @param key Der Writer, der in die Schlüsseldatei schreibt.
     *
     * @see #makeKey makeKey
     * @see #readKey readKey
     */
    public void writeKey(BufferedWriter key) {
        String out_public = String.format("%s.sig.secr.public", System.getProperty("user.name"));
        String out_private = String.format("%s.sig.secr.private", System.getProperty("user.name"));

        try {
            try (BufferedWriter out = Files.newBufferedWriter(Paths.get("schluessel", out_public))) {
                out.write(prime.toString());
                out.newLine();
                out.write(g.toString());
                out.newLine();
                out.write(y.toString());
            }

            try (BufferedWriter out = Files.newBufferedWriter(Paths.get("schluessel", out_private))) {
                out.write(privateKey.toString());
            }

            key.write(String.format("schluessel/%s", out_public));
            key.newLine();
            key.write(String.format("schluessel/%s", out_private));
            key.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
