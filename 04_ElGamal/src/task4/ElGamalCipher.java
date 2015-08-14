/*
 * jCrypt - Programmierumgebung für das Kryptologie-Praktikum
 * Studienarbeit am Institut für Theoretische Informatik der
 * Technischen Universität Braunschweig
 * 
 * Datei:        ElGamalCipher.java
 * Beschreibung: Dummy-Implementierung der ElGamal-Public-Key-Verschlüsselung
 * Erstellt:     30. März 2010
 * Autor:        Martin Klußmann
 */

package task4;

import de.tubs.cs.iti.jcrypt.chiffre.BigIntegerUtil;
import de.tubs.cs.iti.jcrypt.chiffre.BlockCipher;

import java.io.*;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.SecureRandom;
import java.util.Objects;
import java.util.Random;

/**
 * Dummy-Klasse für das ElGamal-Public-Key-Verschlüsselungsverfahren.
 *
 * @author Martin Klußmann
 * @version 1.1 - Sat Apr 03 22:06:35 CEST 2010
 */
public final class ElGamalCipher extends BlockCipher {

    private BigInteger prime = BigInteger.ZERO;
    private BigInteger g = BigInteger.ZERO;
    private BigInteger y = BigInteger.ZERO;
    private BigInteger privateKey = BigInteger.ZERO;

    /**
     * Entschlüsselt den durch den FileInputStream <code>ciphertext</code> gegebenen Chiffretext und schreibt den
     * Klartext in den FileOutputStream <code>cleartext</code>. <p>Das blockweise Lesen des Chiffretextes soll mit der
     * Methode {@link #readCipher readCipher} durchgeführt werden, das blockweise Schreiben des Klartextes mit der
     * Methode {@link #writeClear writeClear}.</p>
     *
     * @param ciphertext Der FileInputStream, der den Chiffretext liefert.
     * @param cleartext  Der FileOutputStream, in den der Klartext geschrieben werden soll.
     */
    public void decipher(FileInputStream ciphertext, FileOutputStream cleartext) {
        BigInteger chipher;

        while ((chipher = readCipher(ciphertext)) != null) {
            writeClear(cleartext, dec(chipher));
        }

        System.out.println("finish");
    }

    /**
     * Verschlüsselt den durch den FileInputStream <code>cleartext</code> gegebenen Klartext und schreibt den
     * Chiffretext in den FileOutputStream <code>ciphertext</code>. <p>Das blockweise Lesen des Klartextes soll mit der
     * Methode {@link #readClear readClear} durchgeführt werden, das blockweise Schreiben des Chiffretextes mit der
     * Methode {@link #writeCipher writeCipher}.</p>
     *
     * @param cleartext  Der FileInputStream, der den Klartext liefert.
     * @param ciphertext Der FileOutputStream, in den der Chiffretext geschrieben werden soll.
     */
    public void encipher(FileInputStream cleartext, FileOutputStream ciphertext) {
        int l = genL();

        BigInteger clear;

        System.out.println("l = " + l);

        while ((clear = readClear(cleartext, l + 1)) != null) {
            BigInteger enc = enc(clear);
            BigInteger dec = dec(enc);
            //System.out.println("clear = " + clear);
            //System.out.println("clear.bitLength() = " + clear.bitLength());
            //System.out.println("enc(clear) = " + enc);
            //System.out.println("enc(clear).bitLength() = " + enc.bitLength());
            //System.out.println("dec(enc(clear)) = " + dec);
            //System.out.println("dec(enc(clear)).bitLength() = " + dec.bitLength());
            writeCipher(ciphertext, enc(clear));
            try {
                assert Objects.equals(clear, dec); //  geht nur wenn beide die selbe configuration nehmen
            } catch (AssertionError e) {
                System.out.println("clear = " + clear);
                System.out.println("dec = " + dec);
                System.out.println("enc = " + enc);
            }
        }

        System.out.println("finish");
    }

    private BigInteger enc(BigInteger clear) {
        BigInteger k = BigIntegerUtil.randomBetween(BigInteger.valueOf(2L), prime.subtract(BigInteger.valueOf(2L)));

        BigInteger a = g.modPow(k, prime);
        BigInteger b = clear.multiply(y.modPow(k, prime)).mod(prime);

        return a.add(b.multiply(prime));
    }

    private BigInteger dec(BigInteger cipher) {
        BigInteger a = cipher.mod(prime);
        BigInteger b = cipher.divide(prime);

        BigInteger exp = prime.subtract(BigInteger.ONE).subtract(privateKey);

        BigInteger z = a.modPow(exp, prime);

        return z.multiply(b).mod(prime);
    }

    private int genL() {
        return Math.min((int)Math.floor((prime.bitLength() - 1) / 8.0), 255);
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

        assert prime.isProbablePrime(42*42*42);

        //System.out.println("prime = " + prime);
        //System.out.println("prime.bitLength() = " + prime.bitLength());

        BigInteger q = prime.subtract(BigInteger.ONE).divide(BigInteger.valueOf(2L));

        assert Objects.equals(prime, q.multiply(BigInteger.valueOf(2L)).add(BigInteger.ONE));

        //System.out.println("q = " + q);
        //System.out.println("q.bitLength() = " + q.bitLength());

        genG(q);

        assert Objects.equals(g.modPow(q, prime), prime.subtract(BigInteger.ONE));

        //System.out.println("g = " + g);
        //System.out.println("g.bitLength() = " + g.bitLength());

        privateKey = BigIntegerUtil.randomBetween(BigInteger.valueOf(2L), prime.subtract(BigInteger.valueOf(2L)));

        //System.out.println("privateKey = " + privateKey);
        //System.out.println("privateKey.bitLength() = " + privateKey.bitLength());

        y = g.modPow(privateKey, prime);

        assert Objects.equals(y, g.modPow(privateKey, prime));

        //System.out.println("y = " + y);
        //System.out.println("y.bitLength() = " + y.bitLength());

        //System.out.println("Dummy für die Schlüsselerzeugung.");
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

            assert prime.isProbablePrime(42*42*42);
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
     * Schreibt den Schlüssel mit dem Writer <code>key</code>.
     *
     * @param key Der Writer, der in die Schlüsseldatei schreibt.
     *
     * @see #makeKey makeKey
     * @see #readKey readKey
     */
    public void writeKey(BufferedWriter key) {
        String out_public = String.format("%s.secr.public", System.getProperty("user.name"));
        String out_private = String.format("%s.secr.private", System.getProperty("user.name"));

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
