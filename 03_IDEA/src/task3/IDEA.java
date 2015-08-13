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
import java.util.Scanner;

/**
 * Dummy-Klasse für den International Data Encryption Algorithm (IDEA).
 *
 * @author Martin Klußmann
 * @version 1.1 - Sat Apr 03 21:57:35 CEST 2010
 */



//TODO: dechiper machen (siehe dechiper_TODO

    //TODO CBD sollte einfach gehen


public final class IDEA extends BlockCipher {

    private String myKey;

    /**
     * Entschlüsselt den durch den FileInputStream <code>ciphertext</code>
     * gegebenen Chiffretext und schreibt den Klartext in den FileOutputStream
     * <code>cleartext</code>.
     *
     * @param ciphertext Der FileInputStream, der den Chiffretext liefert.
     * @param cleartext  Der FileOutputStream, in den der Klartext geschrieben werden soll.
     */
    public void decipher(FileInputStream ciphertext, FileOutputStream cleartext) {
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
            String inputKey = "";
            do {
                System.out.println("Geben Sie einen 16 Zeichen langen ASCII String ein.");
                inputKey = scanner.nextLine();
            } while (!isKeyValid(inputKey));
            myKey = inputKey;
        } else {
            StringBuilder stringBuilder = new StringBuilder(16);
            for (int i = 0; i < 16; i++) {
                stringBuilder.append((char) (Math.random() * 94 + 33));
            }
            myKey = stringBuilder.toString();
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

