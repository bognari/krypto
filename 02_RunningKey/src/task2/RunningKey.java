/*
 * jCrypt - Programmierumgebung für das Kryptologie-Praktikum
 * Studienarbeit am Institut für Theoretische Informatik der
 * Technischen Universität Braunschweig
 * 
 * Datei:        RunningKey.java
 * Beschreibung: Dummy-Implementierung der Chiffre mit laufendem Schlüssel
 * Erstellt:     30. März 2010
 * Autor:        Martin Klußmann
 */

package task2;

import de.tubs.cs.iti.jcrypt.chiffre.CharacterMapping;
import de.tubs.cs.iti.jcrypt.chiffre.Cipher;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.StringTokenizer;

/**
 * Dummy-Klasse für die Chiffre mit laufendem Schlüssel.
 *
 * @author Martin Klußmann
 * @version 1.0 - Tue Mar 30 16:23:47 CEST 2010
 */
public class RunningKey extends Cipher {

  Path key;

  /**
   * Analysiert den durch den Reader <code>ciphertext</code> gegebenen
   * Chiffretext, bricht die Chiffre bzw. unterstützt das Brechen der Chiffre
   * (ggf. interaktiv) und schreibt den Klartext mit dem Writer
   * <code>cleartext</code>.
   *
   * @param ciphertext
   * Der Reader, der den Chiffretext liefert.
   * @param cleartext
   * Der Writer, der den Klartext schreiben soll.
   */
  public void breakCipher(BufferedReader ciphertext, BufferedWriter cleartext) {

  }

  /**
   * Entschlüsselt den durch den Reader <code>ciphertext</code> gegebenen
   * Chiffretext und schreibt den Klartext mit dem Writer
   * <code>cleartext</code>.
   *
   * @param ciphertext
   * Der Reader, der den Chiffretext liefert.
   * @param cleartext
   * Der Writer, der den Klartext schreiben soll.
   */
  public void decipher(BufferedReader ciphertext, BufferedWriter cleartext) {
    try {
      BufferedReader keyText = Files.newBufferedReader(key, Charset.forName(launcher.getInFileEncoding()));
      int keyChar;
      int character;
      while ((character = ciphertext.read()) != -1 && (keyChar = keyText.read()) != -1) {
        character = charMap.mapChar(character);
        keyChar = charMap.mapChar(keyChar);
        if (character != -1) {
          character = (character - keyChar + modulus) % modulus;
          character = charMap.remapChar(character);
          cleartext.write(character);
        } else {
          // Ein überlesenes Zeichen sollte bei korrekter Chiffretext-Datei
          // eigentlich nicht auftreten können.
        }
      }
      cleartext.close();
      ciphertext.close();
    } catch (IOException e) {
      System.err.println("Abbruch: Fehler beim Zugriff auf Klar- oder "
              + "Chiffretextdatei.");
      e.printStackTrace();
      System.exit(1);
    }
  }

  /**
   * Verschlüsselt den durch den Reader <code>cleartext</code> gegebenen
   * Klartext und schreibt den Chiffretext mit dem Writer
   * <code>ciphertext</code>.
   * 
   * @param cleartext
   * Der Reader, der den Klartext liefert.
   * @param ciphertext
   * Der Writer, der den Chiffretext schreiben soll.
   */
  public void encipher(BufferedReader cleartext, BufferedWriter ciphertext) {
    // An dieser Stelle könnte man alle Zeichen, die aus der Klartextdatei
    // gelesen werden, in Klein- bzw. Großbuchstaben umwandeln lassen:
    // charMap.setConvertToLowerCase();
    // charMap.setConvertToUpperCase();
    try {
      BufferedReader keyText = Files.newBufferedReader(key, Charset.forName(launcher.getInFileEncoding()));

      int keyChar;

      // 'character' ist die Integer-Repräsentation eines Zeichens.
      int character;
      // 'characterSkipped' zeigt an, daß ein aus der Klartextdatei gelesenes
      // Zeichen mit dem gewählten Alphabet nicht abgebildet werden konnte.
      boolean characterSkipped = false;
      // Lese zeichenweise aus der Klartextdatei, bis das Dateiende erreicht
      // ist. Der Buchstabe a wird z.B. als ein Wert von 97 gelesen.
      while ((character = cleartext.read()) != -1 && (keyChar = keyText.read()) != -1) {
        // Bilde 'character' auf dessen interne Darstellung ab, d.h. auf einen
        // Wert der Menge {0, 1, ..., Modulus - 1}. Ist z.B. a der erste
        // Buchstabe des Alphabets, wird die gelesene 97 auf 0 abgebildet:
        // mapChar(97) = 0.
        character = charMap.mapChar(character);
        keyChar = charMap.mapChar(keyChar);
        if (character != -1 && keyChar != -1) {
          // Das gelesene Zeichen ist im benutzten Alphabet enthalten und konnte
          // abgebildet werden. Die folgende Quellcode-Zeile stellt den Kern der
          // Caesar-Chiffrierung dar: Addiere zu (der internen Darstellung von)
          // 'character' zyklisch den 'shift' hinzu.

          character = (character + keyChar) % modulus;

          // Das nun chiffrierte Zeichen wird von der internen Darstellung in
          // die Dateikodierung konvertiert. Ist z.B. 1 das Ergebnis der
          // Verschlüsselung (also die interne Darstellung für b), so wird dies
          // konvertiert zu 98: remapChar(1) = 98. Der Wert 98 wird schließlich
          // in die Chiffretextdatei geschrieben.
          character = charMap.remapChar(character);
          ciphertext.write(character);
        } else {
          // Das gelesene Zeichen ist im benutzten Alphabet nicht enthalten.
          characterSkipped = true;
        }
      }
      if (characterSkipped) {
        System.out.println("Warnung: Mindestens ein Zeichen aus der "
                + "Klartextdatei ist im Alphabet nicht\nenthalten und wurde "
                + "überlesen.");
      }
      cleartext.close();
      ciphertext.close();
    } catch (IOException e) {
      System.err.println("Abbruch: Fehler beim Zugriff auf Klar- oder "
              + "Chiffretextdatei.");
      e.printStackTrace();
      System.exit(1);
    }
  }

  /**
   * Erzeugt einen neuen Schlüssel.
   * 
   * @see #readKey readKey
   * @see #writeKey writeKey
   */
  public void makeKey() {
    BufferedReader standardInput = launcher.openStandardInput();
    boolean accepted = false;
    String msg = "Geeignete Werte für den Modulus werden in der Klasse "
            + "'CharacterMapping'\nfestgelegt. Probieren Sie ggf. einen Modulus "
            + "von 26, 27, 30 oder 31.\nDie Verschiebung muß größer oder gleich 0 "
            + "und kleiner als der gewählte\nModulus sein.";
    System.out.println(msg);
    // Frage jeweils solange die Eingabe ab, bis diese akzeptiert werden kann.
    do {
      System.out.print("Geben Sie den Modulus ein: ");
      try {
        modulus = Integer.parseInt(standardInput.readLine());
        if (modulus < 1) {
          System.out.println("Ein Modulus < 1 wird nicht akzeptiert. Bitte "
                  + "korrigieren Sie Ihre Eingabe.");
        } else {
          // Prüfe, ob zum eingegebenen Modulus ein Default-Alphabet existiert.
          String defaultAlphabet = CharacterMapping.getDefaultAlphabet(modulus);
          if (!defaultAlphabet.equals("")) {
            msg = "Vordefiniertes Alphabet: '" + defaultAlphabet
                    + "'\nDieses vordefinierte Alphabet kann durch Angabe einer "
                    + "geeigneten Alphabet-Datei\nersetzt werden. Weitere "
                    + "Informationen finden Sie im Javadoc der Klasse\n'Character"
                    + "Mapping'.";
            System.out.println(msg);
            accepted = true;
          } else {
            msg = "Warnung: Dem eingegebenen Modulus kann kein Default-"
                    + "Alphabet zugeordnet werden.\nErstellen Sie zusätzlich zu "
                    + "dieser Schlüssel- eine passende Alphabet-Datei.\nWeitere "
                    + "Informationen finden Sie im Javadoc der Klasse 'Character"
                    + "Mapping'.";
            System.out.println(msg);
            accepted = true;
          }
        }
      } catch (NumberFormatException e) {
        System.out.println("Fehler beim Parsen des Modulus. Bitte korrigieren"
                + " Sie Ihre Eingabe.");
      } catch (IOException e) {
        System.err
                .println("Abbruch: Fehler beim Lesen von der Standardeingabe.");
        e.printStackTrace();
        System.exit(1);
      }
    } while (!accepted);
    accepted = false;
    do {
      try {
        System.out.print("Geben Sie die den Pfad zum Key ein: ");

        String key = standardInput.readLine();

        this.key = Paths.get(key);
        accepted = true;
      } catch (IOException e) {
        System.err
                .println("Abbruch: Fehler beim Lesen von der Standardeingabe.");
        e.printStackTrace();
        System.exit(1);
      }
    } while (!accepted);
  }

  /**
   * Liest den Schlüssel mit dem Reader <code>key</code>.
   * 
   * @param key
   * Der Reader, der aus der Schlüsseldatei liest.
   * @see #makeKey makeKey
   * @see #writeKey writeKey
   */
  public void readKey(BufferedReader key) {
    String path = "";
    try {
      StringTokenizer st = new StringTokenizer(key.readLine(), " ");
      modulus = Integer.parseInt(st.nextToken());
      System.out.println("Modulus: " + modulus);
      path = st.nextToken();
      this.key = Paths.get(new URI(path));
      System.out.println("Datei: " + this.key.toUri());
      key.close();
    } catch (IOException e) {
      System.err.println("Abbruch: Fehler beim Lesen oder Schließen der "
              + "Schlüsseldatei.");
      e.printStackTrace();
      System.exit(1);
    } catch (NumberFormatException e) {
      System.err.println("Abbruch: Fehler beim Parsen eines Wertes aus der "
              + "Schlüsseldatei.");
      e.printStackTrace();
      System.exit(1);
    } catch (URISyntaxException e) {
      System.err.printf("Der Pfad %s ergibt keinen Sinn.", path);
      e.printStackTrace();
    }
  }

  /**
   * Schreibt den Schlüssel mit dem Writer <code>key</code>.
   * 
   * @param key
   * Der Writer, der in die Schlüsseldatei schreibt.
   * @see #makeKey makeKey
   * @see #readKey readKey
   */
  public void writeKey(BufferedWriter key) {
    try {
      key.write(modulus + " ");

      key.write(this.key.toUri().toString());

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
