/*
 * jCrypt - Programmierumgebung für das Kryptologie-Praktikum
 * Studienarbeit am Institut für Theoretische Informatik der
 * Technischen Universität Braunschweig
 * 
 * Datei:        Vigenere.java
 * Beschreibung: Dummy-Implementierung der Vigenère-Chiffre
 * Erstellt:     30. März 2010
 * Autor:        Martin Klußmann
 */

package task1;

import java.io.*;
import java.math.BigInteger;
import java.util.*;
import java.util.concurrent.SynchronousQueue;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import de.tubs.cs.iti.jcrypt.chiffre.CharacterMapping;
import de.tubs.cs.iti.jcrypt.chiffre.Cipher;
import de.tubs.cs.iti.jcrypt.chiffre.FrequencyTables;
import de.tubs.cs.iti.jcrypt.chiffre.NGram;
import sun.plugin2.message.SetAppletSizeMessage;
import sun.text.resources.cldr.th.FormatData_th;

/**
 * Dummy-Klasse für die Vigenère-Chiffre.
 *
 * @author Martin Klußmann
 * @version 1.0 - Tue Mar 30 15:53:38 CEST 2010
 */
public class Vigenere extends Cipher {

  private List<Integer> shift = new ArrayList<>();

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
    Map<String, Integer> parts = new HashMap<>();
    Map<Integer, Integer> primeFacs = new HashMap<>();

    StringBuilder builder = new StringBuilder();
    String aux = "";
    try {
      while ((aux = ciphertext.readLine()) != null) {
        builder.append(aux);
      }
    } catch (IOException e) {
      e.printStackTrace();
    }

    String text = builder.toString();

    int min = Math.min(text.length(), 3);
    int max = Math.min(2000, Math.max(text.length() / 1000, Math.min(6, text.length())));

    System.out.printf("Testet von bis i = %d, %d%n", min , max);

    int start = 0;

    //for (int i = min; i < max; i++) {
      //Pattern pattern = Pattern.compile(String.format("(?<teilwort>.{%d})(.*?)(\\k<teilwort>)", i), Pattern.DOTALL | Pattern.UNICODE_CHARACTER_CLASS);
    Pattern pattern = Pattern.compile("(?<teilwort>.{3,23})(.*?)(\\k<teilwort>)", Pattern.DOTALL);
      Matcher matcher = pattern.matcher(text);

      while (matcher.find(start)) {
        start = matcher.end(1);
        //System.out.println(start);
        int l = matcher.group(2).length() + matcher.group(1).length();

        List<List<Integer>> ps = powerset(getPrimeFactors(l));

        for (List<Integer> facs : ps) {
          int j = 1;
          for (int f : facs) {
            j *= f;
          }

          if (j > 1) {
            if (primeFacs.containsKey(j)) {
              primeFacs.replace(j, primeFacs.get(j) + 1);
            } else {
              primeFacs.put(j, 1);
            }
          }
        }

        parts.put(matcher.group(1), l);
        //System.out.printf("%10s --- %d%n", matcher.group(1), l);
    //  }
    }

    List<Map.Entry<Integer, Integer>> tlist = new ArrayList<>(primeFacs.entrySet());

    Collections.sort(tlist, (o1, o2) -> o2.getValue().compareTo(o1.getValue()));

    System.out.println("Es wurden folgene mögliche Schlüssellängen gefunden. Wählen Sie eine aus.");

    for (int i = 0; i < Math.min(20, tlist.size()); i++) {
      System.out.printf("%5d --- %5d%n", tlist.get(i).getKey(), tlist.get(i).getValue());
    }


    Scanner scanner = new Scanner(System.in);

    int d = 0;

    do {
      System.out.print("Geben Sie einen mögliche Schlüssellänge an: d = ");
      try {
        d = scanner.nextInt();
      } catch (InputMismatchException e) {
        scanner.next();
        System.out.println("Das war keine Zahl, versuche es erneut");
      }
    } while (d < 1);

    int f = 0;

    do {
      System.out.print("Geben Sie eine Schlüssel Aufsplittung an (kann das Ergebnis verbessern): f = ");
      try {
        f = scanner.nextInt();
      } catch (InputMismatchException e) {
        scanner.next();
        System.out.println("Das war keine Zahl, versuche es erneut");
      }
    } while (f < 1);

    int dfac = d * f;
    List<Integer> shiftfac = new ArrayList<>(dfac);
    //List<String> teilstrings = new ArrayList<>(dfac);

    for (int i = 0; i < dfac; i++) {
      StringBuilder stringBuilder = new StringBuilder();
      for (int j = 0; j * dfac + i < text.length(); j++) {
        stringBuilder.append(text.charAt(j * dfac + i));
      }
      String teiltext = stringBuilder.toString();
      PrintStream out = System.out;
      try {
        System.setOut(new PrintStream("bla"));
      } catch (FileNotFoundException e) {
        e.printStackTrace();
      }
      shiftfac.add(caesarKey(teiltext));
      System.setOut(out);
      //teilstrings.add(teiltext);
    }

    //List<List<Map.Entry<Integer, Integer>>> anzAll = new ArrayList<>(d);

    for (int i = 0; i < d; i++) {
      Map<Integer, Integer> anz = new HashMap<>(d);

      for (int j = 0; j < f; j++) {
        int n = shiftfac.get(j * d + i);
        if (anz.containsKey(n)) {
          anz.replace(n, anz.get(n) + 1);
        } else {
          anz.put(n, 1);
        }
      }

      List<Map.Entry<Integer, Integer>> anzList = new ArrayList<>(anz.entrySet());

      Collections.sort(anzList, (o1, o2) -> o2.getValue().compareTo(o1.getValue()));

      shift.add(anzList.get(0).getKey());
      //anzAll.add(anzList);
    }


    System.out.printf("Key: %s%n", Arrays.toString(shift.toArray(new Integer[shift.size()])));

    System.out.println();
  }

  private int caesarKey(String chiffre) {
    ArrayList<NGram> nGrams = FrequencyTables.getNGramsAsList(1, charMap);
    int character;
    int number = 0;
    HashMap<Integer, Integer> quantities = new HashMap<Integer, Integer>();
    for (char c : chiffre.toCharArray()) {
      character = (int) c;
      number++;
      character = charMap.mapChar(character);
      if (quantities.containsKey(character)) {
        quantities.put(character, quantities.get(character) + 1);
      } else {
        quantities.put(character, 1);
      }
    }
    int currKey = -1;
    int currValue = -1;
    int greatest = -1;
    int mostFrequented = -1;
    Iterator<Integer> it = quantities.keySet().iterator();
    while (it.hasNext()) {
      currKey = it.next();
      currValue = quantities.get(currKey);
      if (currValue > greatest) {
        greatest = currValue;
        mostFrequented = currKey;
      }
    }
    int computedShift = mostFrequented
            - charMap.mapChar(Integer.parseInt(nGrams.get(0).getIntegers()));
    if (computedShift < 0) {
      computedShift += modulus;
    }
    return computedShift;
  }

  private List<Integer> getPrimeFactors(int n) {
    List<Integer> fac = new LinkedList<>();
    for (int i = 2; i < n/2; i++) {
      if (BigInteger.valueOf(i).isProbablePrime(1000) && n % i == 0) {
        int m = n;
        while (m % i == 0) {
          fac.add(i);
          m /= i;
        }
      }
    }
    return fac;
  }

  public static <T> List<List<T>> powerset(Collection<T> list) {
    List<List<T>> ps = new ArrayList<List<T>>();
    ps.add(new ArrayList<T>());   // add the empty set

    // for every item in the original list
    for (T item : list) {
      List<List<T>> newPs = new ArrayList<List<T>>();

      for (List<T> subset : ps) {
        // copy all of the current powerset's subsets
        newPs.add(subset);

        // plus the subsets appended with the current item
        List<T> newSubset = new ArrayList<T>(subset);
        newSubset.add(item);
        newPs.add(newSubset);
      }

      // powerset is now powerset of list.subList(0, list.indexOf(item)+1)
      ps = newPs;
    }
    return ps;
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
// Kommentierung analog 'encipher(cleartext, ciphertext)'.
    try {
      int character;
      int k = 0;
      while ((character = ciphertext.read()) != -1) {
        character = charMap.mapChar(character);
        if (character != -1) {
          character = (character - shift.get(k++ % shift.size()) + modulus) % modulus;
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
      // 'character' ist die Integer-Repräsentation eines Zeichens.
      int character;
      int k = 0;
      // 'characterSkipped' zeigt an, daß ein aus der Klartextdatei gelesenes
      // Zeichen mit dem gewählten Alphabet nicht abgebildet werden konnte.
      boolean characterSkipped = false;
      // Lese zeichenweise aus der Klartextdatei, bis das Dateiende erreicht
      // ist. Der Buchstabe a wird z.B. als ein Wert von 97 gelesen.
      while ((character = cleartext.read()) != -1) {
        // Bilde 'character' auf dessen interne Darstellung ab, d.h. auf einen
        // Wert der Menge {0, 1, ..., Modulus - 1}. Ist z.B. a der erste
        // Buchstabe des Alphabets, wird die gelesene 97 auf 0 abgebildet:
        // mapChar(97) = 0.
        character = charMap.mapChar(character);
        if (character != -1) {
          // Das gelesene Zeichen ist im benutzten Alphabet enthalten und konnte
          // abgebildet werden. Die folgende Quellcode-Zeile stellt den Kern der
          // Caesar-Chiffrierung dar: Addiere zu (der internen Darstellung von)
          // 'character' zyklisch den 'shift' hinzu.
          character = (character + shift.get(k++ % shift.size())) % modulus;
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
        System.out.print("Geben Sie die Verschiebung ein: ");

        String keyseq = standardInput.readLine();

        for (String key : keyseq.split(" ")) {
          int k = Integer.parseInt(key);
          if (!(k >= 0 && k < modulus)) {
            System.out.println("Diese Verschiebung ist nicht geeignet. Bitte "
                    + "korrigieren Sie Ihre Eingabe.");
            break;
          }

          shift.add(k);

          accepted = true;
        }
      } catch (NumberFormatException e) {
        System.out.println("Fehler beim Parsen der Verschiebung. Bitte "
                + "korrigieren Sie Ihre Eingabe.");
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

    try {
      StringTokenizer st = new StringTokenizer(key.readLine(), " ");
      modulus = Integer.parseInt(st.nextToken());
      System.out.println("Modulus: " + modulus);
      while (st.hasMoreElements()) {
        shift.add(Integer.parseInt(st.nextToken()));
      }
      System.out.println("Verschiebung: " + Arrays.toString(shift.toArray(new Integer[shift.size()])));
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

      for (int i : shift) {
        key.write(String.format("%5s", i + ""));
      }

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
