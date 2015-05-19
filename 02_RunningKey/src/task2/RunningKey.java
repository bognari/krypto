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
import de.tubs.cs.iti.jcrypt.chiffre.FrequencyTables;
import de.tubs.cs.iti.jcrypt.chiffre.NGram;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.*;
import java.util.stream.Collectors;

/**
 * Dummy-Klasse für die Chiffre mit laufendem Schlüssel.
 *
 * @author Martin Klußmann
 * @version 1.0 - Tue Mar 30 16:23:47 CEST 2010
 */
public class RunningKey extends Cipher {

    Path key;

    Map<String, NGram> uniGram;
    Map<String, NGram> diGram;
    Map<String, NGram> triGram;

    int uniPrio = 1;
    int diPrio = 10;
    int triPrio = 100;

    Map<Integer, Set<Map.Entry<Integer, Integer>>> combi = new HashMap<>(modulus);


    /**
     * Analysiert den durch den Reader <code>ciphertext</code> gegebenen
     * Chiffretext, bricht die Chiffre bzw. unterstützt das Brechen der Chiffre
     * (ggf. interaktiv) und schreibt den Klartext mit dem Writer
     * <code>cleartext</code>.
     *
     * @param ciphertext Der Reader, der den Chiffretext liefert.
     * @param cleartext  Der Writer, der den Klartext schreiben soll.
     */
    public void breakCipher(BufferedReader ciphertext, BufferedWriter cleartext) {
        key = Paths.get("key.txt");

        uniGram = getNGramMap(FrequencyTables.getNGramsAsList(1, charMap));
        diGram = getNGramMap(FrequencyTables.getNGramsAsList(2, charMap));
        triGram = getNGramMap(FrequencyTables.getNGramsAsList(3, charMap));

        StringBuilder builder = new StringBuilder();
        String aux = "";
        try {
            while ((aux = ciphertext.readLine()) != null) {
                builder.append(aux);
            }
        } catch (IOException e) {
            e.printStackTrace();
        }

        String chipher = builder.toString();
        char[] klarText = new char[chipher.length()];
        char[] keyText = new char[chipher.length()];

        int start = 0;
        int end = 4;

        Map<Character, List<RelationFrequency>> map = getRelationFreqencyMap();

        Scanner cin = new Scanner(System.in);

        System.out.println("Wie soll die Gewichtung aussehen fuer Uni/Di/Tri Grams?");

        try {
            System.out.println("Gewichtung Unigram: 1-1000: ");
            uniPrio = cin.nextInt();

            System.out.println("Gewichtung Digram: 1-1000: ");
            diPrio = cin.nextInt();

            System.out.println("Gewichtung Trigram: 1-1000: ");
            triPrio = cin.nextInt();
        } catch (Exception e) {
            System.out.println("Falsche Eingabe, 1 wird fuer die restlichen ausgewaehlt");
        }

        out:
        do {

            System.out.println("Welche Stelle des Ciphertextes soll betrachtet werden?");
            System.out.println("Waehle: 0-" + chipher.length());
            try {
                System.out.print("Start: ");
                start = cin.nextInt();
            } catch (Exception e) {
                System.out.println("Falsche Eingabe, 0. Stelle wird ausgewaehlt!");
            }
            try {
                System.out.print("Ende: ");
                end = cin.nextInt();
            } catch (Exception e) {
                System.out.println("Falsche Eingabe, 4. Stelle wird ausgewaehlt!");
            }

            in:
            do {

                List<List<RelationFrequency>> komischeTabelle = new LinkedList<>();

                for (int i = start; i < end; i++) {
                    if (klarText[i] != '\0') {
                        List<RelationFrequency> entry = new LinkedList<>();
                        RelationFrequency relationFrequency = new RelationFrequency();
                        relationFrequency.klarCand = klarText[i];
                        relationFrequency.keyCand = keyText[i];
                        entry.add(relationFrequency);
                        komischeTabelle.add(entry);
                    } else {
                        if (map.get(chipher.charAt(i)) != null) {
                            komischeTabelle.add(map.get(chipher.charAt(i)).subList(0, 10));
                        } else {
                            System.err.printf("Unigram ist blöd. %s fehlt", chipher.charAt(i) + "");
                        }

                    }
                }

                List<RelationFrequencyCombi> relationFrequencyCombiList = getCombination(komischeTabelle.subList(0, end - start).toArray(new List[end - start]));


                Collections.sort(relationFrequencyCombiList);

                System.out.println("Es wurden folgende sinnvolle Kombinationen gefunden:");
                System.out.printf("%10s | %10s | %10s | %10s%n", "Position", "Klar", "Key", "Wahrscheinlichkeit");
                for (int i = 0; i < 10 && i < relationFrequencyCombiList.size(); i++) {
                    System.out.printf("%10d | %10s | %10s | %10f%n", i, relationFrequencyCombiList.get(i).klarCand, relationFrequencyCombiList.get(i).keyCand, relationFrequencyCombiList.get(i).frequency);
                }

                System.out.println();
                System.out.print("Wählen Sie eine Kombination: ");

                int index = cin.nextInt();

                for (int i = 0; i < end - start; i++) {
                    keyText[start + i] = relationFrequencyCombiList.get(index).keyCand.charAt(i);
                    klarText[start + i] = relationFrequencyCombiList.get(index).klarCand.charAt(i);
                }

                System.out.print("Wollen Sie weiter machen? [j]a/[n]ein/[v]or/[z]urück ");
                switch (cin.next()) {
                    case "j":
                        continue out;
                    case "v":
                        start++;
                        end++;
                        if (end >= chipher.length()) {
                            break out;
                        }
                        continue in;
                    case "z":
                        start--;
                        end--;
                        if (start <= 0) {
                            break out;
                        }
                        continue in;
                    default:
                        break out;
                }
            } while (true);

        } while (true);

        try {
            cleartext.write(String.copyValueOf(klarText));
            cleartext.flush();
            ciphertext.close();
        } catch (IOException e) {
            e.printStackTrace();
        }

        try {
            BufferedWriter bufferedWriter = Files.newBufferedWriter(key);
            bufferedWriter.write(String.valueOf(keyText));
            bufferedWriter.flush();
            ciphertext.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    Map<String, NGram> getNGramMap(List<NGram> list) {
        Map<String, NGram> ngrams = new LinkedHashMap<>();
        for (NGram ngram : list) {
            ngrams.put(ngram.getCharacters(), ngram);
        }
        return ngrams;
    }

    public List<RelationFrequency> getRelationFreqency(char c) {
        List<RelationFrequency> list = new ArrayList<>(uniGram.size());
        list.addAll(uniGram.keySet().stream().map(key -> new RelationFrequency(c, key.charAt(0))).collect(Collectors.toList()));
        return list;
    }

    public Map<Character, List<RelationFrequency>> getRelationFreqencyMap() {
        Map<Character, List<RelationFrequency>> map = new HashMap<>(uniGram.size());
        for (String key : uniGram.keySet()) {
            List<RelationFrequency> list = getRelationFreqency(key.charAt(0));
            Collections.sort(list);
            map.put(key.charAt(0), list);
        }
        return map;
    }

    class RelationFrequencyCombi implements Comparable<RelationFrequencyCombi> {
        String klarCand = "";
        String keyCand = "";
        double frequency;

        RelationFrequencyCombi(RelationFrequency[] combi) {
            for (RelationFrequency relationFrequency : combi) {
                klarCand += (char) relationFrequency.klarCand;
                keyCand += (char) relationFrequency.keyCand;
            }

            frequency = bewertung(uniPrio, diPrio, triPrio);
        }

        @Override
        public String toString() {
            return klarCand + " | " + keyCand;
        }

        @Override
        public int compareTo(RelationFrequencyCombi o) {
            return Double.compare(o.frequency, frequency);
        }

        private double bewertung(double g1, double g2, double g3) {

            double result;
            double k1 = 0, k2 = 0, k3 = 0;
            double s1 = 0, s2 = 0, s3 = 0;

            for (int i = 0; i < keyCand.length(); i++) {
                s1 += uniGram.get(klarCand.substring(i, i + 1)).getFrequency();
                k1 += uniGram.get(keyCand.substring(i, i + 1)).getFrequency();
            }

            for (int i = 0; i < keyCand.length() - 1; i++) {
                if ((diGram.get(klarCand.substring(i, i + 2))) != null) {
                    s2 += diGram.get(klarCand.substring(i, i + 2)).getFrequency();
                } else {
                    s2 += 0;
                }

                if ((diGram.get(keyCand.substring(i, i + 2))) != null) {
                    k2 += diGram.get(keyCand.substring(i, i + 2)).getFrequency();
                } else {
                    k2 += 0;
                }
            }

            for (int i = 0; i < keyCand.length() - 2; i++) {
                if ((triGram.get(klarCand.substring(i, i + 3))) != null) {
                    s3 += triGram.get(klarCand.substring(i, i + 3)).getFrequency();
                } else {
                    s3 += 0;
                }

                if ((triGram.get(keyCand.substring(i, i + 3))) != null) {
                    k3 += triGram.get(keyCand.substring(i, i + 3)).getFrequency();
                } else {
                    k3 += 0;
                }
            }

            result = (g1 * k1 + g2 * k2 + g3 * k3) * (g1 * s1 + g2 * s2 + g3 * s3);

            return result;
        }
    }

    class RelationFrequency implements Comparable<RelationFrequency> {
        int klarCand;
        int keyCand;

        public RelationFrequency() {

        }

        ;

        public RelationFrequency(char c, char klarCand) {
            this.klarCand = klarCand;
            //c = (char)charMap.mapChar(c);
            //klarCand = (char)charMap.mapChar(klarCand);

            int character = (c - klarCand + 10 * modulus) % modulus;
            character = charMap.remapChar(character);
            this.keyCand = character;
        }

        public double getFrequency() {
            double d;
            try {
                d = uniGram.get(String.valueOf((char) klarCand)).getFrequency() * uniGram.get(String.valueOf((char) keyCand)).getFrequency();
            } catch (Exception e) {
                d = -1;
            }
            return d;
        }

        @Override
        public int compareTo(RelationFrequency o) {
            return Double.compare(o.getFrequency(), getFrequency());
        }

        @Override
        public String toString() {
            return "RelationFreqency{" +
                    "klarCand=" + (char) klarCand +
                    ", keyCand=" + (char) keyCand +
                    "} = " + getFrequency();
        }
    }

    private List<RelationFrequencyCombi> getCombination(List<RelationFrequency>[] relationFrequencys) {
        return combination(relationFrequencys, new LinkedList<>(), new ArrayList<>(relationFrequencys.length));
    }


    private List<RelationFrequencyCombi> combination(List<RelationFrequency>[] relationFrequencys, List<RelationFrequencyCombi> ret, List<RelationFrequency> prefix) {
        //prefix.stream().forEach(relationFrequency -> System.out.print((char)relationFrequency.klarCand));
        //System.out.println();
        //System.out.println();
        if (prefix.size() < relationFrequencys.length) {
            for (RelationFrequency relationFrequency : relationFrequencys[prefix.size()]) {
                prefix.add(relationFrequency);
                combination(relationFrequencys, ret, prefix);
                prefix.remove(prefix.size() - 1);
            }
        } else {
            RelationFrequency[] rf = prefix.toArray(new RelationFrequency[prefix.size()]);
            ret.add(0, new RelationFrequencyCombi(rf));
        }
        return ret;
        /*List<RelationFrequency> la = relationFrequencys[0];
        List<RelationFrequency> lb = relationFrequencys[1];
        List<RelationFrequency> lc = relationFrequencys[2];
        List<RelationFrequency> ld = relationFrequencys[3];

        for (RelationFrequency aLa : la) {
            for (RelationFrequency aLb : lb) {
                for (RelationFrequency aLc : lc) {
                    for (RelationFrequency aLd : ld) {
                        RelationFrequencyCombi combi = new RelationFrequencyCombi(new RelationFrequency[] {aLa, aLb, aLc, aLd});
                        list.add(combi);
                    }
                }
            }
        }
        return list;*/
    }

    /**
     * Entschlüsselt den durch den Reader <code>ciphertext</code> gegebenen
     * Chiffretext und schreibt den Klartext mit dem Writer
     * <code>cleartext</code>.
     *
     * @param ciphertext Der Reader, der den Chiffretext liefert.
     * @param cleartext  Der Writer, der den Klartext schreiben soll.
     */
    public void decipher(BufferedReader ciphertext, BufferedWriter cleartext) {
        try {
            BufferedReader keyText = Files.newBufferedReader(key, Charset.forName(launcher.getInFileEncoding()));
            int keyChar;
            int character;
            while ((character = ciphertext.read()) != -1) {
                character = charMap.mapChar(character);
                if (character != -1) {
                    keyChar = nextValidChar(keyText);
                    if (keyChar != -1) {
                        character = (character - keyChar + modulus) % modulus;
                        character = charMap.remapChar(character);
                        cleartext.write(character);
                    } else {

                    }
                } else {
                    //System.err.println((char)character);
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

    int nextValidChar(BufferedReader in) throws IOException {
        int c = -1;
        do {
            c = in.read();
            if (c == -1) {
                return -1;
            }
            // ToDo
            // c = Character.toLowerCase(c);
            c = charMap.mapChar(c);
        } while (c == -1);
        return c;
    }

    /**
     * Verschlüsselt den durch den Reader <code>cleartext</code> gegebenen
     * Klartext und schreibt den Chiffretext mit dem Writer
     * <code>ciphertext</code>.
     *
     * @param cleartext  Der Reader, der den Klartext liefert.
     * @param ciphertext Der Writer, der den Chiffretext schreiben soll.
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
            while ((character = cleartext.read()) != -1) {
                // Bilde 'character' auf dessen interne Darstellung ab, d.h. auf einen
                // Wert der Menge {0, 1, ..., Modulus - 1}. Ist z.B. a der erste
                // Buchstabe des Alphabets, wird die gelesene 97 auf 0 abgebildet:
                // mapChar(97) = 0.
                // ToDo
                // character = Character.toLowerCase(character);

                character = charMap.mapChar(character);
                if (character != -1) {
                    keyChar = nextValidChar(keyText);

                    if (keyChar != -1) {
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
                        try {
                            character = charMap.remapChar(character);
                        } catch (Exception e) {
                            e.printStackTrace();
                        }
                        ciphertext.write(character);
                    } else {
                        characterSkipped = true;
                    }
                } else {
                    // Das gelesene Zeichen ist im benutzten Alphabet nicht enthalten.
                    characterSkipped = true;
                    //System.err.println((char)character);
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
     * @param key Der Reader, der aus der Schlüsseldatei liest.
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
     * @param key Der Writer, der in die Schlüsseldatei schreibt.
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
