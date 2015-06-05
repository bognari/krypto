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

import java.io.*;
import java.math.BigInteger;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.util.Arrays;
import java.util.BitSet;
import java.util.StringTokenizer;

import de.tubs.cs.iti.jcrypt.chiffre.BlockCipher;

/**
 * Dummy-Klasse für den International Data Encryption Algorithm (IDEA).
 *
 * @author Martin Klußmann
 * @version 1.1 - Sat Apr 03 21:57:35 CEST 2010
 */



//TODO: dechiper machen (siehe dechiper_TODO

    //TODO CBD sollte einfach gehen


public final class IDEA extends BlockCipher {
    String myKey;
    int MAX_16=65536;
    int[] keyArray = new int[16];
    int[] cbc= new int[4];
    boolean cbcMode=false;
    boolean roundKeysSet=false;
    int roundKeys[][] = new int[9][6]; // m n
    int roundKeysReverse[][] = new int[9][6]; // m n
    /**
     * Entschlüsselt den durch den FileInputStream <code>ciphertext</code>
     * gegebenen Chiffretext und schreibt den Klartext in den FileOutputStream
     * <code>cleartext</code>.
     *
     * @param ciphertext Der FileInputStream, der den Chiffretext liefert.
     * @param cleartext  Der FileOutputStream, in den der Klartext geschrieben werden soll.
     */
    public void decipher(FileInputStream ciphertext, FileOutputStream cleartext) {


        /*
        TODO: enchipermetohde mit reverse = true muss einen fehler werfen.
        ???
        PROFIT
         */


        /*
        // #################### REAL STUFF STARTS HERE ##############

        System.out.println(MAX_16);
        System.out.println(Integer.toBinaryString(MAX_16));
        int result2;
        result2=add(MAX_16, 8);
        System.out.println(result2);
        System.out.println(Integer.toBinaryString(result2));

        //biggest Z*2^16 = 32767 = 111111111111111

        //2 hoch 16 = 65536

        int foo = Integer.parseInt("1001", 2);
        System.out.println("par : " + foo);
*/



        // LETS GO


        // READ KEY ?
        makeKeyArray();
        String finalKey="";
        String newKey;
        for (int i=0;i<keyArray.length;i++) {
            newKey = Integer.toBinaryString(keyArray[i]);
            while (newKey.length() < 8) {
                newKey = "0" + newKey;
            }
            System.out.println("newKey = " + newKey);
            finalKey=finalKey.concat(newKey);
        }
        System.out.println("FinalKey = " + finalKey);

        // make reverseRoundkey need to moved to deciper one block or smothing like that maybe flag?

        //makeRoundKeysReverse(key);


        // start with this R_Keys like before

        int bs;
        boolean even=false;
        String block="";
        String secoundBytePart="";


        int[] chiffretextInt=new int[4];
        int[] cleartextInt=new int[4];
        int c=0;
        try{
            while ((bs = ciphertext.read()) != -1) {
                //bs=(byte)cleartext.read();
                System.out.println("Eingelesen aus Cipher = " + bs);
                if (even){
                    secoundBytePart=Integer.toBinaryString(bs);
                    // by default there are no missing leading zeros or should
                    while (secoundBytePart.length() < 8) {
                        secoundBytePart = "0" + secoundBytePart;
                        System.out.println("BUMP IT UP");
                    }

                    block=block+secoundBytePart;
                    chiffretextInt[c]=Integer.parseInt(block, 2);
                    c++;
                    even=false;
                    if(c==4){
                        // CBC
                        //getRandomString 64bit
                        // need to be changed
                        cbc[0]=0;
                        cbc[1]=0;
                        cbc[2]=0;
                        cbc[3]=0;


                        //split into 16 bit strings


                        if(cbcMode){
                            chiffretextInt[0]=xor(chiffretextInt[0],cbc[0]);
                            chiffretextInt[1]=xor(chiffretextInt[1],cbc[1]);
                            chiffretextInt[2]=xor(chiffretextInt[2],cbc[2]);
                            chiffretextInt[3]=xor(chiffretextInt[3],cbc[3]);
                        }
                        // CBC_END
                        System.out.println("Bloecke VOR decipher methode = " + chiffretextInt[0] + " [1]= " + chiffretextInt[1] + " [2]= " + chiffretextInt[2] + " [3]= " + chiffretextInt[3]);
                        cleartextInt=enchiperOneBlock(finalKey,chiffretextInt,true);
                        System.out.println("Bloecke NACH decipher methode = " + cleartextInt[0] + " [1]= " + cleartextInt[1] + " [2]= " + cleartextInt[2] + " [3]= " + cleartextInt[3]);
                        cbc=cleartextInt;
                        //WRITE
                        String strOut="";
                        for (int i=0;i<4;i++) {
                            strOut = Integer.toBinaryString(cleartextInt[i]);
                            while (strOut.length() < 16) {
                                strOut = "0" + strOut;
                            }
                            System.out.println("out teil 1 as int = " + Integer.parseInt(strOut.substring(0,8), 2));
                            System.out.println("out teil 2 as int = " + (Integer.parseInt(strOut.substring(8,16), 2)));
                            cleartext.write(Integer.parseInt(strOut.substring(0,8), 2));
                            cleartext.write(Integer.parseInt(strOut.substring(8, 16), 2));
                        }

                        //WRITE_END
                        c=0;
                    }
                }else{
                    block=Integer.toBinaryString(bs);
                    even=true;
                }
            }
            // nun auffüllen mit leerzeichen;
            if(c!=0) {
                System.out.println("restblock betreten  " + c);
                while (c < 4) {
                    if (even) {
                        block = block + "00000000";
                        chiffretextInt[c] = Integer.parseInt(block, 2);
                        c++;
                        even = false;
                    } else {
                        block = "0000000000000000";
                        chiffretextInt[c] = Integer.parseInt(block, 2);
                        c++;
                    }
                }
                cleartextInt = enchiperOneBlock(finalKey, chiffretextInt,true);

            // no need for cbc, its the last block.!
            //WRITE
            String strOut="";
            for (int i=0;i<4;i++) {
                strOut = Integer.toBinaryString(chiffretextInt[i]);
                while (strOut.length() < 16) {
                    strOut = "0" + strOut;
                    System.out.println("TRIGGER_DEC");
                }
                cleartext.write(Integer.parseInt(strOut.substring(0, 8), 2));
                cleartext.write(Integer.parseInt(strOut.substring(8, 16), 2));
            }
            }
            /*
            ciphertext.write(chiffretextInt[0]);
            ciphertext.write(chiffretextInt[1]);
            ciphertext.write(chiffretextInt[2]);
            ciphertext.write(chiffretextInt[3]);
            */
        }catch (IOException e){
            System.exit(1);
        }


        // ###CP END###


        // WHERE IS CBC?
    }

    /**
     * add two values in Z*2^16
     *
     * @param inputA first Input max Z*2^16
     * @param inputB secound input max Z*2^16
     * @return the sum of both in Z*2^16
     */
    private int add(int inputA, int inputB){
        return (inputA+inputB)%MAX_16;

    }

    /**
     * xor operation dont change the binary view
     * @param inputA first Input max Z*2^16
     * @param inputB secound input max Z*2^16
     * @return XOR of both
     */

    private int xor(int inputA,int inputB) {
        return (inputA ^ inputB); // by default no change in bit length
    }

    /**
     * multiplicate two values in Z*2^16+1 and maps them as needed
     *
     * @param inputA first Input max Z*2^16
     * @param inputB secound input max Z*2^16
     * @return the sum of both in Z*2^16
     */

    private int mul(int inputA, int inputB){
       // if(inputA==0){inputA=MAX_16;}
        inputA=inputA==0?MAX_16:inputA;
        inputB=inputB==0?MAX_16:inputB;
       // return ((inputA*inputB)%(MAX_16+1))==0?MAX_16:((inputA*inputB)%(MAX_16+1));
        //TODO nur long wenn notwendig machen
        long fire=(long)((long)inputA*(long)inputB);
        int hold=(int)(fire%(MAX_16+1));
        if(hold==0){
            return MAX_16;
        }
        return hold;
    }



    private void splitKey(){}

    /**
     *
     */
    /**
     * Verschlüsselt den durch den FileInputStream <code>cleartext</code>
     * gegebenen Klartext und schreibt den Chiffretext in den FileOutputStream
     * <code>ciphertext</code>.
     *
     * @param cleartext  Der FileInputStream, der den Klartext liefert.
     * @param ciphertext Der FileOutputStream, in den der Chiffretext geschrieben werden soll.
     */
    public void encipher(FileInputStream cleartext, FileOutputStream ciphertext) {


        System.out.println("Starte encipher methode mit key = " + myKey);
        System.out.println("Starte encipher methode mit key = " + keyArray[0]);
        // need to get leading zeroes



        makeKeyArray();
        String finalKey="";
        String newKey;
        for (int i=0;i<keyArray.length;i++) {
            newKey = Integer.toBinaryString(keyArray[i]);
            while (newKey.length() < 8) {
                newKey = "0" + newKey;
            }
            System.out.println("newKey = " + newKey);
            finalKey=finalKey.concat(newKey);
        }
        System.out.println("FinalKey = " + finalKey);
        // runden key int key als string haben, dann entsprechend zyklisch shiften als string , dann den key zerschneiden und in int parsen.

        //need to split the long key into round keys, maybe i shall move this into a different function

        int bs;
        boolean even=false;
        String block="";
        String secoundBytePart="";


        int[] chiffretextInt=new int[4];
        int[] cleartextInt=new int[4];
        int c=0;
        try{
            while ((bs = cleartext.read()) != -1) {
                //bs=(byte)cleartext.read();
                System.out.println("Eingelesen aus clearText (bs) = " + bs);
                if (even){
                    secoundBytePart=Integer.toBinaryString(bs);
                    while (secoundBytePart.length() < 8) {
                        secoundBytePart = "0" + secoundBytePart;
                    }
                    block=block+secoundBytePart;
                    cleartextInt[c]=Integer.parseInt(block, 2);
                    c++;
                    even=false;
                    if(c==4){
                        // CBC
                            //getRandomString 64bit
                        //dummy
                        cbc[0]=0;
                        cbc[1]=0;
                        cbc[2]=0;
                        cbc[3]=0;


                            //split into 16 bit strings


                        if(cbcMode){
                            cleartextInt[0]=xor(cleartextInt[0],cbc[0]);
                            cleartextInt[1]=xor(cleartextInt[1],cbc[1]);
                            cleartextInt[2]=xor(cleartextInt[2],cbc[2]);
                            cleartextInt[3]=xor(cleartextInt[3],cbc[3]);
                        }
                        // CBC_END
                        chiffretextInt=enchiperOneBlock(finalKey,cleartextInt,false);
                        cbc=chiffretextInt;
                        //WRITE
                        String strOut="";
                        for (int i=0;i<4;i++) {
                            strOut = Integer.toBinaryString(chiffretextInt[i]);
                            while (strOut.length() < 16) {
                                strOut = "0" + strOut;
                            }
                            System.out.println("out teil 1 = " + Integer.parseInt(strOut.substring(0,8), 2));
                            System.out.println("out teil 2 = " + (Integer.parseInt(strOut.substring(8,16), 2)));
                            ciphertext.write(Integer.parseInt(strOut.substring(0,8), 2));
                            ciphertext.write(Integer.parseInt(strOut.substring(8,16), 2));
                        }

                        //WRITE_END
                        //test




                       // ciphertext.write(chiffretextInt[0]);
                      //  ciphertext.write(chiffretextInt[1]);
                       // ciphertext.write(chiffretextInt[2]);
                       // ciphertext.write(chiffretextInt[3]);

                        c=0;
                    }
                }else{
                    block=Integer.toBinaryString(bs);
                    even=true;
                }

            }
            // nun auffüllen mit leerzeichen;
            if(c!=0) {
                while (c < 4) {
                    if (even) {
                        block = block + "00000000";
                        cleartextInt[c] = Integer.parseInt(block, 2);
                        c++;
                        even = false;
                    } else {
                        block = "0000000000000000";
                        cleartextInt[c] = Integer.parseInt(block, 2);
                        c++;
                    }
                }
                chiffretextInt = enchiperOneBlock(finalKey, cleartextInt,false);

            // no need for cbc, its the last block.!
            //WRITE
            String strOut="";
            for (int i=0;i<4;i++) {
                strOut = Integer.toBinaryString(chiffretextInt[i]);
                while (strOut.length() < 16) {
                    strOut = "0" + strOut;
                }
                ciphertext.write(Integer.parseInt(strOut.substring(0,8), 2));
                ciphertext.write(Integer.parseInt(strOut.substring(8,16), 2));
            }
            }
            /*
            ciphertext.write(chiffretextInt[0]);
            ciphertext.write(chiffretextInt[1]);
            ciphertext.write(chiffretextInt[2]);
            ciphertext.write(chiffretextInt[3]);
            */
        }catch (IOException e){
            System.exit(1);
        }

        // O+ = XOR
        // |+| = ADD
        // O. = MUL

        System.out.println("First letter to chiffre as int   " + chiffretextInt[0]);
        System.out.println("First letter to chiffre as binaryString   " + Integer.toBinaryString(chiffretextInt[0]));

    }

    /**
     * Enchiper one block
     */
    private int[] enchiperOneBlock(String key,int[] parts,boolean reverse){
        //if(parts.length!=4)throw E;
       // System.out.println("Toller key mit lange = "+ key.length());
        int myRoundKeys[][]=new int[9][6];
        if(!reverse){
            myRoundKeys = makeRoundKeys(key);
        }else{
            myRoundKeys= makeRoundKeysReverse(key);
        }
        // ive got my Keys
        //int rK[]=roundKeys[0];



        int c=0;
        while (c<8) {
            parts = makeRound(myRoundKeys[c], parts);
            c++;
            /*
            System.out.println("parts nach einer runde");
            System.out.println(parts[0]);
            System.out.println(parts[1]);
            System.out.println(parts[2]);
            System.out.println(parts[3]);
            */
        }
        parts = makeFinalRound(myRoundKeys[8],parts);

       // System.out.println("FINAL PART = " + parts[0]);

        return parts;

    }

    private int[] makeFinalRound(int[]roundKey,int[]parts){

        int out[]=new int[4];
        out[0]=mul(parts[0],roundKey[0]);
        out[1]=add(parts[1],roundKey[1]);
        out[2]=add(parts[2],roundKey[2]);
        out[3]=mul(parts[3],roundKey[3]);
        return out;
    }


    private int[] makeRound(int[]roundKey,int[]parts){

        // TODO best performance values vs FULL formular

        int a=mul(parts[0],roundKey[0]);
        int b=add(parts[1],roundKey[1]);
        int c=add(parts[2],roundKey[2]);
        int d=mul(parts[3],roundKey[3]);
        int e=xor(a,c);
        int f=xor(b,d);
        int g=mul(e,roundKey[4]);
        int h=add(g,f);
        int i=mul(h,roundKey[5]);
        int j=add(g,i);



        int out[]=new int[4];
        out[0]=mul(a,i);
        out[1]=mul(c,i);
        out[2]=mul(b,j);
        out[3]=mul(d,j);

        return out;
    }

    /**
     * make the Round keys and save it to a global var array
     * it just needed once so there is a flag but should be moved out of this flag sooner than later cause its an unnessary (legacy) call
     * NOTIE: the keys [8][4/5] are NULL
     * @param key the key which is the base for the round keys
     * @return the roundkey array just to make sure its legacy
     */

    private int[][] makeRoundKeys(String key){
        // make key parts
        if(!roundKeysSet) {
            int c = 0;
            int n = 0;
            int m = 0;


            while (m < 8) {
                if (c >= 8) {
                    key = zykShift(key);
                    c = 0;
                }
                if (n < 6) {
                    // System.out.println("Toller key mit lange = "+ key.length());
                    roundKeys[m][n] = Integer.parseInt(key.substring(c * 16, ((c + 1) * 16) - 1), 2);
                    n++;
                    c++;
                } else {
                    n = 0;
                    m++;
                }
            }
            n = 0;
            while (n < 4) {
                roundKeys[8][n] = Integer.parseInt(key.substring(c * 16, (c + 1) * 16), 2);
                n++;
                c++;
            }
        }
        roundKeysSet=true;
        return roundKeys;
    }

    private int[][] makeRoundKeysReverse(String key){

        //TODO evtl ueberschriebt er irgendwas sollte nicht der fall sein, man kann es mal ueberpruefen
        if(!roundKeysSet){
            makeRoundKeys(key);
        }

        //go try hard

        roundKeysReverse[0][0]=inverse(roundKeys[8][0]);
        roundKeysReverse[0][1]=minusKey(roundKeys[8][1]);
        roundKeysReverse[0][2]=minusKey(roundKeys[8][2]);
        roundKeysReverse[0][3]=inverse(roundKeys[8][3]);
        roundKeysReverse[0][4]=roundKeys[7][4];
        roundKeysReverse[0][5]=roundKeys[7][5];

        int r=1; // =2 <=7 .
        while(r<=7){
            System.out.println("round = " + r);
            roundKeysReverse[r][0]=inverse(roundKeys[8-r][0]);
            roundKeysReverse[r][1]=minusKey(roundKeys[8 - r][2]);
            roundKeysReverse[r][2]=minusKey(roundKeys[8-r][1]);
            roundKeysReverse[r][3]=inverse(roundKeys[8-r][3]);
            roundKeysReverse[r][4]=roundKeys[7-r][4];
            roundKeysReverse[r][5]=roundKeys[7-r][5];
            r++;
        }
        roundKeysReverse[8][0]=inverse(roundKeys[0][0]);
        roundKeysReverse[8][1]=minusKey(roundKeys[0][1]);
        roundKeysReverse[8][2]=minusKey(roundKeys[0][2]);
        roundKeysReverse[8][3]=inverse(roundKeys[0][3]);

        return roundKeysReverse;
    }

    private int minusKey(int input){
        int out=(MAX_16-input)%MAX_16;
        return out;
    }
    /**
     * algo 3.3
     * @param input a
     * @return inverse
     */
    private int inverse(int input){


        BigInteger bi1, bi2, bi3;
        bi1= new BigInteger(Integer.toString(input));
        bi2= new BigInteger(Integer.toString(MAX_16+1));
        int n=MAX_16+1;
       // System.out.println("GCD = " + bi1.gcd(bi2));
        bi3 = bi1.modInverse(bi2);
        return bi3.intValue();
    }
    /**
     * zyklischer shift um 25 positionen
     */
    private String zykShift(String inputString){
        return inputString.substring(25,inputString.length())+inputString.substring(0,25);
    }

    /**
     * Convert the chars from the myKey String to the ASCII value in int in the array keyArray
     */
    private void makeKeyArray(){
        for(int i=0;i<16;i++){
            keyArray[i]=(int)myKey.charAt(i);
        }



    }

    /**
     * Erzeugt einen neuen Schlüssel.
     *
     * @see #readKey readKey
     * @see #writeKey writeKey
     */
    public void makeKey() {

        System.out.println("Dummy für die Schlüsselerzeugung.");
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
    }

    /**
     * Schreibt den Schlüssel mit dem Writer <code>key</code>.
     *
     * @param key Der Writer, der in die Schlüsseldatei schreibt.
     * @see #makeKey makeKey
     * @see #readKey readKey
     */
    public void writeKey(BufferedWriter key) {

    }
}
