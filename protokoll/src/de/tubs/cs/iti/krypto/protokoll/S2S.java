package de.tubs.cs.iti.krypto.protokoll;

import de.tubs.cs.iti.jcrypt.chiffre.BigIntegerUtil;
import task3.IDEA;
import task5.Fingerprint;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Objects;
import java.util.Random;

/**
 * Created by stephan on 19.08.15.
 */
public class S2S implements Protocol {

    private Communicator communicator;
    private final String name;
    private final int maxPlayer;
    private final int minPlayer;

    private Fingerprint hash;

    public S2S() {
        name = "Game of Station 2 Station";
        minPlayer = 2;
        maxPlayer = 2;

        hash = new Fingerprint();
        try {
            hash.readParam(Files.newBufferedReader(Paths.get("Station-to-Station")));
        } catch (IOException e) {
            e.printStackTrace();
            System.exit(-1);
        }
    }


    /**
     * Diese Methode weist dem Protokoll das Communicator-objekt com f?r die Spielekommunikation zu.
     *
     * @param Com
     */
    @Override
    public void setCommunicator(Communicator Com) {
        this.communicator = Com;
    }

    /**
     * Diese Methode gibt den Namen des Spieles zurueck.
     *
     * @return<code>String</code> Name des Spieles
     */
    @Override
    public String nameOfTheGame() {
        return name;
    }

    /**
     * Diese Methode fuehrt der Client nach dem Laden des Spielprotokolls auf dem Spiel auf, wenn es die Partei ist, die
     * zuerst Daten sendet.
     */
    @Override
    public void sendFirst() {
        // (0) RSA setup

        RSA myRSA = new RSA();

        // compute prime and q
        Random random = new SecureRandom();
        BigInteger prime;
        BigInteger q;
        do {
            prime = BigInteger.probablePrime(512, random);
            q = prime.subtract(BigInteger.ONE).divide(BigInteger.valueOf(2L));
        } while (!q.isProbablePrime(42));
        assert Objects.equals(q.multiply(BigInteger.valueOf(2L)).add(BigInteger.ONE), prime);

        // compute g
        BigInteger g;
        do {
            g = BigIntegerUtil.randomBetween(BigInteger.valueOf(2L), prime.subtract(BigInteger.ONE));
        } while (!Objects.equals(g.modPow(q, prime), prime.subtract(BigInteger.ONE)));
        assert Objects.equals(g.modPow(q, prime), prime.subtract(BigInteger.ONE));

        communicator.sendTo(1, prime.toString());
        communicator.sendTo(1, g.toString());

        communicator.sendTo(1, myRSA.getE().toString());
        communicator.sendTo(1, myRSA.getN().toString());

        RSA otherRsa = new RSA(new BigInteger(communicator.receive()), new BigInteger(communicator.receive()));

        // (1)

        BigInteger xa = BigIntegerUtil.randomBetween(BigInteger.valueOf(3L), prime.subtract(BigInteger.valueOf(2L)));
        BigInteger ya = g.modPow(xa, prime);

        communicator.sendTo(1, ya.toString());

        // (3)

        Certificate certificateB = new Certificate(communicator.receive(), new BigInteger(communicator.receive())
            .toByteArray(), new BigInteger(communicator.receive()));

        BigInteger yb = new BigInteger(communicator.receive());
        BigInteger eSb = new BigInteger(communicator.receive());

        // 4

        if (!checkCertificate(certificateB)) {
            System.out.println("corrupt certificate");
            return;
        }

        BigInteger k = yb.modPow(xa, prime);

        IDEA idea = new IDEA();
        idea.setKey(k);
        idea.makeEnchipherKey();
        idea.makeDecipherKey();

        BigInteger sb = idea.d(eSb);

        BigInteger actualHash = otherRsa.veri(sb);
        BigInteger expectedHash = hash.hash(yb.multiply(prime).add(ya));

        if (!Objects.equals(actualHash, expectedHash)) {
            System.out.println("corrupt hash");
            return;
        }

        // 5

        BigInteger sa = myRSA.sig(hash.hash(ya.multiply(prime).add(yb)));


        // 6

        Certificate certificateA = TrustedAuthority.newCertificate("ALICE".getBytes());

        idea.makeEnchipherKey();
        BigInteger eSa = idea.e(sa);

        communicator.sendTo(1, certificateA.getID());
        communicator.sendTo(1, new BigInteger(certificateA.getData()).toString());
        communicator.sendTo(1, certificateA.getSignature().toString());

        communicator.sendTo(1, ya.toString());
        communicator.sendTo(1, eSa.toString());

        // 8
        chat(idea, true);

    }

    /**
     * Diese Methode fuehrt der Client nach dem Laden des Spielprotokolls auf dem Spiel auf, wenn es die Partei ist, die
     * zuerst Daten empfaengt.
     */
    @Override
    public void receiveFirst() {
        RSA myRSA = new RSA();

        // 0
        BigInteger prime = new BigInteger(communicator.receive());
        assert prime.isProbablePrime(42);
        BigInteger q = prime.subtract(BigInteger.ONE).divide(BigInteger.valueOf(2L));
        assert q.isProbablePrime(42);
        BigInteger g = new BigInteger(communicator.receive());
        assert Objects.equals(g.modPow(q, prime), prime.subtract(BigInteger.ONE));

        RSA otherRsa = new RSA(new BigInteger(communicator.receive()), new BigInteger(communicator.receive()));

        communicator.sendTo(1, myRSA.getE().toString());
        communicator.sendTo(1, myRSA.getN().toString());

        // 1

        BigInteger ya = new BigInteger(communicator.receive());

        // 2
        BigInteger xb = BigIntegerUtil.randomBetween(BigInteger.valueOf(3L), prime.subtract(BigInteger.valueOf(2L)));
        BigInteger yb = g.modPow(xb, prime);

        BigInteger k = ya.modPow(xb, prime);

        BigInteger sb = myRSA.sig(hash.hash(yb.multiply(prime).add(ya)));

        // 3
        Certificate certificateB = TrustedAuthority.newCertificate("BOB".getBytes());

        IDEA idea = new IDEA();
        idea.setKey(k);
        idea.makeEnchipherKey();
        BigInteger eSb = idea.e(sb);

        communicator.sendTo(0, certificateB.getID());
        communicator.sendTo(0, new BigInteger(certificateB.getData()).toString());
        communicator.sendTo(0, certificateB.getSignature().toString());

        communicator.sendTo(0, yb.toString());
        communicator.sendTo(0, eSb.toString());

        // (6)

        Certificate certificateA = new Certificate(communicator.receive(), new BigInteger(communicator.receive())
            .toByteArray(), new BigInteger(communicator.receive()));

        if (!Objects.equals(ya, new BigInteger(communicator.receive()))) {
            System.out.println("corrupt ya");
            return;
        }

        BigInteger eSa = new BigInteger(communicator.receive());

        // 4

        if (!checkCertificate(certificateA)) {
            System.out.println("corrupt certificate");
            return;
        }


        idea.makeEnchipherKey();
        idea.makeDecipherKey();

        BigInteger sa = idea.d(eSb);

        BigInteger actualHash = otherRsa.veri(sa);
        BigInteger expectedHash = hash.hash(ya.multiply(prime).add(yb));

        if (!Objects.equals(actualHash, expectedHash)) {
            System.out.println("corrupt hash");
            return;
        }

        // 8

        chat(idea, false);
    }

    public void chat(IDEA idea, boolean init) {
        try {

            BufferedReader in = new BufferedReader(new InputStreamReader(System.in));
            String line;
            BigInteger tmp;

            if(init) {
                line = in.readLine();
                if(line == null) {
                    return;
                }
                idea.makeEnchipherKey();
                tmp = new BigInteger(line.getBytes());
                tmp = idea.e(tmp);
                communicator.sendTo(1, tmp.toString(16));
            }

            while(true) {

                line = communicator.receive();
                tmp = new BigInteger(line, 16);
                idea.makeEnchipherKey();
                idea.makeDecipherKey();
                tmp = idea.d(tmp);
                System.out.println(new String(tmp.toByteArray()));

                line = in.readLine();
                if(line == null) {
                    return;
                }
                tmp = new BigInteger(line.getBytes());
                idea.makeEnchipherKey();
                tmp = idea.e(tmp);
                communicator.sendTo(init ? 1 : 0, tmp.toString(16));

            }

        } catch(IOException e) {
            e.printStackTrace();
            System.exit(0);
        }

    }

    /**
     * Diese Methode gibt die minimale Anzahl an Spielern zurueck
     *
     * @return<code>int</code> minimale Anzahl der Spieler
     */
    @Override
    public int minPlayer() {
        return minPlayer;
    }

    /**
     * Diese Methode gibt die maximale Anzahl an Spielern zurueck
     *
     * @return<code>int</code> maximale Anzahl der Spieler
     */
    @Override
    public int maxPlayer() {
        return maxPlayer;
    }

    public static boolean checkCertificate(Certificate cert) {
        MessageDigest sha = null;

        try {
            sha = MessageDigest.getInstance("SHA");
        } catch (Exception e) {
            System.out.println("Could not create message digest! Exception " + e.toString());
        }

        assert sha != null;
        sha.update(cert.getID().getBytes());
        sha.update(cert.getData());
        byte[] digest = sha.digest();

        BigInteger nam = new BigInteger(digest).mod(TrustedAuthority.getModulus());

        BigInteger nom = cert.getSignature().modPow(TrustedAuthority.getPublicExponent(), TrustedAuthority.getModulus());

        return nam.equals(nom);

    }

    class RSA {
        private final static int SIZE = 512;

        private final BigInteger n;
        private final BigInteger d;
        private final BigInteger e;
        RSA() {
            Random random = new SecureRandom();
            BigInteger p = BigInteger.probablePrime(SIZE, random);
            BigInteger q;
            do {
                q = BigInteger.probablePrime(SIZE, random);
            } while (Objects.equals(p, q));

            n = p.multiply(q);

            BigInteger phi = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));

            BigInteger probE;

            do {
                probE = BigIntegerUtil.randomBetween(BigInteger.valueOf(3L), phi.subtract(BigInteger.ONE), random);
            } while (!Objects.equals(probE.gcd(phi), BigInteger.ONE));

            e = probE;

            d = e.modInverse(phi);
        }

        RSA(BigInteger e, BigInteger n) {
            this.n = n;
            this.e = e;
            d = null;
        }

        RSA(BigInteger n, BigInteger e, BigInteger d) {
            this.n = n;
            this.e = e;
            this.d = d;
        }

        public BigInteger getN() {
            return n;
        }

        public BigInteger getE() {
            return e;
        }

        public BigInteger encrypt(BigInteger m) {
            return m.modPow(e, n);
        }

        public BigInteger decrypt(BigInteger c) {
            if (d == null) {
                throw new IllegalStateException("lolled hard !");
            }

            return c.modPow(d, n);
        }

        public BigInteger sig(BigInteger m) {
            return decrypt(m);
        }

        public BigInteger veri(BigInteger c) {
            return encrypt(c);
        }
    }
}
