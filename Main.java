import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.Field;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.a.TypeACurveGenerator;
import java.util.Random;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class Main {
    public static void main(String[] args) {
        double num = 1000;
        double time = 0;
//        Pairing bp = PairingFactory.getPairing("a.properties");

        int r1Bit = 192;
        int q1Bit = 512;
        TypeACurveGenerator pg1 = new TypeACurveGenerator(r1Bit,q1Bit);
        PairingParameters pp1 = pg1.generate();
        Pairing bp = PairingFactory.getPairing(pp1);

        Field G1 = bp.getG1();
        Field Zr = bp.getZr();
        Element P1 = G1.newRandomElement().getImmutable();


        for (int i = 0; i < num; i++) {
            double start = System.currentTimeMillis();
            Element Q = bp.pairing(P1,P1).getImmutable();
            double end = System.currentTimeMillis();
            time += end - start;
        }
        System.out.println("The average times after " + (int)num + " tests");
        System.out.println("A Bilinear Pairing Operation: " + time/num + " ms");

        time = 0;
        Element sP1;
        for (int i = 0; i < num; i++) {
            Element s1 = Zr.newRandomElement().getImmutable();
            double start = System.currentTimeMillis();
            sP1 = P1.mulZn(s1).getImmutable();
//            System.out.println("双线性对中s1大小: " +s1.toBytes().length);
//            System.out.println("双线性对中sp1大小: " +sP1.toBytes().length);
            double end = System.currentTimeMillis();
            time += end - start;
        }
        System.out.println("A Pairing-Based Scalar Multiplication Operation on G1: " + time/num + " ms");



//        double timeG1 = 0;
//        for (int i = 0; i < num; i++) {
//            Element s = Zr.newRandomElement().getImmutable();
//            double start = System.currentTimeMillis();
//            Element resultG1 = P1.mulZn(s).getImmutable();
//            double end = System.currentTimeMillis();
//            timeG1 += end - start;
//        }
//        System.out.println("G1 上的标量乘操作平均时间: " + timeG1 / num + " ms");



        double timeG2 = 0;
        for (int i = 0; i < num; i++) {
            Element t = Zr.newRandomElement().getImmutable();
            Element Q2 = bp.pairing(P1,P1).getImmutable();
            double start = System.currentTimeMillis();
            Element resultG2 = Q2.mulZn(t).getImmutable();
            double end = System.currentTimeMillis();
            timeG2 += end - start;
        }
        System.out.println("A Pairing-Based Scalar Multiplication Operation on G2: " + timeG2 / num + " ms");


        time = 0;
        Element A1;
        for (int i = 0; i < num; i++) {
            Element a = Zr.newRandomElement().getImmutable();
            Element b = Zr.newRandomElement().getImmutable();
            Element a1P = P1.mulZn(a);
            Element b1P = P1.mulZn(b);
            double start = System.currentTimeMillis();
            A1 = a1P.add(b1P).getImmutable();
            double end = System.currentTimeMillis();
            time += end - start;
        }
        System.out.println("A Pairing-Based Point Addition Operation: " + time/num + " ms");



        String input1 = "This is my project! Thank you for watching!";
        time=0;
        for (int i = 0; i < num; i++) {
            double start = System.currentTimeMillis();
            String result = getSHA256Hash(input1);
            byte[] bytes = result.getBytes();
            G1.newRandomElement().setFromHash(bytes, 0, bytes.length);
            double end = System.currentTimeMillis();
            time += end - start;
        }
        System.out.println("A Map-To-Point Hash Function Operation: " + time/num + " ms");




        int rBit = 192;
        int qBit = 192;
        TypeACurveGenerator pg = new TypeACurveGenerator(rBit,qBit);
        PairingParameters pp = pg.generate();
        Pairing np = PairingFactory.getPairing(pp);

        Field G = np.getG1();
        Field Zq = np.getZr();

        Element P = G.newRandomElement().getImmutable();
        Element smP;
        time = 0;
        for (int i = 0; i < num; i++) {
            Element s = Zq.newRandomElement().getImmutable();
            double start = System.currentTimeMillis();
            smP = P.mulZn(s).getImmutable();
            double end = System.currentTimeMillis();
            time += end - start;
//            System.out.println("S大小: " + s.toBytes().length );

        }
//        System.out.println("P大小: " + P.toBytes().length );
        System.out.println("A ECC-Based Scalar Multiplication Operation: " + time/num + " ms");

        time = 0;
        Element A;
        for (int i = 0; i < num; i++) {
            Element a = Zr.newRandomElement().getImmutable();
            Element b = Zr.newRandomElement().getImmutable();
            Element aP = P.mulZn(a);
            Element bP = P.mulZn(b);
            double start = System.currentTimeMillis();
            A = aP.add(bP).getImmutable();
            double end = System.currentTimeMillis();
            time += end - start;
        }
        System.out.println("A ECC-Based Point Addition Operation: " + time/num + " ms");

        time = 0;
        Element ssmP;
        Random random = new Random();
        for (int i = 0; i < num; i++) {
            int rn = random.nextInt(2^80);
            double start = System.currentTimeMillis();
            ssmP = P.mul(BigInteger.valueOf(rn)).getImmutable();
            double end = System.currentTimeMillis();
            time += end - start;
        }
        System.out.println("A ECC-Based Small Scalar Multiplication Operation: " + time/num + " ms");

        //hash function
//        String input2 = "This is my project! Thank you for watching!";
//        long time1 = 0; // Changed from long time=0;
//        for (int i = 0; i < num; i++) {
//            long start = System.currentTimeMillis();
//            String result = getSHA256Hash(input2);
//            long end = System.currentTimeMillis();
//            time += end - start;
//        }
//        System.out.println("A Hash Function Operation: " + time/num + " ms");
        //hash function
        String input2 = "This is my project! Thank you for watching!";
        long time1 = 0;
        for (int i = 0; i < num; i++) {
            long start = System.nanoTime(); // 使用 nanoTime 获取高精度时间
            String result = getSHA256Hash(input2);
            long end = System.nanoTime();
            time1 += (end - start); // 累加纳秒级时间差
        }
        // 将总时间转换为毫秒并计算平均值
        double avgTime = (double) time1 / num / 1_000_000; // 转换为毫秒
        System.out.println("A Hash Function Operation: " + String.format("%.3f", avgTime) + " ms");



    }
    public static String getSHA256Hash(String input) {
        try {
            MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
            byte[] hash = sha256.digest(input.getBytes("UTF-8"));
            StringBuilder hexString = new StringBuilder();
            for (byte b : hash) {
                String hex = Integer.toHexString(0xff & b);
                if(hex.length() == 1) {
                    hexString.append('0');
                }
                hexString.append(hex);
            }
            return hexString.toString();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}