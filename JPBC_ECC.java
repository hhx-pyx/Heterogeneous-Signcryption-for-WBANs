import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

public class JPBC_ECC {
    public static void main(String[] args) {
//        System.out.println("======== 纯 ECC 曲线性能测试（非配对友好曲线） ========");

        // 测试 192-bit 曲线
        testECC192();

//        System.out.println("\n======================================");
    }

    private static void testECC192() {
//        System.out.println("\n--- secp192r1 (192-bit, 96-bit 安全等级) ---");

        ECNamedCurveParameterSpec spec = ECNamedCurveTable.getParameterSpec("secp192r1");
        ECCurve curve = spec.getCurve();
        ECPoint G = spec.getG();
        BigInteger n = spec.getN();

//        System.out.println("曲线名称: secp192r1 (NIST P-192)");
//        System.out.println("阶 n 长度: " + n.bitLength() + " bits");
//        System.out.println("安全等级: 96 bits");

        SecureRandom random = new SecureRandom();
        BigInteger d = new BigInteger(n.bitLength() - 1, random);
        ECPoint Q = G.multiply(d).normalize();

        int num = 1000;

        // ==================== 1. ECC 标量乘法 ====================
        long totalScalarMul = 0;

        // JIT 预热
        for (int i = 0; i < 100; i++) {
            BigInteger k = new BigInteger(n.bitLength() - 1, random);
            Q.multiply(k).normalize();
        }

        // 正式计时
        for (int i = 0; i < num; i++) {
            BigInteger k = new BigInteger(n.bitLength() - 1, random);
            long start = System.nanoTime();
            ECPoint R = Q.multiply(k).normalize();
            long end = System.nanoTime();
            totalScalarMul += (end - start);
        }

        double avgScalarMul = totalScalarMul / 1e6 / num;
        System.out.println("A ECC-Based Scalar Multiplication Operation: " + avgScalarMul + " ms");

        // ==================== 2. ECC 点加法 ====================
        long totalPointAdd = 0;

        BigInteger[] kArray = new BigInteger[num];
        BigInteger[] lArray = new BigInteger[num];
        ECPoint[] kQArray = new ECPoint[num];
        ECPoint[] lQArray = new ECPoint[num];

        // 预生成所有标量和点
        for (int i = 0; i < num; i++) {
            kArray[i] = new BigInteger(n.bitLength() - 1, random);
            lArray[i] = new BigInteger(n.bitLength() - 1, random);
            kQArray[i] = Q.multiply(kArray[i]).normalize();
            lQArray[i] = Q.multiply(lArray[i]).normalize();
        }

        // 正式计时
        for (int i = 0; i < num; i++) {
            long start = System.nanoTime();
            ECPoint R = kQArray[i].add(lQArray[i]).normalize();
            long end = System.nanoTime();
            totalPointAdd += (end - start);
        }

        double avgPointAdd = totalPointAdd / 1e6 / num;
        System.out.println("A ECC-Based Point Addition Operation: " + avgPointAdd + " ms");

        // ==================== 3. Hash 到 Zr 元素 ====================
        String input = "This is my project! Thank you for watching!";
        long totalHash = 0;

        for (int i = 0; i < num; i++) {
            long start = System.nanoTime();
            String hashResult = getSHA256Hash(input);
            byte[] hashBytes = hashResult.getBytes();

            // 将 Hash 值转换为 Zr 元素（对 n 取模）
            BigInteger hashValue = new BigInteger(1, hashBytes).mod(n);
            long end = System.nanoTime();
            totalHash += (end - start);
        }

        double avgHash = totalHash / 1e6 / num;
        System.out.println("A Hash to Zr Element Operation: " + avgHash + " ms");

        System.out.println("\n--- 测试完成 ---");
    }

    // SHA-256 哈希函数
    public static String getSHA256Hash(String input) {
        try {
            MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
            byte[] hash = sha256.digest(input.getBytes("UTF-8"));
            StringBuilder hexString = new StringBuilder();
            for (byte b : hash) {
                String hex = Integer.toHexString(0xff & b);
                if (hex.length() == 1) {
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
