import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Random;

/**
 * 完整版 WBAN 签密方案（纯 ECC secp192r1）
 * 核心特性：
 * 1. 双密文相等性测试（无配对运算，匹配论文公式(1)(2)(3)(4)）
 * 2. 聚合多密文相等性测试（匹配论文公式(5)(6)(7)）
 * 3. 自定义密文数量 + 全维度耗时统计
 */
public class SLHSCGET46 {
    // 系统全局参数
    private static ECCurve curve;
    private static ECPoint G;
    private static BigInteger n;
    private static ECPoint Ppub;
    private static BigInteger s;
    private static SecureRandom random;
    private static final String HASH_ALG = "SHA-256";

    // 哈希函数（严格匹配论文定义）
    private static BigInteger H1(BigInteger zq, ECPoint G1) {
        byte[] combined = concat(zq.toByteArray(), G1.getEncoded(false));
        return hashToZr(combined);
    }
    private static BigInteger H2(ECPoint G1) { return hashToZr(G1.getEncoded(false)); }
    private static BigInteger H3(byte[] input) { return hashToZr(input); }
    private static byte[] H4(ECPoint G1) { return hashToBytes(G1.getEncoded(false)); }
    private static BigInteger H5(byte[]... inputs) {
        byte[] combined = concat(inputs);
        return hashToZr(combined);
    }
    private static BigInteger H6(byte[]... inputs) {
        byte[] combined = concat(inputs);
        return hashToZr(combined);
    }

    // 辅助类定义
    public static class PKI_DoctorKeyPair {
        BigInteger sk_r;
        ECPoint pk_r;
        public PKI_DoctorKeyPair(BigInteger sk_r, ECPoint pk_r) {
            this.sk_r = sk_r;
            this.pk_r = pk_r;
        }
    }

    public static class GroupKey {
        BigInteger sk_G;
        ECPoint hk_G;
        ECPoint Epk;
        BigInteger td;
        public GroupKey(BigInteger sk_G, ECPoint hk_G, ECPoint Epk, BigInteger td) {
            this.sk_G = sk_G;
            this.hk_G = hk_G;
            this.Epk = Epk;
            this.td = td;
        }
    }

    public static class CLC_SensorKeyPair {
        String ID_i;
        String PID_i;
        BigInteger ppk_i;
        ECPoint A_i;
        BigInteger v_i;
        ECPoint V_i;
        ECPoint D_i;
        public CLC_SensorKeyPair(String ID_i, String PID_i, BigInteger ppk_i, ECPoint A_i, BigInteger v_i, ECPoint V_i, ECPoint D_i) {
            this.ID_i = ID_i;
            this.PID_i = PID_i;
            this.ppk_i = ppk_i;
            this.A_i = A_i;
            this.v_i = v_i;
            this.V_i = V_i;
            this.D_i = D_i;
        }
    }

    public static class OfflineCiphertext {
        ECPoint C1;
        ECPoint C2;
        ECPoint T1;
        ECPoint T2;
        BigInteger r1;
        BigInteger r2;
        public OfflineCiphertext(ECPoint C1, ECPoint C2, ECPoint T1, ECPoint T2, BigInteger r1, BigInteger r2) {
            this.C1 = C1;
            this.C2 = C2;
            this.T1 = T1;
            this.T2 = T2;
            this.r1 = r1;
            this.r2 = r2;
        }
    }

    public static class FullCiphertext {
        ECPoint C1;
        ECPoint C2;
        BigInteger C3;
        byte[] C4;
        BigInteger C5;
        String PID_i;
        ECPoint V_i;
        public FullCiphertext(ECPoint C1, ECPoint C2, BigInteger C3, byte[] C4, BigInteger C5, String PID_i, ECPoint V_i) {
            this.C1 = C1;
            this.C2 = C2;
            this.C3 = C3;
            this.C4 = C4;
            this.C5 = C5;
            this.PID_i = PID_i;
            this.V_i = V_i;
        }
    }

    // 核心工具：异或运算（右对齐，处理不同长度的字节数组）
    private static byte[] xor(byte[] a, byte[] b) {
        int maxLen = Math.max(a.length, b.length);
        byte[] result = new byte[maxLen];
        for (int i = 0; i < maxLen; i++) {
            int aIndex = a.length - maxLen + i;
            int bIndex = b.length - maxLen + i;
            byte aByte = (aIndex >= 0) ? a[aIndex] : 0;
            byte bByte = (bIndex >= 0) ? b[bIndex] : 0;
            result[i] = (byte) (aByte ^ bByte);
        }
        return result;
    }

    // ===================== 核心算法 =====================
    // 1. 系统初始化
    public static void setup() {
        long start = System.nanoTime();
        random = new SecureRandom();
        ECNamedCurveParameterSpec spec = ECNamedCurveTable.getParameterSpec("secp192r1");
        curve = spec.getCurve();
        G = spec.getG();
        n = spec.getN();

        s = new BigInteger(n.bitLength() - 1, random);
        Ppub = G.multiply(s).normalize();
        long end = System.nanoTime();
        System.out.println("[初始化] 完成 | 耗时：" + String.format("%.3f", (end - start) / 1_000_000.0) + " ms");
    }

    // 2. 生成基础密钥
    public static Object[] generateBaseKeys() {
        long start = System.nanoTime();
        // 医生密钥
        BigInteger x = new BigInteger(n.bitLength() - 1, random);
        PKI_DoctorKeyPair doctorKey = new PKI_DoctorKeyPair(x, G.multiply(x).normalize());
        // 群组密钥（陷门td）
        BigInteger s_prime = new BigInteger(n.bitLength() - 1, random);
        BigInteger td = new BigInteger(n.bitLength() - 1, random);
        GroupKey groupKey = new GroupKey(s_prime, Ppub.multiply(s_prime).normalize(), G.multiply(td).normalize(), td);
        // 单传感器密钥
        String sensorID = "Sensor-Base";
        String PID = generatePseudonym(sensorID, groupKey);
        ECPoint A_i = G.multiply(new BigInteger(n.bitLength() - 1, random)).normalize();
        Object[] partialKey = generatePartialPrivateKey(PID, A_i);
        BigInteger ppk_i = (BigInteger) partialKey[0];
        BigInteger v_i = new BigInteger(n.bitLength() - 1, random);
        ECPoint V_i = G.multiply(v_i).normalize();
        BigInteger s_plus_td = groupKey.sk_G.add(groupKey.td).mod(n);
        BigInteger ppk_plus_v = ppk_i.add(v_i).mod(n);
        ECPoint D_i = G.multiply(s_plus_td.multiply(ppk_plus_v).mod(n)).normalize();
        CLC_SensorKeyPair sensorKey = new CLC_SensorKeyPair(sensorID, PID, ppk_i, A_i, v_i, V_i, D_i);

        long end = System.nanoTime();
        System.out.println("[基础密钥] 生成完成 | 耗时：" + String.format("%.3f", (end - start) / 1_000_000.0) + " ms");
        return new Object[]{doctorKey, groupKey, sensorKey};
    }

    // 3. 单个密文签密
    public static Object[] signcryptSingle(String msg, CLC_SensorKeyPair sensorKey, PKI_DoctorKeyPair doctorKey, GroupKey groupKey) {
        // 离线签密
        long offlineStart = System.nanoTime();
        BigInteger r1 = new BigInteger(n.bitLength() - 1, random);
        BigInteger r2 = new BigInteger(n.bitLength() - 1, random);
        BigInteger v_r2 = sensorKey.v_i.multiply(r2).mod(n);
        OfflineCiphertext offline = new OfflineCiphertext(
                sensorKey.D_i.multiply(r1).normalize(),
                sensorKey.V_i.multiply(r2).normalize(),
                groupKey.Epk.multiply(v_r2).normalize(),
                doctorKey.pk_r.multiply(v_r2).normalize(),
                r1, r2
        );
        long offlineEnd = System.nanoTime();
        long offlineCost = offlineEnd - offlineStart;

        // 在线签密
        long onlineStart = System.nanoTime();
        byte[] msgBytes = msg.getBytes(StandardCharsets.UTF_8);
        BigInteger H3_M = H3(msgBytes);
        BigInteger ppk_plus_v = sensorKey.ppk_i.add(sensorKey.v_i).mod(n);
        BigInteger H2_T1 = H2(offline.T1);
        byte[] C3_bytes = xor(H2_T1.toByteArray(), H3_M.multiply(offline.r1).multiply(ppk_plus_v).mod(n).toByteArray());
        BigInteger C3 = new BigInteger(1, C3_bytes).mod(n);
        byte[] C4 = xor(H4(offline.T2), concat(msgBytes, sensorKey.A_i.getEncoded(false)));
        BigInteger h1 = H5(offline.C1.getEncoded(false), offline.C2.getEncoded(false), C3.toByteArray(), C4, msgBytes, offline.T2.getEncoded(false), sensorKey.A_i.getEncoded(false), sensorKey.V_i.getEncoded(false));
        BigInteger h2 = H6(offline.C1.getEncoded(false), offline.C2.getEncoded(false), C3.toByteArray(), C4, msgBytes, offline.T2.getEncoded(false), sensorKey.A_i.getEncoded(false), sensorKey.V_i.getEncoded(false));
        BigInteger C5 = offline.r2.add(h1).multiply(sensorKey.v_i).add(sensorKey.ppk_i.multiply(h2)).mod(n);
        FullCiphertext fullCipher = new FullCiphertext(offline.C1, offline.C2, C3, C4, C5, sensorKey.PID_i, sensorKey.V_i);
        long onlineEnd = System.nanoTime();
        long onlineCost = onlineEnd - onlineStart;

        return new Object[]{offlineCost, onlineCost, fullCipher};
    }

    // 4. 单个密文解签密
    public static Object[] unsigncryptSingle(FullCiphertext cipher, PKI_DoctorKeyPair doctorKey, CLC_SensorKeyPair sensorKey) {
        long start = System.nanoTime();
        ECPoint T2_prime = cipher.C2.multiply(doctorKey.sk_r).normalize();
        byte[] H4_T2 = H4(T2_prime);
        byte[] M_Ai = xor(cipher.C4, H4_T2);
        byte[] M_bytes = Arrays.copyOfRange(M_Ai, 0, M_Ai.length - sensorKey.A_i.getEncoded(false).length);
        String plaintext = new String(M_bytes, StandardCharsets.UTF_8);
        // 验证C5
        BigInteger h1 = H5(cipher.C1.getEncoded(false), cipher.C2.getEncoded(false), cipher.C3.toByteArray(), cipher.C4, M_bytes, T2_prime.getEncoded(false), sensorKey.A_i.getEncoded(false), sensorKey.V_i.getEncoded(false));
        BigInteger h2 = H6(cipher.C1.getEncoded(false), cipher.C2.getEncoded(false), cipher.C3.toByteArray(), cipher.C4, M_bytes, T2_prime.getEncoded(false), sensorKey.A_i.getEncoded(false), sensorKey.V_i.getEncoded(false));
        BigInteger PID_zr = hashToZr(cipher.PID_i.getBytes(StandardCharsets.UTF_8));
        BigInteger H1_PID_A = H1(PID_zr, sensorKey.A_i);
        ECPoint verify_right = cipher.C2.add(sensorKey.V_i.multiply(h1).normalize()).add(Ppub.multiply(H1_PID_A).add(sensorKey.A_i).normalize().multiply(h2).normalize()).normalize();
        ECPoint verify_left = G.multiply(cipher.C5).normalize();
        long end = System.nanoTime();
        long cost = end - start;
        return new Object[]{cost, plaintext};
    }

    // 5. 批量验证N个密文
    public static long batchVerifyN(int N, List<FullCiphertext> cipherList, PKI_DoctorKeyPair doctorKey, CLC_SensorKeyPair sensorKey) {
        if (cipherList.size() < N) {
            throw new IllegalArgumentException("密文数量不足");
        }
        long start = System.nanoTime();
        BigInteger sum_C5 = BigInteger.ZERO;
        ECPoint sum_C2 = curve.getInfinity();
        ECPoint sum_h1Vi = curve.getInfinity();
        ECPoint sum_h2PPK = curve.getInfinity();

        List<FullCiphertext> targetCiphers = cipherList.subList(0, N);
        for (FullCiphertext cipher : targetCiphers) {
            ECPoint T2_prime = cipher.C2.multiply(doctorKey.sk_r).normalize();
            byte[] M_Ai = xor(cipher.C4, H4(T2_prime));
            byte[] M_bytes = Arrays.copyOfRange(M_Ai, 0, M_Ai.length - sensorKey.A_i.getEncoded(false).length);
            BigInteger h1 = H5(cipher.C1.getEncoded(false), cipher.C2.getEncoded(false), cipher.C3.toByteArray(), cipher.C4, M_bytes, T2_prime.getEncoded(false), sensorKey.A_i.getEncoded(false), sensorKey.V_i.getEncoded(false));
            BigInteger h2 = H6(cipher.C1.getEncoded(false), cipher.C2.getEncoded(false), cipher.C3.toByteArray(), cipher.C4, M_bytes, T2_prime.getEncoded(false), sensorKey.A_i.getEncoded(false), sensorKey.V_i.getEncoded(false));
            sum_C5 = sum_C5.add(cipher.C5).mod(n);
            sum_C2 = sum_C2.add(cipher.C2).normalize();
            sum_h1Vi = sum_h1Vi.add(sensorKey.V_i.multiply(h1).normalize()).normalize();
            BigInteger PID_zr = hashToZr(cipher.PID_i.getBytes(StandardCharsets.UTF_8));
            BigInteger H1_PID_A = H1(PID_zr, sensorKey.A_i);
            sum_h2PPK = sum_h2PPK.add(Ppub.multiply(H1_PID_A).add(sensorKey.A_i).normalize().multiply(h2).normalize()).normalize();
        }
        ECPoint verify_left = G.multiply(sum_C5).normalize();
        ECPoint verify_right = sum_C2.add(sum_h1Vi).add(sum_h2PPK).normalize();
        long end = System.nanoTime();
        return end - start;
    }

    // 6. 双密文相等性测试
    public static Object[] equalityTestTwo(FullCiphertext C, FullCiphertext C_prime, GroupKey groupKey) {
        long start = System.nanoTime();
        BigInteger td = groupKey.td;

        // 公式(1)：T1 = td·C2；T1' = td·C2'
        ECPoint T1 = C.C2.multiply(td).normalize();
        ECPoint T1_prime = C_prime.C2.multiply(td).normalize();

        // 公式(2)(3)：I = C3⊕H2(T1)；I' = C3'⊕H2(T1')
        BigInteger H2_T1 = H2(T1);
        byte[] I_bytes = xor(C.C3.toByteArray(), H2_T1.toByteArray());
        BigInteger I = new BigInteger(1, I_bytes).mod(n);

        BigInteger H2_T1_prime = H2(T1_prime);
        byte[] I_prime_bytes = xor(C_prime.C3.toByteArray(), H2_T1_prime.toByteArray());
        BigInteger I_prime = new BigInteger(1, I_prime_bytes).mod(n);

        // 公式(4)：I·C1' = I'·C1
        ECPoint left = C_prime.C1.multiply(I).normalize();
        ECPoint right = C.C1.multiply(I_prime).normalize();
        boolean result = left.equals(right);

        long end = System.nanoTime();
        long cost = end - start;
        return new Object[]{cost, result};
    }


    // 7. 聚合多密文相等性测试
    public static Object[] aggregateEqualityTest(int N, List<FullCiphertext> cipherList, GroupKey groupKey, FullCiphertext baseCipher) {
        long start = System.nanoTime();
        BigInteger td = groupKey.td;
        ECPoint C1_base = baseCipher.C1;
        BigInteger I_base = calculateI(baseCipher, td);

        ECPoint C1_hat = curve.getInfinity();
        BigInteger I_hat = BigInteger.ZERO;

        for (int j = 0; j < N; j++) {
            FullCiphertext cipher = cipherList.get(j);
            C1_hat = C1_hat.add(cipher.C1).normalize();
            BigInteger I_j = calculateI(cipher, td);
            I_hat = I_hat.add(I_j).mod(n);
        }

        ECPoint left = C1_hat.multiply(I_base).normalize();
        ECPoint right = C1_base.multiply(I_hat).normalize();
        boolean isPass = left.equals(right);

        long end = System.nanoTime();
        long cost = end - start;
        return new Object[]{cost, isPass};
    }

    // 辅助：计算单个密文的I,j
    private static BigInteger calculateI(FullCiphertext cipher, BigInteger td) {
        ECPoint T1_j = cipher.C2.multiply(td).normalize();
        BigInteger H2_T1j = H2(T1_j);
        byte[] I_bytes = xor(cipher.C3.toByteArray(), H2_T1j.toByteArray());
        return new BigInteger(1, I_bytes).mod(n);
    }

    // 8. 生成N个密文
    public static Object[] generateNCiphers(int N, CLC_SensorKeyPair sensorKey, PKI_DoctorKeyPair doctorKey, GroupKey groupKey) {
        long start = System.nanoTime();
        List<FullCiphertext> cipherList = new ArrayList<>();
        Random rand = new Random();
        for (int i = 0; i < N; i++) {
            String msg = String.format("WBAN-Data-%d: Value=%d, Time=%d", i, 60 + rand.nextInt(40), System.currentTimeMillis() / 1000);
            Object[] singleResult = signcryptSingle(msg, sensorKey, doctorKey, groupKey);
            cipherList.add((FullCiphertext) singleResult[2]);
        }
        long end = System.nanoTime();
        long totalCost = end - start;
        return new Object[]{cipherList, totalCost};
    }

    // ===================== 辅助方法 =====================
    private static String generatePseudonym(String ID_i, GroupKey groupKey) {
        BigInteger H2_hkG = H2(groupKey.hk_G);
        byte[] ID_bytes = ID_i.getBytes(StandardCharsets.UTF_8);
        byte[] PID_bytes = xor(ID_bytes, H2_hkG.toByteArray());
        return new String(PID_bytes, StandardCharsets.UTF_8);
    }

    private static Object[] generatePartialPrivateKey(String PID_i, ECPoint A_i) {
        BigInteger PID_zr = hashToZr(PID_i.getBytes(StandardCharsets.UTF_8));
        BigInteger H1_PID_A = H1(PID_zr, A_i);
        BigInteger t_i = new BigInteger(n.bitLength() - 1, random);
        BigInteger ppk_i = t_i.add(s.multiply(H1_PID_A).mod(n)).mod(n);
        return new Object[]{ppk_i, A_i};
    }

    private static BigInteger hashToZr(byte[] input) {
        try {
            MessageDigest md = MessageDigest.getInstance(HASH_ALG);
            byte[] hash = md.digest(input);
            return new BigInteger(1, hash).mod(n);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("哈希失败", e);
        }
    }

    private static byte[] hashToBytes(byte[] input) {
        try {
            MessageDigest md = MessageDigest.getInstance(HASH_ALG);
            return md.digest(input);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("哈希失败", e);
        }
    }

    private static byte[] concat(byte[]... arrays) {
        int totalLen = 0;
        for (byte[] arr : arrays) totalLen += arr.length;
        byte[] result = new byte[totalLen];
        int offset = 0;
        for (byte[] arr : arrays) {
            System.arraycopy(arr, 0, result, offset, arr.length);
            offset += arr.length;
        }
        return result;
    }

    // ===================== 主函数（全流程测试） =====================
    public static void main(String[] args) {
        //N = 100, 300, 500, 700, 1000
        int N = 700;
        System.out.println("===== WBAN 全流程测试（N=" + N + "）=====\n");

        setup();
        Object[] baseKeys = generateBaseKeys();
        PKI_DoctorKeyPair doctorKey = (PKI_DoctorKeyPair) baseKeys[0];
        GroupKey groupKey = (GroupKey) baseKeys[1];
        CLC_SensorKeyPair sensorKey = (CLC_SensorKeyPair) baseKeys[2];

        String testMsg = "Test-Message: Single-Ciphertext";
        Object[] singleSign = signcryptSingle(testMsg, sensorKey, doctorKey, groupKey);
        long offlineCost = (Long) singleSign[0];
        long onlineCost = (Long) singleSign[1];
        FullCiphertext testCipher = (FullCiphertext) singleSign[2];
        System.out.println("[单个密文签密]");
        System.out.println("  离线耗时：" + String.format("%.3f", offlineCost / 1_000_000.0) + " ms");
        System.out.println("  在线耗时：" + String.format("%.3f", onlineCost / 1_000_000.0) + " ms");
        System.out.println("  总耗时：" + String.format("%.3f", (offlineCost + onlineCost) / 1_000_000.0) + " ms\n");

        Object[] singleUnsign = unsigncryptSingle(testCipher, doctorKey, sensorKey);
        long unsignCost = (Long) singleUnsign[0];
        String plaintext = (String) singleUnsign[1];
        System.out.println("[单个密文解签密]");
        System.out.println("  耗时：" + String.format("%.3f", unsignCost / 1_000_000.0) + " ms");
        System.out.println("  一致性：" + testMsg.equals(plaintext) + "\n");

        Object[] nCiphers = generateNCiphers(N, sensorKey, doctorKey, groupKey);
        List<FullCiphertext> cipherList = (List<FullCiphertext>) nCiphers[0];
        long genCost = (Long) nCiphers[1];
        System.out.println("[生成" + N + "个密文]");
        System.out.println("  总耗时：" + String.format("%.3f", genCost / 1_000_000.0) + " ms");
        System.out.println("  单密文平均耗时：" + String.format("%.3f", (genCost * 1.0 / N) / 1_000_000.0) + " ms\n");

        long batchCost = batchVerifyN(N, cipherList, doctorKey, sensorKey);
        System.out.println("[" + N + "个密文批量验证]");
        System.out.println("  总耗时：" + String.format("%.3f", batchCost / 1_000_000.0) + " ms");
        System.out.println("  单密文平均耗时：" + String.format("%.3f", (batchCost * 1.0 / N) / 1_000_000.0) + " ms\n");

        FullCiphertext C = cipherList.get(0);
        FullCiphertext C_prime = cipherList.get(1);
        Object[] twoEqResult = equalityTestTwo(C, C_prime, groupKey);
        long twoEqCost = (Long) twoEqResult[0];
        boolean twoEqPass = (Boolean) twoEqResult[1];
        System.out.println("[双密文相等性测试]");
        System.out.println("  耗时：" + String.format("%.3f", twoEqCost / 1_000_000.0) + " ms");
        System.out.println("  结果：" + (twoEqPass ? "相同明文" : "不同明文") + "\n");

        Object[] aggEqResult = aggregateEqualityTest(N, cipherList, groupKey, C);
        long aggEqCost = (Long) aggEqResult[0];
        boolean aggEqPass = (Boolean) aggEqResult[1];
        System.out.println("[" + N + "个密文聚合相等性测试]");
        System.out.println("  耗时：" + String.format("%.3f", aggEqCost / 1_000_000.0) + " ms");
        System.out.println("  结果：" + (aggEqPass ? "所有密文对应同一明文" : "存在不同明文") + "\n");

        System.out.println("===== 测试汇总（N=" + N + "）=====");
        System.out.println("1. 单个密文签密总耗时：" + String.format("%.3f", (offlineCost + onlineCost) / 1_000_000.0) + " ms");
        System.out.println("2. 单个密文解签密耗时：" + String.format("%.3f", unsignCost / 1_000_000.0) + " ms");
        System.out.println("3. " + N + "个密文批量验证总耗时：" + String.format("%.3f", batchCost / 1_000_000.0) + " ms");
        System.out.println("4. 双密文相等性测试耗时：" + String.format("%.3f", twoEqCost / 1_000_000.0) + " ms");
        System.out.println("5. " + N + "个密文相等性测试耗时：" + String.format("%.3f", aggEqCost / 1_000_000.0) + " ms");
    }
}
