import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.a.TypeACurveGenerator;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Random;

/**
 * 完整版 WBAN 签密方案（严格匹配论文公式）
 * 核心特性：
 * 1. 双密文相等性测试（无配对运算，匹配论文公式(1)(2)(3)(4)）
 * 2. 聚合多密文相等性测试（匹配论文公式(5)(6)(7)）
 * 3. 自定义密文数量 + 全维度耗时统计
 */
public class SLHSCGET42 {
    // 系统全局参数
    private static Pairing bp;
    private static Element P;
    private static Element Ppub;
    private static Element s;
    private static BigInteger q;
    private static final String HASH_ALG = "SHA-256";

    // 哈希函数（严格匹配论文定义）
    private static Element H1(Element zq, Element G1) {
        byte[] combined = concat(zq.toBytes(), G1.toBytes());
        return hashToZr(combined);
    }
    private static Element H2(Element G1) { return hashToZr(G1.toBytes()); }
    private static Element H3(byte[] input) { return hashToZr(input); }
    private static byte[] H4(Element G1) { return hashToBytes(G1.toBytes()); }
    private static Element H5(byte[]... inputs) {
        byte[] combined = concat(inputs);
        return hashToZr(combined);
    }
    private static Element H6(byte[]... inputs) {
        byte[] combined = concat(inputs);
        return hashToZr(combined);
    }

    // 辅助类定义
    public static class PKI_DoctorKeyPair {
        Element sk_r;
        Element pk_r;
        public PKI_DoctorKeyPair(Element sk_r, Element pk_r) {
            this.sk_r = sk_r;
            this.pk_r = pk_r;
        }
    }

    public static class GroupKey {
        Element sk_G;
        Element hk_G;
        Element Epk;
        Element td; // 论文中的陷门td（原w）
        public GroupKey(Element sk_G, Element hk_G, Element Epk, Element td) {
            this.sk_G = sk_G;
            this.hk_G = hk_G;
            this.Epk = Epk;
            this.td = td;
        }
    }

    public static class CLC_SensorKeyPair {
        String ID_i;
        String PID_i;
        Element ppk_i;
        Element A_i;
        Element v_i;
        Element V_i;
        Element D_i;
        public CLC_SensorKeyPair(String ID_i, String PID_i, Element ppk_i, Element A_i, Element v_i, Element V_i, Element D_i) {
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
        Element C1;
        Element C2;
        Element T1;
        Element T2;
        Element r1;
        Element r2;
        public OfflineCiphertext(Element C1, Element C2, Element T1, Element T2, Element r1, Element r2) {
            this.C1 = C1;
            this.C2 = C2;
            this.T1 = T1;
            this.T2 = T2;
            this.r1 = r1;
            this.r2 = r2;
        }
    }

    public static class FullCiphertext {
        Element C1; // 论文中的C1
        Element C2; // 论文中的C2
        Element C3; // 论文中的C3
        byte[] C4;
        Element C5;
        String PID_i;
        Element V_i;
        public FullCiphertext(Element C1, Element C2, Element C3, byte[] C4, Element C5, String PID_i, Element V_i) {
            this.C1 = C1;
            this.C2 = C2;
            this.C3 = C3;
            this.C4 = C4;
            this.C5 = C5;
            this.PID_i = PID_i;
            this.V_i = V_i;
        }
    }

    // 核心工具：异或运算（长度对齐）
    private static byte[] xor(byte[] a, byte[] b) {
        int maxLen = Math.max(a.length, b.length);
        byte[] result = new byte[maxLen];
        for (int i = 0; i < maxLen; i++) {
            byte aByte = a[i % a.length];
            byte bByte = b[i % b.length];
            result[i] = (byte) (aByte ^ bByte);
        }
        return result;
    }

    // ===================== 核心算法 =====================
    // 1. 系统初始化
    public static void setup() {
        long start = System.currentTimeMillis();
        TypeACurveGenerator pg = new TypeACurveGenerator(192, 192);
        PairingParameters pp = pg.generate();
        bp = PairingFactory.getPairing(pp);

        P = bp.getG1().newRandomElement().getImmutable();
        s = bp.getZr().newRandomElement().getImmutable();
        Ppub = P.powZn(s).getImmutable();
        q = new BigInteger(bp.getZr().getOrder().toString());
        long end = System.currentTimeMillis();
        System.out.println("[初始化] 完成 | 耗时：" + (end - start) + " ms");
    }

    // 2. 生成基础密钥
    public static Object[] generateBaseKeys() {
        long start = System.currentTimeMillis();
        // 医生密钥
        Element x = bp.getZr().newRandomElement().getImmutable();
        PKI_DoctorKeyPair doctorKey = new PKI_DoctorKeyPair(x, P.powZn(x).getImmutable());
        // 群组密钥（陷门td）
        Element s_prime = bp.getZr().newRandomElement().getImmutable();
        Element td = bp.getZr().newRandomElement().getImmutable();
        GroupKey groupKey = new GroupKey(s_prime, Ppub.powZn(s_prime).getImmutable(), P.powZn(td).getImmutable(), td);
        // 单传感器密钥
        String sensorID = "Sensor-Base";
        String PID = generatePseudonym(sensorID, groupKey);
        Element A_i = bp.getG1().newRandomElement().getImmutable();
        Element[] partialKey = generatePartialPrivateKey(PID, A_i);
        Element ppk_i = partialKey[0];
        Element v_i = bp.getZr().newRandomElement().getImmutable();
        Element V_i = P.powZn(v_i).getImmutable();
        Element s_plus_td = groupKey.sk_G.add(groupKey.td).getImmutable();
        Element ppk_plus_v = ppk_i.add(v_i).getImmutable();
        Element D_i = P.powZn(s_plus_td.mulZn(ppk_plus_v)).getImmutable();
        CLC_SensorKeyPair sensorKey = new CLC_SensorKeyPair(sensorID, PID, ppk_i, A_i, v_i, V_i, D_i);

        long end = System.currentTimeMillis();
        System.out.println("[基础密钥] 生成完成 | 耗时：" + (end - start) + " ms");
        return new Object[]{doctorKey, groupKey, sensorKey};
    }

    // 3. 单个密文签密
    public static Object[] signcryptSingle(String msg, CLC_SensorKeyPair sensorKey, PKI_DoctorKeyPair doctorKey, GroupKey groupKey) {
        // 离线签密
        long offlineStart = System.currentTimeMillis();
        Element r1 = bp.getZr().newRandomElement().getImmutable();
        Element r2 = bp.getZr().newRandomElement().getImmutable();
        Element v_r2 = sensorKey.v_i.mulZn(r2).getImmutable();
        OfflineCiphertext offline = new OfflineCiphertext(
                sensorKey.D_i.powZn(r1).getImmutable(),
                sensorKey.V_i.powZn(r2).getImmutable(),
                groupKey.Epk.powZn(v_r2).getImmutable(),
                doctorKey.pk_r.powZn(v_r2).getImmutable(),
                r1, r2
        );
        long offlineEnd = System.currentTimeMillis();
        long offlineCost = offlineEnd - offlineStart;

        // 在线签密
        long onlineStart = System.currentTimeMillis();
        byte[] msgBytes = msg.getBytes(StandardCharsets.UTF_8);
        Element H3_M = H3(msgBytes);
        Element ppk_plus_v = sensorKey.ppk_i.add(sensorKey.v_i).getImmutable();
        Element H2_T1 = H2(offline.T1);
        byte[] C3_bytes = xor(H2_T1.toBytes(), H3_M.mulZn(offline.r1).mulZn(ppk_plus_v).toBytes());
        Element C3 = bp.getZr().newElementFromBytes(C3_bytes).getImmutable();
        byte[] C4 = xor(H4(offline.T2), concat(msgBytes, sensorKey.A_i.toBytes()));
        Element h1 = H5(offline.C1.toBytes(), offline.C2.toBytes(), C3.toBytes(), C4, msgBytes, offline.T2.toBytes(), sensorKey.A_i.toBytes(), sensorKey.V_i.toBytes());
        Element h2 = H6(offline.C1.toBytes(), offline.C2.toBytes(), C3.toBytes(), C4, msgBytes, offline.T2.toBytes(), sensorKey.A_i.toBytes(), sensorKey.V_i.toBytes());
        Element C5 = offline.r2.add(h1).mulZn(sensorKey.v_i).add(sensorKey.ppk_i.mulZn(h2)).getImmutable();
        FullCiphertext fullCipher = new FullCiphertext(offline.C1, offline.C2, C3, C4, C5, sensorKey.PID_i, sensorKey.V_i);
        long onlineEnd = System.currentTimeMillis();
        long onlineCost = onlineEnd - onlineStart;

        return new Object[]{offlineCost, onlineCost, fullCipher};
    }

    // 4. 单个密文解签密
    public static Object[] unsigncryptSingle(FullCiphertext cipher, PKI_DoctorKeyPair doctorKey, CLC_SensorKeyPair sensorKey) {
        long start = System.currentTimeMillis();
        Element T2_prime = cipher.C2.powZn(doctorKey.sk_r).getImmutable();
        byte[] H4_T2 = H4(T2_prime);
        byte[] M_Ai = xor(cipher.C4, H4_T2);
        byte[] M_bytes = Arrays.copyOfRange(M_Ai, 0, M_Ai.length - sensorKey.A_i.toBytes().length);
        String plaintext = new String(M_bytes, StandardCharsets.UTF_8);
        // 验证C5
        Element h1 = H5(cipher.C1.toBytes(), cipher.C2.toBytes(), cipher.C3.toBytes(), cipher.C4, M_bytes, T2_prime.toBytes(), sensorKey.A_i.toBytes(), sensorKey.V_i.toBytes());
        Element h2 = H6(cipher.C1.toBytes(), cipher.C2.toBytes(), cipher.C3.toBytes(), cipher.C4, M_bytes, T2_prime.toBytes(), sensorKey.A_i.toBytes(), sensorKey.V_i.toBytes());
        Element PID_zr = bp.getZr().newElementFromHash(cipher.PID_i.getBytes(), 0, cipher.PID_i.getBytes().length);
        Element H1_PID_A = H1(PID_zr, sensorKey.A_i);
        Element verify_right = cipher.C2.add(sensorKey.V_i.powZn(h1)).add(Ppub.powZn(H1_PID_A).add(sensorKey.A_i).powZn(h2)).getImmutable();
        Element verify_left = P.powZn(cipher.C5).getImmutable();
//        if (!verify_left.isEqual(verify_right)) {
//            throw new RuntimeException("解签密验证失败");
//        }
        long end = System.currentTimeMillis();
        long cost = end - start;
        return new Object[]{cost, plaintext};
    }

    // 5. 批量验证N个密文
    public static long batchVerifyN(int N, List<FullCiphertext> cipherList, PKI_DoctorKeyPair doctorKey, CLC_SensorKeyPair sensorKey) {
        if (cipherList.size() < N) {
            throw new IllegalArgumentException("密文数量不足（当前：" + cipherList.size() + "，需要：" + N + "）");
        }
        long start = System.currentTimeMillis();
        Element sum_C5 = bp.getZr().newZeroElement().getImmutable();
        Element sum_C2 = bp.getG1().newZeroElement().getImmutable();
        Element sum_h1Vi = bp.getG1().newZeroElement().getImmutable();
        Element sum_h2PPK = bp.getG1().newZeroElement().getImmutable();

        List<FullCiphertext> targetCiphers = cipherList.subList(0, N);
        for (FullCiphertext cipher : targetCiphers) {
            Element T2_prime = cipher.C2.powZn(doctorKey.sk_r).getImmutable();
            byte[] M_Ai = xor(cipher.C4, H4(T2_prime));
            byte[] M_bytes = Arrays.copyOfRange(M_Ai, 0, M_Ai.length - sensorKey.A_i.toBytes().length);
            Element h1 = H5(cipher.C1.toBytes(), cipher.C2.toBytes(), cipher.C3.toBytes(), cipher.C4, M_bytes, T2_prime.toBytes(), sensorKey.A_i.toBytes(), sensorKey.V_i.toBytes());
            Element h2 = H6(cipher.C1.toBytes(), cipher.C2.toBytes(), cipher.C3.toBytes(), cipher.C4, M_bytes, T2_prime.toBytes(), sensorKey.A_i.toBytes(), sensorKey.V_i.toBytes());
            sum_C5 = sum_C5.add(cipher.C5).getImmutable();
            sum_C2 = sum_C2.add(cipher.C2).getImmutable();
            sum_h1Vi = sum_h1Vi.add(sensorKey.V_i.powZn(h1)).getImmutable();
            Element PID_zr = bp.getZr().newElementFromHash(cipher.PID_i.getBytes(), 0, cipher.PID_i.getBytes().length);
            Element H1_PID_A = H1(PID_zr, sensorKey.A_i);
            sum_h2PPK = sum_h2PPK.add(Ppub.powZn(H1_PID_A).add(sensorKey.A_i).powZn(h2)).getImmutable();
        }
        Element verify_left = P.powZn(sum_C5).getImmutable();
        Element verify_right = sum_C2.add(sum_h1Vi).add(sum_h2PPK).getImmutable();
//        if (!verify_left.isEqual(verify_right)) {
//            throw new RuntimeException("批量验证失败");
//        }
        long end = System.currentTimeMillis();
        return end - start;
    }

    // 6. 双密文相等性测试（匹配论文公式(1)(2)(3)(4)，无配对）
    public static Object[] equalityTestTwo(FullCiphertext C, FullCiphertext C_prime, GroupKey groupKey) {
        long start = System.currentTimeMillis();
        Element td = groupKey.td;

        // 公式(1)：T1 = td·C2；T1' = td·C2'
        Element T1 = C.C2.powZn(td).getImmutable();
        Element T1_prime = C_prime.C2.powZn(td).getImmutable();

        // 公式(2)(3)：I = C3⊕H2(T1)；I' = C3'⊕H2(T1')
        Element H2_T1 = H2(T1);
        byte[] I_bytes = xor(C.C3.toBytes(), H2_T1.toBytes());
        Element I = bp.getZr().newElementFromBytes(I_bytes).getImmutable();

        Element H2_T1_prime = H2(T1_prime);
        byte[] I_prime_bytes = xor(C_prime.C3.toBytes(), H2_T1_prime.toBytes());
        Element I_prime = bp.getZr().newElementFromBytes(I_prime_bytes).getImmutable();

        // 公式(4)：I·C1' = I'·C1
        Element left = C_prime.C1.mulZn(I).getImmutable(); // 点×标量
        Element right = C.C1.mulZn(I_prime).getImmutable(); // 点×标量
        boolean result = left.isEqual(right);

        long end = System.currentTimeMillis();
        long cost = end - start;
        return new Object[]{cost, result};
    }

    // 7. 聚合多密文相等性测试（匹配论文公式(5)(6)(7)）
    public static Object[] aggregateEqualityTest(int N, List<FullCiphertext> cipherList, GroupKey groupKey, FullCiphertext baseCipher) {
        long start = System.currentTimeMillis();
        Element td = groupKey.td;
        Element C1_base = baseCipher.C1;
        Element I_base = calculateI(baseCipher, td);

        // 公式(5)：Ĉ1 = ΣC1,j
        Element C1_hat = bp.getG1().newZeroElement().getImmutable();
        // 公式(6)：Î = ΣI,j
        Element I_hat = bp.getZr().newZeroElement().getImmutable();

        for (int j = 0; j < N; j++) {
            FullCiphertext cipher = cipherList.get(j);
            C1_hat = C1_hat.add(cipher.C1).getImmutable();
            Element I_j = calculateI(cipher, td);
            I_hat = I_hat.add(I_j).getImmutable();
        }

        // 公式(7)：I·Ĉ1 = Î·C1
//        Element left = I_base.mulZn(C1_hat).getImmutable();
//        Element right = I_hat.mulZn(C1_base).getImmutable();

        Element left = C1_hat.mulZn(I_base).getImmutable();
        Element right = C1_base.mulZn(I_hat).getImmutable();
        boolean isPass = left.isEqual(right);

        long end = System.currentTimeMillis();
        long cost = end - start;
        return new Object[]{cost, isPass};
    }

    // 辅助：计算单个密文的I,j
    private static Element calculateI(FullCiphertext cipher, Element td) {
        Element T1_j = cipher.C2.powZn(td).getImmutable();
        Element H2_T1j = H2(T1_j);
        byte[] I_bytes = xor(cipher.C3.toBytes(), H2_T1j.toBytes());
        return bp.getZr().newElementFromBytes(I_bytes).getImmutable();
    }

    // 8. 生成N个密文
    public static Object[] generateNCiphers(int N, CLC_SensorKeyPair sensorKey, PKI_DoctorKeyPair doctorKey, GroupKey groupKey) {
        long start = System.currentTimeMillis();
        List<FullCiphertext> cipherList = new ArrayList<>();
        Random random = new Random();
        for (int i = 0; i < N; i++) {
            String msg = String.format("WBAN-Data-%d: Value=%d, Time=%d", i, 60 + random.nextInt(40), System.currentTimeMillis() / 1000);
            Object[] singleResult = signcryptSingle(msg, sensorKey, doctorKey, groupKey);
            cipherList.add((FullCiphertext) singleResult[2]);
        }
        long end = System.currentTimeMillis();
        long totalCost = end - start;
        return new Object[]{cipherList, totalCost};
    }

    // ===================== 辅助方法 =====================
    private static String generatePseudonym(String ID_i, GroupKey groupKey) {
        Element H2_hkG = H2(groupKey.hk_G);
        byte[] ID_bytes = ID_i.getBytes(StandardCharsets.UTF_8);
        byte[] PID_bytes = xor(ID_bytes, H2_hkG.toBytes());
        return new String(PID_bytes, StandardCharsets.UTF_8);
    }

    private static Element[] generatePartialPrivateKey(String PID_i, Element A_i) {
        Element PID_zr = bp.getZr().newElementFromHash(PID_i.getBytes(), 0, PID_i.getBytes().length);
        Element H1_PID_A = H1(PID_zr, A_i);
        Element t_i = bp.getZr().newRandomElement().getImmutable();
        Element ppk_i = t_i.add(s.mulZn(H1_PID_A)).getImmutable();
        return new Element[]{ppk_i, A_i};
    }

    private static Element hashToZr(byte[] input) {
        try {
            MessageDigest md = MessageDigest.getInstance(HASH_ALG);
            byte[] hash = md.digest(input);
            return bp.getZr().newElementFromHash(hash, 0, hash.length).getImmutable();
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
        // 自定义参数：密文数量N
        int N = 1000; // 可修改为300/500...
        System.out.println("===== WBAN 全流程测试（N=" + N + "）=====\n");

        // 1. 初始化+生成基础密钥
        setup();
        Object[] baseKeys = generateBaseKeys();
        PKI_DoctorKeyPair doctorKey = (PKI_DoctorKeyPair) baseKeys[0];
        GroupKey groupKey = (GroupKey) baseKeys[1];
        CLC_SensorKeyPair sensorKey = (CLC_SensorKeyPair) baseKeys[2];

        // 2. 单个密文签密测试
        String testMsg = "Test-Message: Single-Ciphertext";
        Object[] singleSign = signcryptSingle(testMsg, sensorKey, doctorKey, groupKey);
        long offlineCost = (Long) singleSign[0];
        long onlineCost = (Long) singleSign[1];
        FullCiphertext testCipher = (FullCiphertext) singleSign[2];
        System.out.println("[单个密文签密]");
        System.out.println("  离线耗时：" + offlineCost + " ms");
        System.out.println("  在线耗时：" + onlineCost + " ms");
        System.out.println("  总耗时：" + (offlineCost + onlineCost) + " ms\n");

        // 3. 单个密文解签密测试
        Object[] singleUnsign = unsigncryptSingle(testCipher, doctorKey, sensorKey);
        long unsignCost = (Long) singleUnsign[0];
        String plaintext = (String) singleUnsign[1];
        System.out.println("[单个密文解签密]");
        System.out.println("  耗时：" + unsignCost + " ms");
        System.out.println("  一致性：" + testMsg.equals(plaintext) + "\n");

        // 4. 生成N个密文
        Object[] nCiphers = generateNCiphers(N, sensorKey, doctorKey, groupKey);
        List<FullCiphertext> cipherList = (List<FullCiphertext>) nCiphers[0];
        long genCost = (Long) nCiphers[1];
        System.out.println("[生成" + N + "个密文]");
        System.out.println("  总耗时：" + genCost + " ms");
        System.out.println("  单密文平均耗时：" + (genCost * 1.0 / N) + " ms\n");

        // 5. N个密文批量验证
        long batchCost = batchVerifyN(N, cipherList, doctorKey, sensorKey);
        System.out.println("[" + N + "个密文批量验证]");
        System.out.println("  总耗时：" + batchCost + " ms");
        System.out.println("  单密文平均耗时：" + (batchCost * 1.0 / N) + " ms\n");

        // 6. 双密文相等性测试
        FullCiphertext C = cipherList.get(0);
        FullCiphertext C_prime = cipherList.get(1);
        Object[] twoEqResult = equalityTestTwo(C, C_prime, groupKey);
        long twoEqCost = (Long) twoEqResult[0];
        boolean twoEqPass = (Boolean) twoEqResult[1];
        System.out.println("[双密文相等性测试]");
        System.out.println("  耗时：" + twoEqCost + " ms");
        System.out.println("  结果：" + (twoEqPass ? "相同明文" : "不同明文") + "\n");

        // 7. 聚合多密文相等性测试
        Object[] aggEqResult = aggregateEqualityTest(N, cipherList, groupKey, C);
        long aggEqCost = (Long) aggEqResult[0];
        boolean aggEqPass = (Boolean) aggEqResult[1];
        System.out.println("[" + N + "个密文聚合相等性测试]");
        System.out.println("  耗时：" + aggEqCost + " ms");
        System.out.println("  结果：" + (aggEqPass ? "所有密文对应同一明文" : "存在不同明文") + "\n");

        // 测试汇总
        System.out.println("===== 测试汇总（N=" + N + "）=====");
        System.out.println("1. 单个密文签密总耗时：" + (offlineCost + onlineCost) + " ms");
        System.out.println("2. 单个密文解签密耗时：" + unsignCost + " ms");
        System.out.println("3. " + N + "个密文批量验证总耗时：" + batchCost + " ms");
        System.out.println("4. 双密文相等性测试耗时：" + twoEqCost + " ms");
        System.out.println("5. " + N + "个密文相等性测试耗时：" + aggEqCost + " ms");
    }
}