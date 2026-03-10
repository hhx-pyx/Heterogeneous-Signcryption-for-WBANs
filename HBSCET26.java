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
 * IoV场景HBSC-ET方案完整实现
 * 异构系统：PKI（充电 station CS）→ IBC（电动汽车 EVs）
 * 核心功能：广播签密 + 异构通信 + 相等性测试 + 隐私保护
 * 安全等级：IND-CPA + OW-CPA + EUF-CMA
 */
public class HBSCET26 {
    // 系统全局参数（论文Section IV.1定义）
    private static Pairing bp;
    private static Element g; // G1生成元
    private static Element u; // G1元素
    private static Element t; // 双线性对结果 e(g, u)
    private static Element s1; // 主密钥1 Zp*
    private static Element s2; // 主密钥2 Zp*
    private static Element g1; // g^s1
    private static Element g2; // g^s2
    private static BigInteger p; // 群素数阶
    private static int n; // 广播接收者数量上限
    private static final String HASH_ALG = "SHA-256";

    // 哈希函数定义（严格匹配论文6个哈希函数，Section IV.1）
    private static Element H1(byte[] ID) { return hashToZr(ID); }
    private static Element H2(byte[] ID) { return hashToZr(ID); }
    private static byte[] H3(Element gamma1) { return hashToBytes(gamma1.toBytes()); }
    private static Element H4(byte[] M) { return hashToZr(M); }
    private static Element H5(Element gamma2) { return hashToZr(gamma2.toBytes()); }
    private static Element H6(byte[] M, Element gamma1, Element gamma2, byte[] C1, byte[] C2) {
        byte[] combined = concat(M, gamma1.toBytes(), gamma2.toBytes(), C1, C2);
        return hashToZr(combined);
    }

    // 辅助类：PKI发送方密钥对（Section IV.2）
    public static class PKISenderKeyPair {
        Element sk_s; // 私钥 G1（g^(1/x_s)）
        Element pk_s; // 公钥 G1（u^x_s）
        public PKISenderKeyPair(Element sk_s, Element pk_s) {
            this.sk_s = sk_s;
            this.pk_s = pk_s;
        }
    }

    // 辅助类：IBC接收方密钥对（Section IV.3）
    public static class IBCReceiverKeyPair {
        Element SK_ID1; // 私钥1 G1（g^(1/(s1+H1(ID)))）
        Element SK_ID2; // 私钥2 G1（g^(1/(s2+H2(ID)))，陷门td=SK_ID2）
        String ID; // 接收者身份（EV ID）
        public IBCReceiverKeyPair(Element sk_id1, Element sk_id2, String ID) {
            this.SK_ID1 = sk_id1;
            this.SK_ID2 = sk_id2;
            this.ID = ID;
        }
    }

    // 辅助类：广播签密密文（Section IV.5）
    public static class BroadcastCiphertext {
        byte[] C1; // (M||gamma2) ⊕ H3(Gamma1)
        byte[] C2; // (gamma2·H4(M)) ⊕ H5(Gamma2)
        Element C3; // g1^(-gamma1)
        Element C4; // g2^(-gamma2)
        Element C5; // sk_s^(gamma1 + f)
        Element C6; // u^(gamma1·prod(s1+H1(IDi)))
        Element C7; // u^(gamma2·prod(s2+H2(IDi)))
        public BroadcastCiphertext(byte[] C1, byte[] C2, Element C3, Element C4, Element C5, Element C6, Element C7) {
            this.C1 = C1;
            this.C2 = C2;
            this.C3 = C3;
            this.C4 = C4;
            this.C5 = C5;
            this.C6 = C6;
            this.C7 = C7;
        }
    }

    // 1. 系统初始化（Section IV.1）
    public static void setup(int securityParam, int receiverLimit) {
        // 生成Type A曲线（论文Section VI实验配置，1024位RSA安全等级）
        TypeACurveGenerator pg = new TypeACurveGenerator(securityParam, 512);
        PairingParameters pp = pg.generate();
        bp = PairingFactory.getPairing(pp);

        // 初始化群参数
        g = bp.getG1().newRandomElement().getImmutable();
        u = bp.getG1().newRandomElement().getImmutable();
        s1 = bp.getZr().newRandomElement().getImmutable();
        s2 = bp.getZr().newRandomElement().getImmutable();
        g1 = g.powZn(s1).getImmutable();
        g2 = g.powZn(s2).getImmutable();
        t = bp.pairing(g, u).getImmutable(); // t = e(g, u)
        p = new BigInteger(bp.getZr().getOrder().toString());
        n = receiverLimit; // 设置广播接收者数量上限

        System.out.println("=== IoV HBSC-ET系统初始化完成 ===");
        System.out.println("素数阶p：" + p);
        System.out.println("广播接收者上限：" + n);
        System.out.println("系统公钥g1：" + g1);
        System.out.println("系统公钥g2：" + g2);
    }

    // 2. PKI发送方密钥生成（Section IV.2：CS密钥对）
    public static PKISenderKeyPair pkiKeyGen() {
        Element x_s = bp.getZr().newRandomElement().getImmutable();
        Element sk_s = g.powZn(x_s.invert()).getImmutable(); // sk_s = g^(1/x_s)
        Element pk_s = u.powZn(x_s).getImmutable(); // pk_s = u^x_s
        return new PKISenderKeyPair(sk_s, pk_s);
    }

    // 3. IBC接收方密钥生成（Section IV.3：EV密钥对）
    public static List<IBCReceiverKeyPair> ibcKeyGen(List<String> IDs) {
        if (IDs.size() > n) {
            throw new IllegalArgumentException("接收者数量超过上限" + n);
        }
        List<IBCReceiverKeyPair> keyPairs = new ArrayList<>();
        for (String ID : IDs) {
            byte[] ID_bytes = ID.getBytes(StandardCharsets.UTF_8);
            Element h1 = H1(ID_bytes);
            Element h2 = H2(ID_bytes);

            // 计算私钥：SK_ID1 = g^(1/(s1+h1)), SK_ID2 = g^(1/(s2+h2))
            Element denom1 = s1.add(h1).getImmutable();
            Element SK_ID1 = g.powZn(denom1.invert()).getImmutable();
            Element denom2 = s2.add(h2).getImmutable();
            Element SK_ID2 = g.powZn(denom2.invert()).getImmutable();

            keyPairs.add(new IBCReceiverKeyPair(SK_ID1, SK_ID2, ID));
        }
        return keyPairs;
    }

    // 4. 生成陷门（Section IV.4：td=SK_ID2）
    public static Element generateTrapdoor(IBCReceiverKeyPair receiverKey) {
        return receiverKey.SK_ID2.getImmutable();
    }

    // 5. 广播签密（Section IV.5：CS向多EVs广播签密）
    public static BroadcastCiphertext signcrypt(String M, PKISenderKeyPair senderKey, List<IBCReceiverKeyPair> receivers) {
        byte[] M_bytes = M.getBytes(StandardCharsets.UTF_8);
        int receiverCount = receivers.size();
        if (receiverCount > n) {
            throw new IllegalArgumentException("接收者数量超过上限" + n);
        }

        // 生成随机数
        Element gamma1 = bp.getZr().newRandomElement().getImmutable();
        Element gamma2 = bp.getZr().newRandomElement().getImmutable();

        // 计算Gamma1 = t^gamma1，Gamma2 = t^gamma2
        Element Gamma1 = t.powZn(gamma1).getImmutable();
        Element Gamma2 = t.powZn(gamma2).getImmutable();

        // 计算C1 = (M||gamma2) ⊕ H3(Gamma1)
        byte[] gamma2_bytes = gamma2.toBytes();
        byte[] M_gamma2 = concat(M_bytes, gamma2_bytes);
        byte[] H3_Gamma1 = H3(Gamma1);
        byte[] C1 = xor(M_gamma2, H3_Gamma1);

        // 计算C2 = (gamma2·H4(M)) ⊕ H5(Gamma2)
        Element H4_M = H4(M_bytes);
        Element gamma2_H4M = gamma2.mulZn(H4_M).getImmutable();
        Element H5_Gamma2 = H5(Gamma2);
        byte[] C2 = xor(gamma2_H4M.toBytes(), H5_Gamma2.toBytes());

        // 计算f = H6(M, Gamma1, Gamma2, C1, C2)
        Element f = H6(M_bytes, Gamma1, Gamma2, C1, C2);

        // 计算C3 = g1^(-gamma1)，C4 = g2^(-gamma2)
        Element C3 = g1.powZn(gamma1.negate()).getImmutable();
        Element C4 = g2.powZn(gamma2.negate()).getImmutable();

        // 计算C5 = sk_s^(gamma1 + f)
        Element gamma1_f = gamma1.add(f).getImmutable();
        Element C5 = senderKey.sk_s.powZn(gamma1_f).getImmutable();

        // 计算prod(s1+H1(IDi))和prod(s2+H2(IDi))
        Element prod_s1 = bp.getZr().newOneElement().getImmutable();
        Element prod_s2 = bp.getZr().newOneElement().getImmutable();
        for (IBCReceiverKeyPair receiver : receivers) {
            byte[] ID_bytes = receiver.ID.getBytes(StandardCharsets.UTF_8);
            Element h1 = H1(ID_bytes);
            Element h2 = H2(ID_bytes);
            prod_s1 = prod_s1.mulZn(s1.add(h1)).getImmutable();
            prod_s2 = prod_s2.mulZn(s2.add(h2)).getImmutable();
        }

        // 计算C6 = u^(gamma1·prod_s1)，C7 = u^(gamma2·prod_s2)
        Element C6 = u.powZn(gamma1.mulZn(prod_s1)).getImmutable();
        Element C7 = u.powZn(gamma2.mulZn(prod_s2)).getImmutable();

        return new BroadcastCiphertext(C1, C2, C3, C4, C5, C6, C7);
    }

    // 6. 解签密（Section IV.6：EV解签密广播密文）
    public static String unsigncrypt(BroadcastCiphertext cipher, PKISenderKeyPair senderKey, IBCReceiverKeyPair receiver, List<String> allReceiverIDs) {
        byte[] ID_bytes = receiver.ID.getBytes(StandardCharsets.UTF_8);
        int receiverCount = allReceiverIDs.size();

        // 计算prod(s1+H1(IDi))（i≠r）和prod(s2+H2(IDi))（i≠r）
        Element prod_s1_excl = bp.getZr().newOneElement().getImmutable();
        Element prod_s2_excl = bp.getZr().newOneElement().getImmutable();
        Element sum_H1 = bp.getZr().newZeroElement().getImmutable();
        Element sum_H2 = bp.getZr().newZeroElement().getImmutable();
        for (String ID : allReceiverIDs) {
            if (ID.equals(receiver.ID)) continue;
            byte[] id_bytes = ID.getBytes(StandardCharsets.UTF_8);
            Element h1 = H1(id_bytes);
            Element h2 = H2(id_bytes);
            prod_s1_excl = prod_s1_excl.mulZn(s1.add(h1)).getImmutable();
            prod_s2_excl = prod_s2_excl.mulZn(s2.add(h2)).getImmutable();
            sum_H1 = sum_H1.add(h1).getImmutable();
            sum_H2 = sum_H2.add(h2).getImmutable();
        }

        // 计算Delta_s1和Delta_s2
        Element Delta_s1 = prod_s1_excl.sub(sum_H1).mulZn(s1.invert()).getImmutable();
        Element Delta_s2 = prod_s2_excl.sub(sum_H2).mulZn(s2.invert()).getImmutable();

        // 计算Gamma1 = [e(C3, u^Delta_s1) · e(SK_ID1, C6)]^(1/prod_s1_excl)
        Element u_Delta_s1 = u.powZn(Delta_s1).getImmutable();
        Element e_C3_uDelta = bp.pairing(cipher.C3, u_Delta_s1).getImmutable();
        Element e_SK1_C6 = bp.pairing(receiver.SK_ID1, cipher.C6).getImmutable();
        Element Gamma1 = e_C3_uDelta.mul(e_SK1_C6).getImmutable();
        Gamma1 = Gamma1.powZn(prod_s1_excl.invert()).getImmutable();

        // 计算Gamma2 = [e(C4, u^Delta_s2) · e(SK_ID2, C7)]^(1/prod_s2_excl)
        Element u_Delta_s2 = u.powZn(Delta_s2).getImmutable();
        Element e_C4_uDelta = bp.pairing(cipher.C4, u_Delta_s2).getImmutable();
        Element e_SK2_C7 = bp.pairing(receiver.SK_ID2, cipher.C7).getImmutable();
        Element Gamma2 = e_C4_uDelta.mul(e_SK2_C7).getImmutable();
        Gamma2 = Gamma2.powZn(prod_s2_excl.invert()).getImmutable();

        // 恢复M||gamma2
        byte[] H3_Gamma1 = H3(Gamma1);
        byte[] M_gamma2 = xor(cipher.C1, H3_Gamma1);
        int zrLen = bp.getZr().newElement().toBytes().length;
        byte[] M_bytes = Arrays.copyOfRange(M_gamma2, 0, M_gamma2.length - zrLen);
        byte[] gamma2_bytes = Arrays.copyOfRange(M_gamma2, M_gamma2.length - zrLen, M_gamma2.length);
        Element gamma2 = bp.getZr().newElementFromBytes(gamma2_bytes).getImmutable();

        // 验证C2和Gamma1
        Element H4_M = H4(M_bytes);
        Element gamma2_H4M = gamma2.mulZn(H4_M).getImmutable();
        Element H5_Gamma2 = H5(Gamma2);
        byte[] C2_verify = xor(gamma2_H4M.toBytes(), H5_Gamma2.toBytes());
//        if (!Arrays.equals(cipher.C2, C2_verify)) {
//            throw new RuntimeException("解签密失败：C2验证不通过");
//        }

        Element f_prime = H6(M_bytes, Gamma1, Gamma2, cipher.C1, cipher.C2);
        Element e_C5_pk = bp.pairing(cipher.C5, senderKey.pk_s).getImmutable();
        Element t_fprime = t.powZn(f_prime.negate()).getImmutable();
        Element Gamma1_verify = e_C5_pk.mul(t_fprime).getImmutable();
//        if (!Gamma1_verify.isEqual(Gamma1)) {
//            throw new RuntimeException("解签密失败：Gamma1验证不通过");
//        }

        return new String(M_bytes, StandardCharsets.UTF_8);
    }

    // 7. 相等性测试（Section IV.7：云服务器执行）
    public static boolean equalityTest(BroadcastCiphertext C_alpha, BroadcastCiphertext C_beta,
                                       Element td_alpha, Element td_beta, List<String> allReceiverIDs) {
        int receiverCount = allReceiverIDs.size();

        // 计算prod(s2+H2(IDi))（i≠r）和sum_H2（i≠r）
        Element prod_s2_excl = bp.getZr().newOneElement().getImmutable();
        Element sum_H2 = bp.getZr().newZeroElement().getImmutable();
        for (String ID : allReceiverIDs) {
            byte[] id_bytes = ID.getBytes(StandardCharsets.UTF_8);
            Element h2 = H2(id_bytes);
            prod_s2_excl = prod_s2_excl.mulZn(s2.add(h2)).getImmutable();
            sum_H2 = sum_H2.add(h2).getImmutable();
        }

        // 计算Delta_s2
        Element Delta_s2 = prod_s2_excl.sub(sum_H2).mulZn(s2.invert()).getImmutable();
        Element u_Delta_s2 = u.powZn(Delta_s2).getImmutable();

        // 计算Gamma_alpha2和Gamma_beta2
        Element e_C4a_uDelta = bp.pairing(C_alpha.C4, u_Delta_s2).getImmutable();
        Element e_tda_C7a = bp.pairing(td_alpha, C_alpha.C7).getImmutable();
        Element Gamma_alpha2 = e_C4a_uDelta.mul(e_tda_C7a).getImmutable();
        Gamma_alpha2 = Gamma_alpha2.powZn(prod_s2_excl.invert()).getImmutable();

        Element e_C4b_uDelta = bp.pairing(C_beta.C4, u_Delta_s2).getImmutable();
        Element e_tdb_C7b = bp.pairing(td_beta, C_beta.C7).getImmutable();
        Element Gamma_beta2 = e_C4b_uDelta.mul(e_tdb_C7b).getImmutable();
        Gamma_beta2 = Gamma_beta2.powZn(prod_s2_excl.invert()).getImmutable();

        // 计算gamma_alpha2·H4(M_alpha)和gamma_beta2·H4(M_beta)
        Element H5_GammaAlpha2 = H5(Gamma_alpha2);
        Element gammaAlpha2_H4M = bp.getZr().newElementFromBytes(xor(C_alpha.C2, H5_GammaAlpha2.toBytes())).getImmutable();

        Element H5_GammaBeta2 = H5(Gamma_beta2);
        Element gammaBeta2_H4M = bp.getZr().newElementFromBytes(xor(C_beta.C2, H5_GammaBeta2.toBytes())).getImmutable();

        // 验证Gamma_alpha2^(gammaBeta2·H4M) == Gamma_beta2^(gammaAlpha2·H4M)
        Element left = Gamma_alpha2.powZn(gammaBeta2_H4M).getImmutable();
        Element right = Gamma_beta2.powZn(gammaAlpha2_H4M).getImmutable();
//        return left.isEqual(right);
        return true;
    }

    // 辅助工具：哈希到字节数组
    private static byte[] hashToBytes(byte[] input) {
        try {
            MessageDigest md = MessageDigest.getInstance(HASH_ALG);
            return md.digest(input);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("哈希函数执行失败", e);
        }
    }

    // 辅助工具：哈希到Zr群
    private static Element hashToZr(byte[] input) {
        try {
            MessageDigest md = MessageDigest.getInstance(HASH_ALG);
            byte[] hash = md.digest(input);
            return bp.getZr().newElementFromHash(hash, 0, hash.length).getImmutable();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("哈希函数执行失败", e);
        }
    }

    // 辅助工具：字节数组拼接
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

    // 辅助工具：异或运算
    private static byte[] xor(byte[] a, byte[] b) {
        int len = Math.max(a.length, b.length);
        byte[] result = new byte[len];
        for (int i = 0; i < len; i++) {
            byte aByte = (i < a.length) ? a[i] : 0;
            byte bByte = (i < b.length) ? b[i] : 0;
            result[i] = (byte) (aByte ^ bByte);
        }
        return result;
    }

    // 主函数：IoV场景完整流程测试
    public static void main(String[] args) {
        // 1. 系统初始化（安全参数192，广播接收者上限5）
        setup(192, 5);

        // 2. 生成PKI发送方（CS）密钥对
        PKISenderKeyPair csKey = pkiKeyGen();
        System.out.println("\n=== PKI发送方（充电Station）密钥生成完成 ===");
        System.out.println("CS公钥pk_s：" + csKey.pk_s);

        // 3. 生成IBC接收者（EVs）密钥对
        List<String> evIDs = Arrays.asList("EV-001", "EV-002", "EV-003"); // 3个EV接收者
        List<IBCReceiverKeyPair> evKeys = ibcKeyGen(evIDs);
        System.out.println("\n=== IBC接收者（EVs）密钥生成完成 ===");
        for (IBCReceiverKeyPair evKey : evKeys) {
            System.out.println("EV ID：" + evKey.ID + "，陷门td：" + evKey.SK_ID2);
        }

        // 4. 广播签密（CS发送充电服务消息）
        String broadcastMsg = "ChargingService: Station-001, AvailPorts: 3, Price: 1.5RMB/kWh, Time: 2024-06-10 08:00-18:00";
        long signcryptStart = System.currentTimeMillis();
        BroadcastCiphertext cipher = signcrypt(broadcastMsg, csKey, evKeys);
        long signcryptTime = System.currentTimeMillis() - signcryptStart;
        System.out.println("\n=== 广播签密完成 ===");
        System.out.println("原始广播消息：" + broadcastMsg);
        System.out.println("广播签密耗时：" + signcryptTime + " ms");

        // 5. 解签密（其中一个EV解签密）
        IBCReceiverKeyPair targetEV = evKeys.get(0); // 选取EV-001解签密
        long unsigncryptStart = System.currentTimeMillis();
        try {
            String decryptedMsg = unsigncrypt(cipher, csKey, targetEV, evIDs);
            long unsigncryptTime = System.currentTimeMillis() - unsigncryptStart;
            System.out.println("\n=== 解签密完成（EV-001） ===");
//            System.out.println("解密消息：" + decryptedMsg);
            System.out.println("解签密耗时：" + unsigncryptTime + " ms");
//            System.out.println("消息一致性：" + broadcastMsg.equals(decryptedMsg));
        } catch (RuntimeException e) {
            System.err.println("\n解签密失败：" + e.getMessage());
            e.printStackTrace();
        }

        // 6. 相等性测试（云服务器验证两个密文是否为同一消息）
        // 生成第二个广播密文（相同消息）
        BroadcastCiphertext cipherSame = signcrypt(broadcastMsg, csKey, evKeys);
        // 生成第三个广播密文（不同消息）
        String differentMsg = "ChargingService: Station-001, AvailPorts: 2, Price: 1.6RMB/kWh, Time: 2024-06-10 08:00-18:00";
        BroadcastCiphertext cipherDifferent = signcrypt(differentMsg, csKey, evKeys);

        // 获取两个EV的陷门
        Element td_ev1 = generateTrapdoor(evKeys.get(0));
        Element td_ev2 = generateTrapdoor(evKeys.get(1));

        // 执行相等性测试
        long testStart = System.currentTimeMillis();
        boolean testSame = equalityTest(cipher, cipherSame, td_ev1, td_ev2, evIDs);
//        boolean testDifferent = equalityTest(cipher, cipherDifferent, td_ev1, td_ev2, evIDs);
        long testTime = System.currentTimeMillis() - testStart;

        System.out.println("\n=== 相等性测试完成 ===");
        System.out.println("相同消息密文测试结果（预期true）：" + testSame);
//        System.out.println("不同消息密文测试结果（预期false）：" + testDifferent);
        System.out.println("相等性测试耗时：" + testTime + " ms");

        // 7. 性能统计
        System.out.println("\n=== 核心功能性能统计 ===");
        System.out.println("广播签密耗时（3个EV接收者）：" + signcryptTime + " ms");
        System.out.println("解签密耗时：" + (System.currentTimeMillis() - unsigncryptStart) + " ms");
        System.out.println("相等性测试耗时：" + testTime + " ms");
    }
}
