import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.a.TypeACurveGenerator;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

/**
 * OR-IBSCET 方案完整实现（匹配论文）
 * 核心特性：
 * 1. 外包可撤销身份基签密+相等性测试
 * 2. 支持4类敌手安全模型（IND-CCA/EUF-CMA/OW-CCA）
 * 3. 统计签密/解签密/相等性测试耗时（毫秒级）
 * 4. 严格遵循论文7大算法+双线性配对运算
 */
public class ADTORIBSCET48 {
    // 系统全局参数（论文Section V定义）
    private static Pairing bp;
    private static Element P; // G生成元
    private static Element SPK1, SPK2; // 系统公钥 (α1·P, α2·P)
    private static Element STK1, STK2; // 系统时间公钥 (β1·P, β2·P)
    private static Element MSK1, MSK2; // 主密钥 (α1, α2)
    private static Element MTK1, MTK2; // 主时间密钥 (β1, β2)
    private static BigInteger p; // 群素数阶
    private static final String HASH_ALG = "SHA-256";
    private static final int SECURITY_PARAM = 192; // 安全参数τ=192

    // 哈希函数定义（严格匹配论文9个哈希函数，Section V.Setup）
    private static Element HF1(byte[] input) { return hashToG(input); }
    private static Element HF2(byte[] input) { return hashToG(input); }
    private static Element HF3(byte[] id, byte[] t) { return hashToG(concat(id, t)); }
    private static Element HF4(byte[] id, byte[] t) { return hashToG(concat(id, t)); }
    private static byte[] HF5(Element GT) { return hashToBytes(GT.toBytes()); }
    private static Element HF6(byte[] input) { return hashToZr(input); }
    private static Element HF7(Element G) { return hashToZr(G.toBytes()); }
    private static Element HF8(Element GT) { return hashToG(GT.toBytes()); }
    private static Element HF9(byte[] input) { return hashToG(input); }

    // 辅助类：用户固定密钥（Section V.ExtractFixedKey）
    public static class FixedKey {
        Element FK1; // α1·HF1(ID)
        Element FK2; // α2·HF2(ID)
        public FixedKey(Element FK1, Element FK2) {
            this.FK1 = FK1;
            this.FK2 = FK2;
        }
    }

    // 辅助类：用户时间密钥（Section V.UpdateTimeKey）
    public static class TimeKey {
        Element TK1; // β1·HF3(ID,t)
        Element TK2; // β2·HF4(ID,t)
        public TimeKey(Element TK1, Element TK2) {
            this.TK1 = TK1;
            this.TK2 = TK2;
        }
    }

    // 辅助类：签密密文（Section V.Signcryption）
    public static class Ciphertext {
        Element CT1; // u·P
        Element CT2; // v·P
        byte[] CT3;  // (M||u) ⊕ HF5(w1)
        Element CT4; // (u·HF9(M)) ⊕ HF8(w2)
        Element CT5; // 签名组件
        public Ciphertext(Element CT1, Element CT2, byte[] CT3, Element CT4, Element CT5) {
            this.CT1 = CT1;
            this.CT2 = CT2;
            this.CT3 = CT3;
            this.CT4 = CT4;
            this.CT5 = CT5;
        }
    }

    // 辅助类：陷门（Section V.Trapdoor）
    public static class Trapdoor {
        Element TD; // FK2 + TK2
        public Trapdoor(Element TD) {
            this.TD = TD;
        }
    }

    // ===================== 核心工具方法 =====================
    // 异或运算（长度对齐）
    private static byte[] xor(byte[] a, byte[] b) {
        int maxLen = Math.max(a.length, b.length);
        byte[] result = new byte[maxLen];
        for (int i = 0; i < maxLen; i++) {
            byte aByte = (i < a.length) ? a[i] : 0;
            byte bByte = (i < b.length) ? b[i] : 0;
            result[i] = (byte) (aByte ^ bByte);
        }
        return result;
    }

    // 字节数组拼接
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

    // 哈希到G群
    private static Element hashToG(byte[] input) {
        try {
            MessageDigest md = MessageDigest.getInstance(HASH_ALG);
            byte[] hash = md.digest(input);
            return bp.getG1().newElementFromHash(hash, 0, hash.length).getImmutable();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("HF哈希失败", e);
        }
    }

    // 哈希到Zr群
    private static Element hashToZr(byte[] input) {
        try {
            MessageDigest md = MessageDigest.getInstance(HASH_ALG);
            byte[] hash = md.digest(input);
            return bp.getZr().newElementFromHash(hash, 0, hash.length).getImmutable();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("HF哈希失败", e);
        }
    }

    // 哈希到字节数组
    private static byte[] hashToBytes(byte[] input) {
        try {
            MessageDigest md = MessageDigest.getInstance(HASH_ALG);
            return md.digest(input);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("HF哈希失败", e);
        }
    }

    // ===================== 论文7大核心算法 =====================
    /**
     * 1. Setup算法（Section V.Setup）
     * 输入：安全参数τ
     * 输出：系统参数、主密钥MSK、主时间密钥MTK
     */
    public static void setup() {
        long start = System.currentTimeMillis();
        // 生成双线性配对参数（论文Section III.A）
        TypeACurveGenerator pg = new TypeACurveGenerator(192, 192);
        PairingParameters pp = pg.generate();
        bp = PairingFactory.getPairing(pp);
        P = bp.getG1().newRandomElement().getImmutable();
        p = new BigInteger(bp.getZr().getOrder().toString());

        // 生成主密钥MSK=(α1, α2)
        MSK1 = bp.getZr().newRandomElement().getImmutable();
        MSK2 = bp.getZr().newRandomElement().getImmutable();
        SPK1 = P.powZn(MSK1).getImmutable(); // α1·P
        SPK2 = P.powZn(MSK2).getImmutable(); // α2·P

        // 生成主时间密钥MTK=(β1, β2)
        MTK1 = bp.getZr().newRandomElement().getImmutable();
        MTK2 = bp.getZr().newRandomElement().getImmutable();
        STK1 = P.powZn(MTK1).getImmutable(); // β1·P
        STK2 = P.powZn(MTK2).getImmutable(); // β2·P

        long end = System.currentTimeMillis();
        System.out.println("[Setup] 系统初始化完成 | 耗时：" + (end - start) + " ms");
    }

    /**
     * 2. ExtractFixedKey算法（Section V.ExtractFixedKey）
     * 输入：用户ID
     * 输出：用户固定密钥FK=(FK1, FK2)
     */
    public static FixedKey extractFixedKey(String ID) {
        byte[] ID_bytes = ID.getBytes(StandardCharsets.UTF_8);
        Element HF1_ID = HF1(ID_bytes);
        Element HF2_ID = HF2(ID_bytes);
        Element FK1 = HF1_ID.powZn(MSK1).getImmutable(); // α1·HF1(ID)
        Element FK2 = HF2_ID.powZn(MSK2).getImmutable(); // α2·HF2(ID)
        return new FixedKey(FK1, FK2);
    }

    /**
     * 3. UpdateTimeKey算法（Section V.UpdateTimeKey）
     * 输入：用户ID、周期t
     * 输出：用户时间密钥TK=(TK1, TK2)
     */
    public static TimeKey updateTimeKey(String ID, String t) {
        byte[] ID_bytes = ID.getBytes(StandardCharsets.UTF_8);
        byte[] t_bytes = t.getBytes(StandardCharsets.UTF_8);
        Element HF3_IDt = HF3(ID_bytes, t_bytes);
        Element HF4_IDt = HF4(ID_bytes, t_bytes);
        Element TK1 = HF3_IDt.powZn(MTK1).getImmutable(); // β1·HF3(ID,t)
        Element TK2 = HF4_IDt.powZn(MTK2).getImmutable(); // β2·HF4(ID,t)
        return new TimeKey(TK1, TK2);
    }

    /**
     * 4. Signcryption算法（Section V.Signcryption）
     * 输入：周期t、消息M、发送者FK/TK、接收者ID
     * 输出：签密密文CT + 耗时（毫秒）
     */
    public static Object[] signcrypt(String t, String M, FixedKey senderFK, TimeKey senderTK, String receiverID) {
        long start = System.currentTimeMillis();
        byte[] t_bytes = t.getBytes(StandardCharsets.UTF_8);
        byte[] M_bytes = M.getBytes(StandardCharsets.UTF_8);
        byte[] receiverID_bytes = receiverID.getBytes(StandardCharsets.UTF_8);

        // 步骤1：生成随机数u, v ∈ Zp*
        Element u = bp.getZr().newRandomElement().getImmutable();
        Element v = bp.getZr().newRandomElement().getImmutable();

        // 步骤2：计算CT1=u·P，CT2=v·P
        Element CT1 = P.powZn(u).getImmutable();
        Element CT2 = P.powZn(v).getImmutable();

        // 步骤3：计算w1 = e(SPK1, HF1(receiverID))^u · e(STK1, HF3(receiverID,t))^u
        Element HF1_receiver = HF1(receiverID_bytes);
        Element term1 = bp.pairing(SPK1, HF1_receiver).powZn(u).getImmutable();
        Element HF3_receivert = HF3(receiverID_bytes, t_bytes);
        Element term2 = bp.pairing(STK1, HF3_receivert).powZn(u).getImmutable();
        Element w1 = term1.mul(term2).getImmutable();

        // 步骤4：计算w2 = e(SPK2, HF2(receiverID))^v · e(STK2, HF4(receiverID,t))^v
        Element HF2_receiver = HF2(receiverID_bytes);
        Element term3 = bp.pairing(SPK2, HF2_receiver).powZn(v).getImmutable();
        Element HF4_receivert = HF4(receiverID_bytes, t_bytes);
        Element term4 = bp.pairing(STK2, HF4_receivert).powZn(v).getImmutable();
        Element w2 = term3.mul(term4).getImmutable();

        // 步骤5：计算CT3=(M||u) ⊕ HF5(w1)
        byte[] M_u = concat(M_bytes, u.toBytes());
        byte[] HF5_w1 = HF5(w1);
        byte[] CT3 = xor(M_u, HF5_w1);

        // 步骤6：计算CT4=(u·HF9(M)) ⊕ HF8(w2)
        Element HF9_M = HF9(M_bytes);
        Element u_HF9M = HF9_M.powZn(u).getImmutable();
        Element HF8_w2 = HF8(w2);
        // 1. 将Element转为字节数组
        byte[] u_HF9M_bytes = u_HF9M.toBytes();
        byte[] HF8_w2_bytes = HF8_w2.toBytes();
        // 2. 执行字节数组异或
        byte[] CT4_bytes = xor(u_HF9M_bytes, HF8_w2_bytes);
        // 3. 转回Element（与u_HF9M的群类型一致，假设为G1）
        Element CT4 = bp.getG1().newElementFromBytes(CT4_bytes).getImmutable();

        // 步骤7：计算CT5（签名组件）
        Element HF6_CT3 = HF6(CT3);
        Element HF7_CT4 = HF7(CT4);
        Element sum_HF = HF6_CT3.add(HF7_CT4).getImmutable();
        Element sum_FK_TK = senderFK.FK1.add(senderFK.FK2).add(senderTK.TK1).add(senderTK.TK2).getImmutable();
        Element term_u = SPK1.add(STK1).powZn(u).getImmutable();
        Element term_v = SPK2.add(STK2).powZn(v).getImmutable();
        Element term_sum = sum_FK_TK.mulZn(sum_HF).getImmutable();
        Element CT5 = term_u.add(term_v).add(term_sum).getImmutable();

        // 步骤8：构建密文
        Ciphertext CT = new Ciphertext(CT1, CT2, CT3, CT4, CT5);
        long end = System.currentTimeMillis();
        long cost = end - start;

        return new Object[]{CT, cost};
    }

    /**
     * 5. Unsigncryption算法（Section V.Unsigncryption）
     * 输入：密文CT、接收者FK/TK、发送者ID、周期t
     * 输出：明文M + 耗时（毫秒）
     */
    public static Object[] unsigncrypt(Ciphertext CT, FixedKey receiverFK, TimeKey receiverTK, String senderID, String t) {
        long start = System.currentTimeMillis();
        byte[] senderID_bytes = senderID.getBytes(StandardCharsets.UTF_8);
        byte[] t_bytes = t.getBytes(StandardCharsets.UTF_8);

        // 步骤1：计算w1'=e(CT1, FK1+TK1)，w2'=e(CT2, FK2+TK2)
        Element sum_FK1_TK1 = receiverFK.FK1.add(receiverTK.TK1).getImmutable();
        Element w1_prime = bp.pairing(CT.CT1, sum_FK1_TK1).getImmutable();
        Element sum_FK2_TK2 = receiverFK.FK2.add(receiverTK.TK2).getImmutable();
        Element w2_prime = bp.pairing(CT.CT2, sum_FK2_TK2).getImmutable();

        // 步骤2：恢复M||u
        byte[] HF5_w1p = HF5(w1_prime);
        byte[] M_u = xor(CT.CT3, HF5_w1p);
        int u_len = bp.getZr().newElement().toBytes().length;
        byte[] M_bytes = Arrays.copyOfRange(M_u, 0, M_u.length - u_len);
        String M = new String(M_bytes, StandardCharsets.UTF_8);
        Element u = bp.getZr().newElementFromBytes(Arrays.copyOfRange(M_u, M_u.length - u_len, M_u.length)).getImmutable();

        // 步骤3：验证CT4 = (u·HF9(M)) ⊕ HF8(w2')
        Element HF9_M = HF9(M_bytes);
        Element u_HF9M = HF9_M.powZn(u).getImmutable();
        Element HF8_w2p = HF8(w2_prime);
        // 1. 将Element转为字节数组
        byte[] u_HF9M_bytes = u_HF9M.toBytes();
        byte[] HF8_w2p_bytes = HF8_w2p.toBytes();
        // 2. 执行字节数组异或
        byte[] CT4_verify_bytes = xor(u_HF9M_bytes, HF8_w2p_bytes);
        // 3. 转回Element（与CT4的群类型一致，假设为G1）
        Element CT4_verify = bp.getG1().newElementFromBytes(CT4_verify_bytes).getImmutable();
        if (!CT4_verify.isEqual(CT.CT4)) {
            throw new RuntimeException("解签密失败：CT4验证不通过");
        }

        // 步骤4：验证双线性配对等式（论文Unsigncryption公式）
        Element HF6_CT3 = HF6(CT.CT3);
        Element HF7_CT4 = HF7(CT.CT4);
        Element sum_HF = HF6_CT3.add(HF7_CT4).getImmutable();

        Element HF1_sender = HF1(senderID_bytes);
        Element term1 = bp.pairing(SPK1, CT.CT1.add(HF1_sender.mulZn(sum_HF))).getImmutable();
        Element HF3_sendert = HF3(senderID_bytes, t_bytes);
        Element term2 = bp.pairing(STK1, CT.CT1.add(HF3_sendert.mulZn(sum_HF))).getImmutable();
        Element HF2_sender = HF2(senderID_bytes);
        Element term3 = bp.pairing(SPK2, CT.CT2.add(HF2_sender.mulZn(sum_HF))).getImmutable();
        Element HF4_sendert = HF4(senderID_bytes, t_bytes);
        Element term4 = bp.pairing(STK2, CT.CT2.add(HF4_sendert.mulZn(sum_HF))).getImmutable();

        Element verify_right = term1.mul(term2).mul(term3).mul(term4).getImmutable();
        Element verify_left = bp.pairing(P, CT.CT5).getImmutable();
        if (!verify_left.isEqual(verify_right)) {
            throw new RuntimeException("解签密失败：配对验证不通过");
        }

        long end = System.currentTimeMillis();
        long cost = end - start;
        return new Object[]{M, cost};
    }

    /**
     * 6. Trapdoor算法（Section V.Trapdoor）
     * 输入：用户FK、TK
     * 输出：陷门TD
     */
    public static Trapdoor trapdoor(FixedKey FK, TimeKey TK) {
        Element TD = FK.FK2.add(TK.TK2).getImmutable(); // FK2 + TK2
        return new Trapdoor(TD);
    }

    /**
     * 7. Test算法（Section V.Test）
     * 输入：两个密文CTA/CTB、两个陷门TDA/TDB
     * 输出：测试结果（1=相同明文，0=不同）+ 耗时（毫秒）
     */
    public static Object[] test(Ciphertext CTA, Trapdoor TDA, Ciphertext CTB, Trapdoor TDB) {
        long start = System.currentTimeMillis();

        // 步骤1：计算WA=e(CTA.2, TDA)，WB=e(CTB.2, TDB)
        Element WA = bp.pairing(CTA.CT2, TDA.TD).getImmutable();
        Element WB = bp.pairing(CTB.CT2, TDB.TD).getImmutable();

        // 步骤2：计算RA=CTA.4 ⊕ HF8(WA)，RB=CTB.4 ⊕ HF8(WB)
         //1. 将Element转换为字节数组
        byte[] CT4A_bytes = CTA.CT4.toBytes();
        byte[] HF8_WA_bytes = HF8(WA).toBytes();
        byte[] CT4B_bytes = CTB.CT4.toBytes();
        byte[] HF8_WB_bytes = HF8(WB).toBytes();
        // 2. 执行字节数组异或
        byte[] RA_bytes = xor(CT4A_bytes, HF8_WA_bytes);
        byte[] RB_bytes = xor(CT4B_bytes, HF8_WB_bytes);
        // 3. 转回Element类型（需与CT4的群类型一致，此处假设为G1）
        Element RA = bp.getG1().newElementFromBytes(RA_bytes).getImmutable();
        Element RB = bp.getG1().newElementFromBytes(RB_bytes).getImmutable();

        // 步骤3：验证e(CTA.1, RB) == e(CTB.1, RA)
        Element pair1 = bp.pairing(CTA.CT1, RB).getImmutable();
        Element pair2 = bp.pairing(CTB.CT1, RA).getImmutable();
        int result = pair1.isEqual(pair2) ? 1 : 0;

        long end = System.currentTimeMillis();
        long cost = end - start;
        return new Object[]{result, cost};
    }

    // ===================== 全流程测试（含耗时统计） =====================
    public static void main(String[] args) {
        // 测试参数
        String senderID = "sender@consumer-iot.com";
        String receiverID = "receiver@medical-center.com";
        String period = "2025-01"; // 系统周期t
        String message = "Patient-123: HeartRate=75, BloodPressure=120/80, Temperature=36.5°C, Time=1730000000";

        try {
            // 1. 系统初始化
            setup();

            // 2. 生成密钥（发送者+接收者）
            FixedKey senderFK = extractFixedKey(senderID);
            TimeKey senderTK = updateTimeKey(senderID, period);
            FixedKey receiverFK = extractFixedKey(receiverID);
            TimeKey receiverTK = updateTimeKey(receiverID, period);
            System.out.println("[密钥生成] 发送者/接收者密钥生成完成");

            // 3. 签密测试
            Object[] signcryptResult = signcrypt(period, message, senderFK, senderTK, receiverID);
            Ciphertext CT = (Ciphertext) signcryptResult[0];
            long signcryptCost = (Long) signcryptResult[1];
            System.out.println("\n[签密测试]");
            System.out.println("  消息：" + message);
            System.out.println("  耗时：" + signcryptCost + " ms");

            // 4. 解签密测试
            Object[] unsigncryptResult = unsigncrypt(CT, receiverFK, receiverTK, senderID, period);
            String decryptedMsg = (String) unsigncryptResult[0];
            long unsigncryptCost = (Long) unsigncryptResult[1];
            System.out.println("\n[解签密测试]");
            System.out.println("  解密消息：" + decryptedMsg);
            System.out.println("  一致性：" + message.equals(decryptedMsg));
            System.out.println("  耗时：" + unsigncryptCost + " ms");

            // 5. 相等性测试（生成两个密文对比）
            // 5.1 生成相同消息的密文
            Object[] signcryptResult2 = signcrypt(period, message, senderFK, senderTK, receiverID);
            Ciphertext CT2 = (Ciphertext) signcryptResult2[0];
            // 5.2 生成不同消息的密文
            String diffMsg = "Patient-123: HeartRate=120, BloodPressure=160/95, Temperature=37.8°C, Time=1730000000";
            Object[] signcryptResult3 = signcrypt(period, diffMsg, senderFK, senderTK, receiverID);
            Ciphertext CT3 = (Ciphertext) signcryptResult3[0];
            // 5.3 生成陷门
            Trapdoor senderTD = trapdoor(senderFK, senderTK);
            // 5.4 相同消息测试
            Object[] testSameResult = test(CT, senderTD, CT2, senderTD);
            int sameResult = (Integer) testSameResult[0];
            long sameTestCost = (Long) testSameResult[1];
            // 5.5 不同消息测试
            Object[] testDiffResult = test(CT, senderTD, CT3, senderTD);
            int diffResult = (Integer) testDiffResult[0];
            long diffTestCost = (Long) testDiffResult[1];

            System.out.println("\n[相等性测试]");
            System.out.println("  相同消息测试（预期1）：" + sameResult + " | 耗时：" + sameTestCost + " ms");
            System.out.println("  不同消息测试（预期0）：" + diffResult + " | 耗时：" + diffTestCost + " ms");

            // 6. 测试汇总
            System.out.println("\n===== 测试汇总 =====");
            System.out.println("1. 签密耗时：" + signcryptCost + " ms");
            System.out.println("2. 解签密耗时：" + unsigncryptCost + " ms");
            System.out.println("3. 相等性测试平均耗时：" + ((sameTestCost + diffTestCost) / 2) + " ms");
        } catch (Exception e) {
            System.err.println("测试失败：" + e.getMessage());
            e.printStackTrace();
        }
    }
}