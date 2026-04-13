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
import java.util.List;
import java.util.Random;

/**
 * 恢复单密文实验的CIOOHSC方案
 * 核心特性：保留单密文签密/解签密独立流程 + 自定义聚合数量功能
 */
public class EOFHASC29 {
    // 系统全局参数（论文Section V定义）
    private static Pairing bp;
    private static Element P; // G1生成元（加法群）
    private static Element Ppub; // 系统公钥 (κ·P)
    private static Element kappa; // SP主密钥 Zq*
    private static BigInteger q; // 群素数阶
    private static final String HASH_ALG = "SHA-256";
    // 固定发送者/接收者身份（无需重复配置）
    private static final String FIXED_SENDER_ID = "Vehicle-Fixed-001";
    private static final String FIXED_RECEIVER_ID = "RSU-Fixed-001";

    // 哈希函数定义（严格匹配论文4个哈希函数，Section V.A）
    private static Element H0(byte[] input) { return hashToZr(input); }
    private static Element H1(byte[] ID, Element A) {
        byte[] combined = concat(ID, A.toBytes());
        return hashToZr(combined);
    }
    private static byte[] H2(Element U) { return hashToBytes(U.toBytes()); }
    private static Element H3(byte[] m, Element PID_s, Element B, Element C, Element U, long T) {
        byte[] combined = concat(m, PID_s.toBytes(), B.toBytes(), C.toBytes(), U.toBytes(), String.valueOf(T).getBytes(StandardCharsets.UTF_8));
        return hashToZr(combined);
    }

    // 辅助类定义（严格遵循论文结构）
    public static class PartialPrivateKey {
        Element delta; // 部分私钥组件 (α + κ·PID_s)
        Element A; // α·P（用于验证delta）
        public PartialPrivateKey(Element delta, Element A) {
            this.delta = delta;
            this.A = A;
        }
    }
    public static class CLCVehicleKeyPair {
        String ID_s;
        Element PID_s; // 伪身份 H1(ID_s||A)
        Element beta_s; // 自有秘密值 Zq*
        Element delta; // 部分私钥组件
        Element B; // delta·P
        Element C; // beta_s·P
        public CLCVehicleKeyPair(String ID_s, Element PID_s, Element beta_s, Element delta, Element B, Element C) {
            this.ID_s = ID_s;
            this.PID_s = PID_s;
            this.beta_s = beta_s;
            this.delta = delta;
            this.B = B;
            this.C = C;
        }
    }
    public static class IBCEdgeKeyPair {
        String ID_r;
        Element Sk_r; // 私钥 (γ + κ·Q_r)
        Element Pk_r; // 公钥 (γ + κ·Q_r)⁻¹·P
        public IBCEdgeKeyPair(String ID_r, Element Sk_r, Element Pk_r) {
            this.ID_r = ID_r;
            this.Sk_r = Sk_r;
            this.Pk_r = Pk_r;
        }
    }
    public static class OfflineCiphertext {
        Element eta;
        Element U;
        Element W;
        public OfflineCiphertext(Element eta, Element U, Element W) {
            this.eta = eta;
            this.U = U;
            this.W = W;
        }
    }
    public static class OnlineCiphertext {
        byte[] mu;
        Element chi;
        Element W;
        long T;
        public OnlineCiphertext(byte[] mu, Element chi, Element W, long T) {
            this.mu = mu;
            this.chi = chi;
            this.W = W;
            this.T = T;
        }
    }

    // 1. 系统初始化（Section V.A）
    public static void setup(int securityParam) {
        TypeACurveGenerator pg = new TypeACurveGenerator(securityParam, 192);
        PairingParameters pp = pg.generate();
        bp = PairingFactory.getPairing(pp);

        P = bp.getG1().newRandomElement().getImmutable();
        kappa = bp.getZr().newRandomElement().getImmutable();
        Ppub = P.powZn(kappa).getImmutable();
        q = new BigInteger(bp.getZr().getOrder().toString());

        System.out.println("=== IoV CIOOHSC系统初始化完成 ===");
        System.out.println("固定发送者ID：" + FIXED_SENDER_ID);
        System.out.println("固定接收者ID：" + FIXED_RECEIVER_ID);
        System.out.println("=================================");
    }

    // 2. 生成发送者密钥对（Section V.B-V.C）
    private static CLCVehicleKeyPair generateSenderKeyPair() {
        // 生成部分私钥
        Element alpha = bp.getZr().newRandomElement().getImmutable();
        Element A = P.powZn(alpha).getImmutable();
        byte[] ID_s_bytes = FIXED_SENDER_ID.getBytes(StandardCharsets.UTF_8);
        Element PID_s = H1(ID_s_bytes, A);
        Element kappa_PID_s = kappa.mulZn(PID_s).getImmutable();
        Element delta = alpha.add(kappa_PID_s).getImmutable();
        PartialPrivateKey psk = new PartialPrivateKey(delta, A);

        // 验证部分私钥
        Element delta_P = P.powZn(delta).getImmutable();
        Element PID_s_Ppub = Ppub.powZn(PID_s).getImmutable();
        Element A_PID_s_Ppub = A.add(PID_s_Ppub).getImmutable();
        if (!delta_P.isEqual(A_PID_s_Ppub)) {
            throw new RuntimeException("发送者密钥生成失败：部分私钥验证不通过");
        }

        // 生成完整密钥对
        Element beta_s = bp.getZr().newRandomElement().getImmutable();
        Element B = P.powZn(delta).getImmutable();
        Element C = P.powZn(beta_s).getImmutable();
        return new CLCVehicleKeyPair(FIXED_SENDER_ID, PID_s, beta_s, delta, B, C);
    }

    // 3. 生成接收者密钥对（Section V.D）
    private static IBCEdgeKeyPair generateReceiverKeyPair() {
        byte[] ID_r_bytes = FIXED_RECEIVER_ID.getBytes(StandardCharsets.UTF_8);
        Element gamma = bp.getZr().newRandomElement().getImmutable();
        Element Q_r = H1(ID_r_bytes, bp.getG1().newZeroElement().getImmutable());
        Element kappa_Q_r = kappa.mulZn(Q_r).getImmutable();
        Element Sk_r = gamma.add(kappa_Q_r).getImmutable();
        Element Sk_r_inv = Sk_r.invert().getImmutable();
        Element Pk_r = P.powZn(Sk_r_inv).getImmutable();
        return new IBCEdgeKeyPair(FIXED_RECEIVER_ID, Sk_r, Pk_r);
    }

    // 4. 离线签密（Section V.E）
    private static OfflineCiphertext offlineSigncrypt(IBCEdgeKeyPair receiverKey) {
        Element eta = bp.getZr().newRandomElement().getImmutable();
        Element U = P.powZn(eta).getImmutable();
        Element W = receiverKey.Pk_r.powZn(eta).getImmutable();
        return new OfflineCiphertext(eta, U, W);
    }

    // 5. 在线签密（Section V.F）
    private static OnlineCiphertext onlineSigncrypt(String m, OfflineCiphertext offlineCipher, CLCVehicleKeyPair senderKey) {
        byte[] m_bytes = m.getBytes(StandardCharsets.UTF_8);
        long T = System.currentTimeMillis() / 1000; // 秒级时间戳

        byte[] H2_U = H2(offlineCipher.U);
        byte[] mu = xor(m_bytes, H2_U);

        Element theta = H3(m_bytes, senderKey.PID_s, senderKey.B, senderKey.C, offlineCipher.U, T);
        Element beta_delta = senderKey.beta_s.add(senderKey.delta).getImmutable();
        Element theta_inv = theta.invert().getImmutable();
        Element theta_inv_beta_delta = theta_inv.mulZn(beta_delta).getImmutable();
        Element chi = theta_inv_beta_delta.add(offlineCipher.eta).getImmutable();

        return new OnlineCiphertext(mu, chi, offlineCipher.W, T);
    }

    // 6. 单密文解签密（Section V.G）
    private static String unsigncryptSingle(OnlineCiphertext cipher, CLCVehicleKeyPair senderKey, IBCEdgeKeyPair receiverKey, long maxDeltaT) {
        // 验证时间戳新鲜性
        long currentTime = System.currentTimeMillis() / 1000;
        if (currentTime - cipher.T > maxDeltaT) {
            throw new RuntimeException("单密文解签密失败：密文已过期");
        }

        // 计算U = Sk_r · W
        Element U = cipher.W.powZn(receiverKey.Sk_r).getImmutable();

        // 恢复明文m
        byte[] H2_U = H2(U);
        byte[] m_bytes = xor(cipher.mu, H2_U);
        String m = new String(m_bytes, StandardCharsets.UTF_8);

        // 验证密文合法性
        Element theta = H3(m_bytes, senderKey.PID_s, senderKey.B, senderKey.C, U, cipher.T);
        Element chi_P = P.powZn(cipher.chi).getImmutable();
        Element B_C = senderKey.B.add(senderKey.C).getImmutable();
        Element theta_inv = theta.invert().getImmutable();
        Element theta_inv_BC = B_C.powZn(theta_inv).getImmutable();
        Element verify = chi_P.sub(theta_inv_BC).getImmutable();

        if (!verify.isEqual(U)) {
            throw new RuntimeException("单密文解签密失败：密文验证不通过");
        }

        return m;
    }

    // ===================== 单密文独立实验方法 =====================
    /**
     * 单密文签密+解签密独立实验
     * @param maxDeltaT 密文过期时间（秒）
     * @return 实验结果（明文+各阶段耗时）
     */
    public static SingleExperimentResult singleCipherExperiment(long maxDeltaT) {
        System.out.println("\n=== 单密文签密/解签密实验开始 ===");

        // 生成密钥对
        CLCVehicleKeyPair senderKey = generateSenderKeyPair();
        IBCEdgeKeyPair receiverKey = generateReceiverKeyPair();

        // 生成测试消息
        String testMsg = String.format("V2I-Data: VehicleID=%s, Speed=%dkm/h, Time=%d, Type=Single",
                FIXED_SENDER_ID, 60 + new Random().nextInt(40), System.currentTimeMillis() / 1000);
        System.out.println("测试消息：" + testMsg);

        // 离线签密（统计耗时）
        long offlineStart = System.currentTimeMillis();
        OfflineCiphertext offlineCipher = offlineSigncrypt(receiverKey);
        long offlineTime = System.currentTimeMillis() - offlineStart;
        System.out.println("离线签密耗时：" + offlineTime + " ms");

        // 在线签密（统计耗时）
        long onlineStart = System.currentTimeMillis();
        OnlineCiphertext onlineCipher = onlineSigncrypt(testMsg, offlineCipher, senderKey);
        long onlineTime = System.currentTimeMillis() - onlineStart;
        System.out.println("在线签密耗时：" + onlineTime + " ms");

        // 解签密（统计耗时）
        long unsignStart = System.currentTimeMillis();
        String decryptedMsg = unsigncryptSingle(onlineCipher, senderKey, receiverKey, maxDeltaT);
        long unsignTime = System.currentTimeMillis() - unsignStart;
        System.out.println("解签密耗时：" + unsignTime + " ms");

        // 验证一致性
        boolean isConsistent = testMsg.equals(decryptedMsg);
        System.out.println("消息一致性：" + isConsistent);
        System.out.println("解密消息：" + decryptedMsg);
        System.out.println("=== 单密文实验结束 ===");

        return new SingleExperimentResult(testMsg, decryptedMsg, offlineTime, onlineTime, unsignTime, isConsistent);
    }

    // ===================== 自定义聚合数量方法 =====================
    public static AggregateResult customAggregateUnsigncrypt(int aggregateCount, long maxDeltaT) {

        // 生成密钥对
        CLCVehicleKeyPair senderKey = generateSenderKeyPair();
        IBCEdgeKeyPair receiverKey = generateReceiverKeyPair();

        // 生成指定数量的密文
        List<OnlineCiphertext> cipherList = new ArrayList<>();
        List<String> originalMsgs = new ArrayList<>();
        Random random = new Random();

        for (int i = 0; i < aggregateCount; i++) {
            String msg = String.format("V2I-Data: VehicleID=%s, Speed=%dkm/h, Time=%d, Seq=%d, Type=Aggregate",
                    FIXED_SENDER_ID, 60 + random.nextInt(40), System.currentTimeMillis() / 1000, i);
            originalMsgs.add(msg);

            // 生成密文
            OfflineCiphertext offlineCipher = offlineSigncrypt(receiverKey);
            OnlineCiphertext onlineCipher = onlineSigncrypt(msg, offlineCipher, senderKey);
            cipherList.add(onlineCipher);
        }

        long totalStartTime = System.currentTimeMillis();

        // 聚合解签密核心逻辑
        List<String> decryptedMsgs = new ArrayList<>();
        Element sumChi = bp.getZr().newZeroElement().getImmutable();
        Element sumThetaInvBC = bp.getG1().newZeroElement().getImmutable();
        List<Element> UList = new ArrayList<>();
        List<byte[]> mBytesList = new ArrayList<>();

        // 阶段1：计算中间参数
        for (OnlineCiphertext cipher : cipherList) {
            // 验证时间戳
            long currentTime = System.currentTimeMillis() / 1000;
            if (currentTime - cipher.T > maxDeltaT) {
                throw new RuntimeException("聚合密文包含过期消息");
            }

            // 计算U_i
            Element U = cipher.W.powZn(receiverKey.Sk_r).getImmutable();
            UList.add(U);

            // 恢复明文
            byte[] H2_U = H2(U);
            byte[] mBytes = xor(cipher.mu, H2_U);
            mBytesList.add(mBytes);

            // 聚合参数
            Element theta = H3(mBytes, senderKey.PID_s, senderKey.B, senderKey.C, U, cipher.T);
            sumChi = sumChi.add(cipher.chi).getImmutable();
            Element BC = senderKey.B.add(senderKey.C).getImmutable();
            Element thetaInv = theta.invert().getImmutable();
            sumThetaInvBC = sumThetaInvBC.add(BC.powZn(thetaInv)).getImmutable();
        }

        // 阶段2：批量验证
        Element sumChiP = P.powZn(sumChi).getImmutable();
        Element verifyLeft = sumChiP.sub(sumThetaInvBC).getImmutable();
        Element verifyRight = bp.getG1().newZeroElement().getImmutable();
        for (Element U : UList) {
            verifyRight = verifyRight.add(U).getImmutable();
        }
        if (!verifyLeft.isEqual(verifyRight)) {
            throw new RuntimeException("聚合验证失败：等式不成立");
        }

        // 阶段3：整理结果
        for (byte[] mBytes : mBytesList) {
            decryptedMsgs.add(new String(mBytes, StandardCharsets.UTF_8));
        }

        // 统计耗时
        long totalTime = System.currentTimeMillis() - totalStartTime;
        boolean isConsistent = originalMsgs.equals(decryptedMsgs);

        // 打印结果
        System.out.println("\n=== 聚合解签密完成 ===");
        System.out.println("聚合密文数量：" + aggregateCount);
        System.out.println("总耗时：" + totalTime + " ms");
//        System.out.println("消息一致性：" + isConsistent);
//        System.out.println("解密消息示例（前2条）：");
//        for (int i = 0; i < Math.min(2, decryptedMsgs.size()); i++) {
//            System.out.println("  消息" + (i+1) + "：" + decryptedMsgs.get(i));
//        }
//        System.out.println("=================================");

        return new AggregateResult(decryptedMsgs, totalTime, isConsistent);
    }

    // 辅助类：实验结果封装
    public static class SingleExperimentResult {
        String originalMsg;
        String decryptedMsg;
        long offlineTime;
        long onlineTime;
        long unsignTime;
        boolean isConsistent;
        public SingleExperimentResult(String originalMsg, String decryptedMsg, long offlineTime, long onlineTime, long unsignTime, boolean isConsistent) {
            this.originalMsg = originalMsg;
            this.decryptedMsg = decryptedMsg;
            this.offlineTime = offlineTime;
            this.onlineTime = onlineTime;
            this.unsignTime = unsignTime;
            this.isConsistent = isConsistent;
        }
    }
    public static class AggregateResult {
        List<String> decryptedMsgs;
        long totalTime;
        boolean isConsistent;
        public AggregateResult(List<String> decryptedMsgs, long totalTime, boolean isConsistent) {
            this.decryptedMsgs = decryptedMsgs;
            this.totalTime = totalTime;
            this.isConsistent = isConsistent;
        }
    }

    // 辅助工具方法
    private static Element hashToZr(byte[] input) {
        try {
            MessageDigest md = MessageDigest.getInstance(HASH_ALG);
            byte[] hash = md.digest(input);
            return bp.getZr().newElementFromHash(hash, 0, hash.length).getImmutable();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("哈希函数执行失败", e);
        }
    }
    private static byte[] hashToBytes(byte[] input) {
        try {
            MessageDigest md = MessageDigest.getInstance(HASH_ALG);
            return md.digest(input);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("哈希函数执行失败", e);
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

    // 主函数：包含单密文实验 + 聚合实验
    public static void main(String[] args) {
        // 系统初始化（安全参数192）
        setup(192);

        // 1. 执行单密文签密/解签密实验
        singleCipherExperiment(300); // 密文有效期300秒

        // 2. 执行聚合实验（自定义数量）
        customAggregateUnsigncrypt(100, 300);  // 聚合2个密文
        customAggregateUnsigncrypt(300, 300);  // 聚合5个密文
        customAggregateUnsigncrypt(500, 300); // 聚合10个密文
        customAggregateUnsigncrypt(700, 300); // 聚合10个密文
        customAggregateUnsigncrypt(1000, 300); // 聚合10个密文

    }
}