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
import java.util.List;
import java.util.Random;

/**
 * 恢复单密文实验的CIOOHSC方案（纯 ECC secp192r1）
 * 核心特性：保留单密文签密/解签密独立流程 + 自定义聚合数量功能
 * 技术栈：BouncyCastle 1.83 + secp192r1 (96-bit security)
 */
public class EOFHASC29 {
    // 系统全局参数
    private static ECCurve curve;
    private static ECPoint G;
    private static BigInteger n;
    private static ECPoint Ppub;
    private static BigInteger kappa;
    private static SecureRandom random;
    // 固定发送者/接收者身份
    private static final String FIXED_SENDER_ID = "Vehicle-Fixed-001";
    private static final String FIXED_RECEIVER_ID = "RSU-Fixed-001";

    // 哈希函数定义（严格匹配论文4个哈希函数）
    private static BigInteger H0(byte[] input) { return hashToZr(input); }
    private static BigInteger H1(byte[] ID, ECPoint A) {
        byte[] combined = concat(ID, A.getEncoded(false));
        return hashToZr(combined);
    }
    private static byte[] H2(ECPoint U) { return hashToBytes(U.getEncoded(false)); }
    private static BigInteger H3(byte[] m, BigInteger PID_s, ECPoint B, ECPoint C, ECPoint U, long T) {
        byte[] combined = concat(m, PID_s.toByteArray(), B.getEncoded(false), C.getEncoded(false), U.getEncoded(false), String.valueOf(T).getBytes(StandardCharsets.UTF_8));
        return hashToZr(combined);
    }

    // 辅助类定义
    public static class PartialPrivateKey {
        BigInteger delta;
        ECPoint A;
        public PartialPrivateKey(BigInteger delta, ECPoint A) {
            this.delta = delta;
            this.A = A;
        }
    }
    public static class CLCVehicleKeyPair {
        String ID_s;
        BigInteger PID_s;
        BigInteger beta_s;
        BigInteger delta;
        ECPoint B;
        ECPoint C;
        public CLCVehicleKeyPair(String ID_s, BigInteger PID_s, BigInteger beta_s, BigInteger delta, ECPoint B, ECPoint C) {
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
        BigInteger Sk_r;
        ECPoint Pk_r;
        public IBCEdgeKeyPair(String ID_r, BigInteger Sk_r, ECPoint Pk_r) {
            this.ID_r = ID_r;
            this.Sk_r = Sk_r;
            this.Pk_r = Pk_r;
        }
    }
    public static class OfflineCiphertext {
        BigInteger eta;
        ECPoint U;
        ECPoint W;
        public OfflineCiphertext(BigInteger eta, ECPoint U, ECPoint W) {
            this.eta = eta;
            this.U = U;
            this.W = W;
        }
    }
    public static class OnlineCiphertext {
        byte[] mu;
        BigInteger chi;
        ECPoint W;
        long T;
        public OnlineCiphertext(byte[] mu, BigInteger chi, ECPoint W, long T) {
            this.mu = mu;
            this.chi = chi;
            this.W = W;
            this.T = T;
        }
    }

    // 1. 系统初始化
    public static void setup() {
        random = new SecureRandom();
        ECNamedCurveParameterSpec spec = ECNamedCurveTable.getParameterSpec("secp192r1");
        curve = spec.getCurve();
        G = spec.getG();
        n = spec.getN();

        kappa = new BigInteger(n.bitLength() - 1, random);
        Ppub = G.multiply(kappa).normalize();

        System.out.println("=== IoV CIOOHSC系统初始化完成 (纯 ECC secp192r1) ===");
        System.out.println("固定发送者ID：" + FIXED_SENDER_ID);
        System.out.println("固定接收者ID：" + FIXED_RECEIVER_ID);
        System.out.println("=================================");
    }

    // 2. 生成发送者密钥对
    private static CLCVehicleKeyPair generateSenderKeyPair() {
        BigInteger alpha = new BigInteger(n.bitLength() - 1, random);
        ECPoint A = G.multiply(alpha).normalize();
        byte[] ID_s_bytes = FIXED_SENDER_ID.getBytes(StandardCharsets.UTF_8);
        BigInteger PID_s = H1(ID_s_bytes, A);
        BigInteger kappa_PID_s = kappa.multiply(PID_s).mod(n);
        BigInteger delta = alpha.add(kappa_PID_s).mod(n);
        PartialPrivateKey psk = new PartialPrivateKey(delta, A);

        // 验证部分私钥
        ECPoint delta_P = G.multiply(delta).normalize();
        ECPoint PID_s_Ppub = Ppub.multiply(PID_s).normalize();
        ECPoint A_PID_s_Ppub = A.add(PID_s_Ppub).normalize();
        if (!delta_P.equals(A_PID_s_Ppub)) {
            throw new RuntimeException("发送者密钥生成失败：部分私钥验证不通过");
        }

        BigInteger beta_s = new BigInteger(n.bitLength() - 1, random);
        ECPoint B = G.multiply(delta).normalize();
        ECPoint C = G.multiply(beta_s).normalize();
        return new CLCVehicleKeyPair(FIXED_SENDER_ID, PID_s, beta_s, delta, B, C);
    }

    // 3. 生成接收者密钥对
    private static IBCEdgeKeyPair generateReceiverKeyPair() {
        byte[] ID_r_bytes = FIXED_RECEIVER_ID.getBytes(StandardCharsets.UTF_8);
        BigInteger gamma = new BigInteger(n.bitLength() - 1, random);
        ECPoint Q_r_temp = curve.getInfinity();
        BigInteger Q_r = H1(ID_r_bytes, Q_r_temp);
        BigInteger kappa_Q_r = kappa.multiply(Q_r).mod(n);
        BigInteger Sk_r = gamma.add(kappa_Q_r).mod(n);
        BigInteger Sk_r_inv = Sk_r.modInverse(n);
        ECPoint Pk_r = G.multiply(Sk_r_inv).normalize();
        return new IBCEdgeKeyPair(FIXED_RECEIVER_ID, Sk_r, Pk_r);
    }

    // 4. 离线签密
    private static OfflineCiphertext offlineSigncrypt(IBCEdgeKeyPair receiverKey) {
        BigInteger eta = new BigInteger(n.bitLength() - 1, random);
        ECPoint U = G.multiply(eta).normalize();
        ECPoint W = receiverKey.Pk_r.multiply(eta).normalize();
        return new OfflineCiphertext(eta, U, W);
    }

    // 5. 在线签密
    private static OnlineCiphertext onlineSigncrypt(String m, OfflineCiphertext offlineCipher, CLCVehicleKeyPair senderKey) {
        byte[] m_bytes = m.getBytes(StandardCharsets.UTF_8);
        long T = System.currentTimeMillis() / 1000;

        byte[] H2_U = H2(offlineCipher.U);
        byte[] mu = xor(m_bytes, H2_U);

        BigInteger theta = H3(m_bytes, senderKey.PID_s, senderKey.B, senderKey.C, offlineCipher.U, T);
        BigInteger beta_delta = senderKey.beta_s.add(senderKey.delta).mod(n);
        BigInteger theta_inv = theta.modInverse(n);
        BigInteger theta_inv_beta_delta = theta_inv.multiply(beta_delta).mod(n);
        BigInteger chi = theta_inv_beta_delta.add(offlineCipher.eta).mod(n);

        return new OnlineCiphertext(mu, chi, offlineCipher.W, T);
    }

    // 6. 单密文解签密
    private static String unsigncryptSingle(OnlineCiphertext cipher, CLCVehicleKeyPair senderKey, IBCEdgeKeyPair receiverKey, long maxDeltaT) {
        long currentTime = System.currentTimeMillis() / 1000;
        if (currentTime - cipher.T > maxDeltaT) {
            throw new RuntimeException("单密文解签密失败：密文已过期");
        }

        ECPoint U = cipher.W.multiply(receiverKey.Sk_r).normalize();
        byte[] H2_U = H2(U);
        byte[] m_bytes = xor(cipher.mu, H2_U);
        String m = new String(m_bytes, StandardCharsets.UTF_8);

        BigInteger theta = H3(m_bytes, senderKey.PID_s, senderKey.B, senderKey.C, U, cipher.T);
        ECPoint chi_P = G.multiply(cipher.chi).normalize();
        ECPoint B_C = senderKey.B.add(senderKey.C).normalize();
        BigInteger theta_inv = theta.modInverse(n);
        ECPoint theta_inv_BC = B_C.multiply(theta_inv).normalize();
        ECPoint verify = chi_P.subtract(theta_inv_BC).normalize();

        if (!verify.equals(U)) {
            throw new RuntimeException("单密文解签密失败：密文验证不通过");
        }

        return m;
    }

    // 单密文独立实验
    public static SingleExperimentResult singleCipherExperiment(long maxDeltaT) {
        System.out.println("\n=== 单密文签密/解签密实验开始 ===");

        CLCVehicleKeyPair senderKey = generateSenderKeyPair();
        IBCEdgeKeyPair receiverKey = generateReceiverKeyPair();

        String testMsg = String.format("V2I-Data: VehicleID=%s, Speed=%dkm/h, Time=%d, Type=Single",
                FIXED_SENDER_ID, 60 + new Random().nextInt(40), System.currentTimeMillis() / 1000);
        System.out.println("测试消息：" + testMsg);

        long offlineStart = System.nanoTime();
        OfflineCiphertext offlineCipher = offlineSigncrypt(receiverKey);
        long offlineTime = System.nanoTime() - offlineStart;

        long onlineStart = System.nanoTime();
        OnlineCiphertext onlineCipher = onlineSigncrypt(testMsg, offlineCipher, senderKey);
        long onlineTime = System.nanoTime() - onlineStart;

        long unsignStart = System.nanoTime();
        String decryptedMsg = unsigncryptSingle(onlineCipher, senderKey, receiverKey, maxDeltaT);
        long unsignTime = System.nanoTime() - unsignStart;

        boolean isConsistent = testMsg.equals(decryptedMsg);
        System.out.println("离线签密耗时：" + String.format("%.3f", offlineTime / 1_000_000.0) + " ms");
        System.out.println("在线签密耗时：" + String.format("%.3f", onlineTime / 1_000_000.0) + " ms");
        System.out.println("解签密耗时：" + String.format("%.3f", unsignTime / 1_000_000.0) + " ms");
        System.out.println("消息一致性：" + isConsistent);
        System.out.println("=== 单密文实验结束 ===");

        return new SingleExperimentResult(testMsg, decryptedMsg, offlineTime, onlineTime, unsignTime, isConsistent);
    }

    // 自定义聚合数量方法
    public static AggregateResult customAggregateUnsigncrypt(int aggregateCount, long maxDeltaT) {
        CLCVehicleKeyPair senderKey = generateSenderKeyPair();
        IBCEdgeKeyPair receiverKey = generateReceiverKeyPair();

        List<OnlineCiphertext> cipherList = new ArrayList<>();
        List<String> originalMsgs = new ArrayList<>();
        Random rand = new Random();

        for (int i = 0; i < aggregateCount; i++) {
            String msg = String.format("V2I-Data: VehicleID=%s, Speed=%dkm/h, Time=%d, Seq=%d, Type=Aggregate",
                    FIXED_SENDER_ID, 60 + rand.nextInt(40), System.currentTimeMillis() / 1000, i);
            originalMsgs.add(msg);

            OfflineCiphertext offlineCipher = offlineSigncrypt(receiverKey);
            OnlineCiphertext onlineCipher = onlineSigncrypt(msg, offlineCipher, senderKey);
            cipherList.add(onlineCipher);
        }

        long totalStartTime = System.nanoTime();

        List<String> decryptedMsgs = new ArrayList<>();
        BigInteger sumChi = BigInteger.ZERO;
        ECPoint sumThetaInvBC = curve.getInfinity();
        List<ECPoint> UList = new ArrayList<>();
        List<byte[]> mBytesList = new ArrayList<>();

        for (OnlineCiphertext cipher : cipherList) {
            long currentTime = System.currentTimeMillis() / 1000;
            if (currentTime - cipher.T > maxDeltaT) {
                throw new RuntimeException("聚合密文包含过期消息");
            }

            ECPoint U = cipher.W.multiply(receiverKey.Sk_r).normalize();
            UList.add(U);

            byte[] H2_U = H2(U);
            byte[] mBytes = xor(cipher.mu, H2_U);
            mBytesList.add(mBytes);

            BigInteger theta = H3(mBytes, senderKey.PID_s, senderKey.B, senderKey.C, U, cipher.T);
            sumChi = sumChi.add(cipher.chi).mod(n);
            ECPoint BC = senderKey.B.add(senderKey.C).normalize();
            BigInteger thetaInv = theta.modInverse(n);
            sumThetaInvBC = sumThetaInvBC.add(BC.multiply(thetaInv)).normalize();
        }

        ECPoint sumChiP = G.multiply(sumChi).normalize();
        ECPoint verifyLeft = sumChiP.subtract(sumThetaInvBC).normalize();
        ECPoint verifyRight = curve.getInfinity();
        for (ECPoint U : UList) {
            verifyRight = verifyRight.add(U).normalize();
        }
        if (!verifyLeft.equals(verifyRight)) {
            throw new RuntimeException("聚合验证失败：等式不成立");
        }

        for (byte[] mBytes : mBytesList) {
            decryptedMsgs.add(new String(mBytes, StandardCharsets.UTF_8));
        }

        long totalTime = System.nanoTime() - totalStartTime;
        boolean isConsistent = originalMsgs.equals(decryptedMsgs);

        System.out.println("\n=== 聚合解签密完成 ===");
        System.out.println("聚合密文数量：" + aggregateCount);
        System.out.println("总耗时：" + String.format("%.3f", totalTime / 1_000_000.0) + " ms");
        System.out.println("=================================");

        return new AggregateResult(decryptedMsgs, totalTime, isConsistent);
    }

    // 实验结果封装
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
    private static BigInteger hashToZr(byte[] input) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] hash = md.digest(input);
            return new BigInteger(1, hash).mod(n);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("哈希函数执行失败", e);
        }
    }
    private static byte[] hashToBytes(byte[] input) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
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
            int aIndex = a.length - len + i;
            int bIndex = b.length - len + i;
            byte aByte = (aIndex >= 0) ? a[aIndex] : 0;
            byte bByte = (bIndex >= 0) ? b[bIndex] : 0;
            result[i] = (byte) (aByte ^ bByte);
        }
        return result;
    }

    // 主函数
    public static void main(String[] args) {
        setup();

        // 1. 执行单密文签密/解签密实验
        singleCipherExperiment(300);

        // 2. 执行聚合实验
        customAggregateUnsigncrypt(100, 300);
        customAggregateUnsigncrypt(300, 300);
        customAggregateUnsigncrypt(500, 300);
        customAggregateUnsigncrypt(700, 300);
        customAggregateUnsigncrypt(1000, 300);
    }
}

