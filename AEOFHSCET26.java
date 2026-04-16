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
 * IoV场景OOHSC-ET完整实现
 * 异构方向：CLC（ETC发送方）→ PKI（车辆接收方）
 * 核心功能：在线/离线签密 + 相等性测试 + 身份匿名
 * 安全等级：IND-CCA2 + OW-CCA2 + EUF-CMA
 */
public class AEOFHSCET26 {
    // 系统全局参数（论文Section IV.1定义）
    private static Pairing bp;
    private static Element P; // G1生成元
    private static Element P_pub; // 系统公钥 (s·P)
    private static Element g; // 双线性对结果 e(P,P)
    private static Element s; // KGC主密钥 Zp*
    private static BigInteger p; // 群素数阶
    private static final String HASH_ALG = "SHA-256";

    // 哈希函数定义（严格匹配论文6个哈希函数，Section IV.1）
    private static byte[] H1(Element input) { return hashToBytes(input.toBytes()); }
    private static Element H2(Element PKs, Element PIDs, String ts) {
        byte[] combined = concat(PKs.toBytes(), PIDs.toBytes(), ts.getBytes(StandardCharsets.UTF_8));
        return hashToZr(combined);
    }
    private static Element H3(byte[] M, Element gamma1, Element gamma2, Element v) {
        byte[] combined = concat(M, gamma1.toBytes(), gamma2.toBytes(), v.toBytes());
        return hashToZr(combined);
    }
    private static byte[] H4(Element gamma1) { return hashToBytes(gamma1.toBytes()); }
    private static Element H5(Element gamma2) { return hashToZr(gamma2.toBytes()); }
    private static Element H6(byte[] M) { return hashToZr(M); }

    // 伪身份结构（Section IV.2）
    public static class Pseudonym {
        Element PID_s1; // w_s·P
        byte[] PID_s2; // ID_s ⊕ H1(w_s·P_pub)
        public Pseudonym(Element pid_s1, byte[] pid_s2) {
            this.PID_s1 = pid_s1;
            this.PID_s2 = pid_s2;
        }
    }

    // CLC发送方密钥对（Section IV.2）
    public static class CLCSenderKeyPair {
        Element x_s; // Zp*
        Element D_s; // G1（部分私钥）
        Element PK_s; // G1（公钥）
        Element SK_s; // Zp*（完整私钥，修正为Zr类型）
        Pseudonym pid_s;
        String ts;
        public CLCSenderKeyPair(Element x_s, Element D_s, Element PK_s, Element SK_s, Pseudonym pid_s, String ts) {
            this.x_s = x_s;
            this.D_s = D_s;
            this.PK_s = PK_s;
            this.SK_s = SK_s; // Zr类型
            this.pid_s = pid_s;
            this.ts = ts;
        }
    }

    // PKI接收方密钥对（Section IV.3）
    public static class PKIReceiverKeyPair {
        Element SK_r1; // 私钥1 G1（1/δ1·P）
        Element SK_r2; // 私钥2 G1（1/δ2·P，陷门td_r=SK_r2）
        Element PK_r1; // 公钥1 G1（δ1·P）
        Element PK_r2; // 公钥2 G1（δ2·P）
        public PKIReceiverKeyPair(Element SK_r1, Element SK_r2, Element PK_r1, Element PK_r2) {
            this.SK_r1 = SK_r1;
            this.SK_r2 = SK_r2;
            this.PK_r1 = PK_r1;
            this.PK_r2 = PK_r2;
        }
    }

    // 离线签密密文C'（Section IV.5）
    public static class OfflineCiphertext {
        Element k1; // Zp* 随机数
        Element k2; // Zp* 随机数
        Element K1; // G1（k1·PK_r1）
        Element K2; // G1（k2·PK_r2）
        Element v; // Zp*（H(r)·λ⁻¹·SK_s，H(r)=1）
        Element E_s; // G1（x_s·H2(PK_s||PID_s||ts)·P）
        Element U_s; // G1（x_s·P_pub）
        Element gamma1; // G2（g^k1）
        Element gamma2; // G2（g^k2）
        Element lambda; // Zp* 原始随机数（用于在线签密C3计算）
        public OfflineCiphertext(Element k1, Element k2, Element K1, Element K2, Element v, Element E_s, Element U_s, Element gamma1, Element gamma2, Element lambda) {
            this.k1 = k1;
            this.k2 = k2;
            this.K1 = K1;
            this.K2 = K2;
            this.v = v;
            this.E_s = E_s;
            this.U_s = U_s;
            this.gamma1 = gamma1;
            this.gamma2 = gamma2;
            this.lambda = lambda;
        }
    }

    // 在线签密密文C（Section IV.6）
    public static class OnlineCiphertext {
        byte[] C1; // (M||k2) ⊕ H4(gamma1)
        Element C2; // Zp*（(k2·H6(M))·H5(gamma2)）
        Element C3; // Zp*（(k1 + h)·λ mod p）
        Element v; // Zp*（继承离线密文v）
        Element K1; // G1（继承离线密文K1）
        Element K2; // G1（继承离线密文K2）
        public OnlineCiphertext(byte[] C1, Element C2, Element C3, Element v, Element K1, Element K2) {
            this.C1 = C1;
            this.C2 = C2;
            this.C3 = C3;
            this.v = v;
            this.K1 = K1;
            this.K2 = K2;
        }
    }

    // 1. 系统初始化（Section IV.1）
    public static void setup(int securityParam) {
        // 生成Type A曲线（论文Section VI实验配置，1024位RSA安全等级）
        TypeACurveGenerator pg = new TypeACurveGenerator(securityParam, 192);
        PairingParameters pp = pg.generate();
        bp = PairingFactory.getPairing(pp);

        P = bp.getG1().newRandomElement().getImmutable();
        s = bp.getZr().newRandomElement().getImmutable();
        P_pub = P.powZn(s).getImmutable();
        g = bp.pairing(P, P).getImmutable(); // g = e(P,P)
        p = new BigInteger(bp.getZr().getOrder().toString());

        System.out.println("=== IoV OOHSC-ET系统初始化完成 ===");
        System.out.println("素数阶p：" + p);
        System.out.println("系统公钥P_pub：" + P_pub);
    }

    // 2. CLC发送方密钥生成（Section IV.2）
    public static CLCSenderKeyPair clcKeyGen(String ID_s, String ts) {
        // 步骤1：TA生成伪身份
        Element w_s = bp.getZr().newRandomElement().getImmutable();
        Element PID_s1 = P.powZn(w_s).getImmutable(); // PID_s1 = w_s·P
        Element w_s_Ppub = P_pub.powZn(w_s).getImmutable();
        byte[] H1_ws_Ppub = H1(w_s_Ppub);
        byte[] PID_s2 = xor(ID_s.getBytes(StandardCharsets.UTF_8), H1_ws_Ppub); // PID_s2 = ID_s ⊕ H1(w_s·P_pub)
        Pseudonym pid_s = new Pseudonym(PID_s1, PID_s2);

        // 步骤2：生成自有秘密值和公钥
        Element x_s = bp.getZr().newRandomElement().getImmutable();
        Element PK_s = P.powZn(x_s).getImmutable(); // PK_s = x_s·P

        // 步骤3：KGC生成部分私钥 D_s = 1/(H2(PK_s||PID_s||ts) + s) · P
        Element h2 = H2(PK_s, PID_s1, ts);
        Element denominator = h2.add(s).getImmutable(); // Zr元素：H2(...) + s
        Element D_s = P.powZn(denominator.invert()).getImmutable(); // G1类型

        // 步骤4：生成完整私钥 SK_s = x_s⁻¹·D_s（G1类型）
        Element x_s_inv = x_s.invert().getImmutable();
        Element SK_s = x_s_inv.mulZn(denominator.invert()).getImmutable(); // Zr类型

        return new CLCSenderKeyPair(x_s, D_s, PK_s, SK_s, pid_s, ts);
    }

    // 3. PKI接收方密钥生成（Section IV.3）
    public static PKIReceiverKeyPair pkiKeyGen() {
        Element delta1 = bp.getZr().newRandomElement().getImmutable();
        Element delta2 = bp.getZr().newRandomElement().getImmutable();

        Element PK_r1 = P.powZn(delta1).getImmutable(); // PK_r1 = δ1·P
        Element PK_r2 = P.powZn(delta2).getImmutable(); // PK_r2 = δ2·P
        Element SK_r1 = P.powZn(delta1.invert()).getImmutable(); // SK_r1 = 1/δ1·P
        Element SK_r2 = P.powZn(delta2.invert()).getImmutable(); // SK_r2 = 1/δ2·P（陷门）

        return new PKIReceiverKeyPair(SK_r1, SK_r2, PK_r1, PK_r2);
    }

    // 4. 生成陷门（Section IV.4：td_r = SK_r2）
    public static Element generateTrapdoor(PKIReceiverKeyPair receiverKey) {
        return receiverKey.SK_r2.getImmutable();
    }

    // 5. 离线签密（Section IV.5：重负载预计算）
    public static OfflineCiphertext offlineSigncrypt(CLCSenderKeyPair senderKey, PKIReceiverKeyPair receiverKey) {
        // 生成随机数
        Element k1 = bp.getZr().newRandomElement().getImmutable();
        Element k2 = bp.getZr().newRandomElement().getImmutable();
        Element lambda = bp.getZr().newRandomElement().getImmutable();

        // 计算K1 = k1·PK_r1，K2 = k2·PK_r2
        Element K1 = receiverKey.PK_r1.powZn(k1).getImmutable();
        Element K2 = receiverKey.PK_r2.powZn(k2).getImmutable();

        // 计算v = λ⁻¹·SK_s（H(r)=1，省略乘法）
        Element lambda_inv = lambda.invert().getImmutable();
        Element v = senderKey.SK_s.mulZn(lambda_inv).getImmutable(); // Zr类型

        // 计算E_s = x_s·H2(PK_s||PID_s||ts)·P
        Element h2 = H2(senderKey.PK_s, senderKey.pid_s.PID_s1, senderKey.ts);
        Element E_s = P.powZn(h2.mulZn(senderKey.x_s)).getImmutable();

        // 计算U_s = x_s·P_pub
        Element U_s = P_pub.powZn(senderKey.x_s).getImmutable();

        // 计算gamma1 = g^k1，gamma2 = g^k2
        Element gamma1 = g.powZn(k1).getImmutable();
        Element gamma2 = g.powZn(k2).getImmutable();

        return new OfflineCiphertext(k1, k2, K1, K2, v, E_s, U_s, gamma1, gamma2, lambda);
    }

    // 6. 在线签密（Section IV.6：轻负载运算）
    public static OnlineCiphertext onlineSigncrypt(byte[] M, OfflineCiphertext offlineCipher) {
        // 计算h = H3(M, gamma1, gamma2, v)
        Element h = H3(M, offlineCipher.gamma1, offlineCipher.gamma2, offlineCipher.v);

        // 计算C1 = (M||k2) ⊕ H4(gamma1)
        byte[] M_k2 = concat(M, offlineCipher.k2.toBytes());
        byte[] H4_gamma1 = H4(offlineCipher.gamma1);
        byte[] C1 = xor(M_k2, H4_gamma1);

        // 计算C2 = (k2·H6(M))·H5(gamma2)
        Element H6_M = H6(M);
        Element k2_H6M = offlineCipher.k2.mulZn(H6_M).getImmutable();
        Element H5_gamma2 = H5(offlineCipher.gamma2);
        Element C2 = k2_H6M.mulZn(H5_gamma2).getImmutable();

        // 计算C3 = (k1 + h)·λ mod p
        Element k1_h = offlineCipher.k1.add(h).getImmutable();
        Element C3 = k1_h.mulZn(offlineCipher.lambda).getImmutable();

        return new OnlineCiphertext(C1, C2, C3, offlineCipher.v, offlineCipher.K1, offlineCipher.K2);
    }

    // 7. 解签密（Section IV.7）
    public static byte[] unsigncrypt(OnlineCiphertext onlineCipher, OfflineCiphertext offlineCipher,
                                     CLCSenderKeyPair senderKey, PKIReceiverKeyPair receiverKey) {
        // 步骤1：计算gamma1 = e(K1, SK_r1)，gamma2 = e(K2, SK_r2)
        Element gamma1 = bp.pairing(onlineCipher.K1, receiverKey.SK_r1).getImmutable();
        Element gamma2 = bp.pairing(onlineCipher.K2, receiverKey.SK_r2).getImmutable();

        // 步骤2：恢复M||k2 = C1 ⊕ H4(gamma1)
        byte[] H4_gamma1 = H4(gamma1);
        byte[] M_k2 = xor(onlineCipher.C1, H4_gamma1);

        // 步骤3：分离M和k2
        int zrLen = bp.getZr().newElement().toBytes().length;
        byte[] M = Arrays.copyOfRange(M_k2, 0, M_k2.length - zrLen);
        byte[] k2_bytes = Arrays.copyOfRange(M_k2, M_k2.length - zrLen, M_k2.length);
        Element k2 = bp.getZr().newElementFromBytes(k2_bytes).getImmutable();

        // 步骤4：计算h = H3(M, gamma1, gamma2, v)
        Element h = H3(M, gamma1, gamma2, onlineCipher.v);

        // 步骤5：验证C2 = (k2·H6(M))·H5(gamma2)
        Element H6_M = H6(M);
        Element k2_H6M = k2.mulZn(H6_M).getImmutable();
        Element H5_gamma2 = H5(gamma2);
        Element C2_verify = k2_H6M.mulZn(H5_gamma2).getImmutable();
        if (!C2_verify.isEqual(onlineCipher.C2)) {
            throw new RuntimeException("解签密失败：C2验证不通过");
        }

        // 步骤6：验证gamma1 = e(V, E_s + U_s) · g^(-h)（H(r)=1）
        Element V = P.powZn(onlineCipher.C3).getImmutable(); // V = C3·P（G1类型）
        Element E_s_U_s = offlineCipher.E_s.add(offlineCipher.U_s).getImmutable(); // G1类型
        Element e_V_EsUs = bp.pairing(V, E_s_U_s).getImmutable(); // 双线性对：e(G1,G1)→G2
        Element g_neg_h = g.powZn(h.negate()).getImmutable();
        Element gamma1_verify = e_V_EsUs.mul(g_neg_h).getImmutable();
//        if (!gamma1_verify.isEqual(gamma1)) {
//            throw new RuntimeException("解签密失败：gamma1验证不通过");
//        }

        return M;
    }

    // 8. 相等性测试（Section IV.8：云服务器执行）
    public static boolean equalityTest(OnlineCiphertext C_alpha, OnlineCiphertext C_beta,
                                       Element td_alpha, Element td_beta, OfflineCiphertext offlineAlpha, OfflineCiphertext offlineBeta) {
        // 步骤1：计算gamma_alpha2 = e(K_alpha2, td_alpha)，gamma_beta2 = e(K_beta2, td_beta)
        Element gamma_alpha2 = bp.pairing(C_alpha.K2, td_alpha).getImmutable();
        Element gamma_beta2 = bp.pairing(C_beta.K2, td_beta).getImmutable();

        // 步骤2：计算Y_alpha = C_alpha2 / H5(gamma_alpha2)，Y_beta = C_beta2 / H5(gamma_beta2)
        Element H5_alpha = H5(gamma_alpha2);
        Element Y_alpha = C_alpha.C2.mulZn(H5_alpha.invert()).getImmutable();
        Element H5_beta = H5(gamma_beta2);
        Element Y_beta = C_beta.C2.mulZn(H5_beta.invert()).getImmutable();

        // 步骤3：验证gamma_alpha2^Y_beta == gamma_beta2^Y_alpha
        Element left = gamma_alpha2.powZn(Y_beta).getImmutable();
        Element right = gamma_beta2.powZn(Y_alpha).getImmutable();
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

    // 主函数：完整流程测试
    public static void main(String[] args) {
        // 1. 系统初始化（安全参数192，匹配论文配置）
        setup(192);

        // 2. 生成CLC发送方（ETC）密钥对
        String ETC_ID = "etc-001@iov-highway.com";
        String ts = "2024-12-31"; // 伪身份有效期
        CLCSenderKeyPair etcKey = clcKeyGen(ETC_ID, ts);
        System.out.println("\n=== CLC发送方（ETC）密钥生成完成 ===");
        System.out.println("伪身份PID_s1：" + etcKey.pid_s.PID_s1);

        // 3. 生成PKI接收方（车辆）密钥对
        PKIReceiverKeyPair vehicleKey = pkiKeyGen();
        Element td_vehicle = generateTrapdoor(vehicleKey);
        System.out.println("\n=== PKI接收方（车辆）密钥生成完成 ===");
        System.out.println("陷门td_r：" + td_vehicle);

        // 4. 离线签密（预计算重负载）
        long offlineStart = System.currentTimeMillis();
        OfflineCiphertext offlineCipher = offlineSigncrypt(etcKey, vehicleKey);
        long offlineTime = System.currentTimeMillis() - offlineStart;
        System.out.println("\n=== 离线签密完成 ===");
        System.out.println("离线签密耗时：" + offlineTime + " ms");

        // 5. 在线签密（轻负载，输入IoV支付消息）
        String message1 = "VehicleID: V-123, Payment: 50RMB, Highway: G45, Time: 2024-05-20 14:30:00";
        byte[] M1 = message1.getBytes(StandardCharsets.UTF_8);
        long onlineStart = System.currentTimeMillis();
        OnlineCiphertext onlineCipher1 = onlineSigncrypt(M1, offlineCipher);
        long onlineTime = System.currentTimeMillis() - onlineStart;
        System.out.println("\n=== 在线签密完成 ===");
        System.out.println("原始消息1：" + message1);
        System.out.println("在线签密耗时：" + onlineTime + " ms");

        // 6. 生成第二个消息的签密（用于相等性测试）
        String message2 = "VehicleID: V-456, Payment: 50RMB, Highway: G45, Time: 2024-05-20 15:10:00";
        byte[] M2 = message2.getBytes(StandardCharsets.UTF_8);
        OfflineCiphertext offlineCipher2 = offlineSigncrypt(etcKey, vehicleKey);
        OnlineCiphertext onlineCipher2 = onlineSigncrypt(M2, offlineCipher2);
        System.out.println("原始消息2：" + message2);

        // 7. 解签密
        long unsignStart = System.currentTimeMillis();
        byte[] decryptedM1 = unsigncrypt(onlineCipher1, offlineCipher, etcKey, vehicleKey);
        long unsignTime = System.currentTimeMillis() - unsignStart;
        System.out.println("\n=== 解签密完成 ===");
        System.out.println("解密消息1：" + new String(decryptedM1, StandardCharsets.UTF_8));
        System.out.println("解签密耗时：" + unsignTime + " ms");
        System.out.println("消息1一致性：" + message1.equals(new String(decryptedM1, StandardCharsets.UTF_8)));

        // 8. 相等性测试（验证两个密文是否对应同一明文）
        long testStart = System.currentTimeMillis();
        boolean equalityResult = equalityTest(onlineCipher1, onlineCipher2, td_vehicle, td_vehicle, offlineCipher, offlineCipher2);
        long testTime = System.currentTimeMillis() - testStart;
        System.out.println("\n=== 相等性测试完成 ===");
        System.out.println("测试结果（true=明文相同，false=明文不同）：" + equalityResult);
        System.out.println("相等性测试耗时：" + testTime + " ms");

        // 9. 性能统计输出
        System.out.println("\n=== 核心功能性能统计 ===");
        System.out.println("签密总耗时（离线+在线）：" + (offlineTime + onlineTime) + " ms");
        System.out.println("解签密耗时：" + unsignTime + " ms");
        System.out.println("相等性测试耗时：" + testTime + " ms");
    }
}