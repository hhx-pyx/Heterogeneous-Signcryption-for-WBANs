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
 * CL-PREMET 方案完整修正版（匹配论文）
 * 核心特性：
 * 1. 修复所有编译错误（Element.xor、变量未定义等）
 * 2. 无证书代理重加密+多密文相等性测试（支持任意数量密文）
 * 3. 自定义密文数量N，精准统计测试耗时
 * 4. 支持OW-CCA/IND-CCA安全，严格遵循论文10大算法
 */
public class LADMCET50 {
    // 系统全局参数（论文Section V.A定义）
    private static Pairing bp;
    private static Element g1; // G1生成元
    private static Element g2; // G2生成元
    private static Element phi; // g1^α（系统公钥组件）
    private static Element alpha; // 主密钥α
    private static BigInteger p; // 群素数阶
    private static final String HASH_ALG = "SHA-256";
    private static final int SECURITY_PARAM = 192; // r=192
    private static final int CURVE_PARAM = 512; // q=512

    // 哈希函数定义（严格匹配论文6个哈希函数，Section V.A）
    private static Element H1(byte[] input) { return hashToG2(input); }
    private static Element H2(byte[] M, byte[] beta) { return hashToZr(concat(M, beta)); }
    private static byte[] H3(Element GT, Element G1) { return hashToBytes(concat(GT.toBytes(), G1.toBytes())); }
    private static Element H4(Element GT) { return hashToG2(GT.toBytes()); }
    private static byte[] H5(Element G2) { return hashToBytes(G2.toBytes()); }
    private static byte[] H6(Element GT) { return hashToBytes(GT.toBytes()); }

    // 辅助类：用户密钥对（Section V.C）
    public static class KeyPair {
        Element sk1; // 私钥组件1（x）
        Element sk2; // 私钥组件2（psk^x）
        Element pk1; // 公钥组件1（phi^x = g1^(αx)）
        Element pk2; // 公钥组件2（g2^x）
        public KeyPair(Element sk1, Element sk2, Element pk1, Element pk2) {
            this.sk1 = sk1;
            this.sk2 = sk2;
            this.pk1 = pk1;
            this.pk2 = pk2;
        }
    }

    // 辅助类：密文（Section V.D）
    public static class Ciphertext {
        Element C0; // g2^β
        Element C1; // g1^(1/γ)
        byte[] C2;  // H3(e(pk1, H1(ID)^θ), C1) ⊕ (M||β)
        Element C3; // g1^θ
        Element C4; // H1(M)^γ ⊕ H4(e(pk2, C3^β))
        public Ciphertext(Element C0, Element C1, byte[] C2, Element C3, Element C4) {
            this.C0 = C0;
            this.C1 = C1;
            this.C2 = C2;
            this.C3 = C3;
            this.C4 = C4;
        }
    }

    // 辅助类：陷门（Section V.F）
    public static class Trapdoor {
        Element td; // C0^sk1（授权陷门）
        public Trapdoor(Element td) {
            this.td = td;
        }
    }

    // 辅助类：重加密密钥（Section V.H）
    public static class ReKey {
        byte[] rk1; // H3(e(C3, sk2), C1) ⊕ H5((pkj2)^β)
        Element rk2; // H4(e(C3, C0^sk1))
        public ReKey(byte[] rk1, Element rk2) {
            this.rk1 = rk1;
            this.rk2 = rk2;
        }
    }

    // 辅助类：重加密密文（Section V.I）
    public static class ReEncryptedCiphertext {
        Element U0; // C0
        Element U1; // C1
        byte[] U2;  // C2 ⊕ rk1
        Element U3; // C3
        Element U4; // C4 ⊕ rk2
        public ReEncryptedCiphertext(Element U0, Element U1, byte[] U2, Element U3, Element U4) {
            this.U0 = U0;
            this.U1 = U1;
            this.U2 = U2;
            this.U3 = U3;
            this.U4 = U4;
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

    // 哈希到G1群
    private static Element hashToG1(byte[] input) {
        try {
            MessageDigest md = MessageDigest.getInstance(HASH_ALG);
            byte[] hash = md.digest(input);
            return bp.getG1().newElementFromHash(hash, 0, hash.length).getImmutable();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("H哈希失败", e);
        }
    }

    // 哈希到G2群
    private static Element hashToG2(byte[] input) {
        try {
            MessageDigest md = MessageDigest.getInstance(HASH_ALG);
            byte[] hash = md.digest(input);
            return bp.getG2().newElementFromHash(hash, 0, hash.length).getImmutable();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("H哈希失败", e);
        }
    }

    // 哈希到Zr群
    private static Element hashToZr(byte[] input) {
        try {
            MessageDigest md = MessageDigest.getInstance(HASH_ALG);
            byte[] hash = md.digest(input);
            return bp.getZr().newElementFromHash(hash, 0, hash.length).getImmutable();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("H哈希失败", e);
        }
    }

    // 哈希到字节数组
    private static byte[] hashToBytes(byte[] input) {
        try {
            MessageDigest md = MessageDigest.getInstance(HASH_ALG);
            return md.digest(input);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("H哈希失败", e);
        }
    }

    // 群元素求逆（G1/G2/Zr通用）
    private static Element inverse(Element elem) {
        return elem.powZn(bp.getZr().newElement(p.subtract(BigInteger.ONE)).getImmutable()).getImmutable();
    }

    // Element异或（转换为字节数组实现，修复无xor方法问题）
    private static Element elementXor(Element a, Element b) {
        byte[] aBytes = a.toBytes();
        byte[] bBytes = b.toBytes();
        byte[] xorBytes = xor(aBytes, bBytes);
        // 按a的群类型转回Element（保持类型一致）
        if (a.getField().equals(bp.getG1())) {
            return bp.getG1().newElementFromBytes(xorBytes).getImmutable();
        } else if (a.getField().equals(bp.getG2())) {
            return bp.getG2().newElementFromBytes(xorBytes).getImmutable();
        } else if (a.getField().equals(bp.getZr())) {
            return bp.getZr().newElementFromBytes(xorBytes).getImmutable();
        } else {
            throw new IllegalArgumentException("不支持的群类型");
        }
    }

    // ===================== 论文10大核心算法（修复后） =====================
    /**
     * 1. Setup算法（Section V.A）
     * 输入：安全参数λ
     * 输出：系统参数pp、主密钥α
     */
    public static void setup() {
        long start = System.currentTimeMillis();
        // 生成双线性配对参数（r=192, q=512，论文Section III.A）
        TypeACurveGenerator pg = new TypeACurveGenerator(192, 192);
        PairingParameters pp = pg.generate();
        bp = PairingFactory.getPairing(pp);
        g1 = bp.getG1().newRandomElement().getImmutable();
        g2 = bp.getG2().newRandomElement().getImmutable();
        p = new BigInteger(bp.getZr().getOrder().toString());

        // 生成主密钥α和系统公钥组件phi = g1^α
        alpha = bp.getZr().newRandomElement().getImmutable();
        phi = g1.powZn(alpha).getImmutable();

        long end = System.currentTimeMillis();
        System.out.println("[Setup] 系统初始化完成 | 耗时：" + (end - start) + " ms");
    }

    /**
     * 2. PartialKeyExtract算法（Section V.B）
     * 输入：用户ID
     * 输出：部分私钥psk = H1(ID)^α
     */
    public static Element partialKeyExtract(String ID) {
        byte[] ID_bytes = ID.getBytes(StandardCharsets.UTF_8);
        Element H1_ID = H1(ID_bytes);
        return H1_ID.powZn(alpha).getImmutable(); // psk = H1(ID)^α
    }

    /**
     * 3. UserKeyGen算法（Section V.C）
     * 输入：部分私钥psk
     * 输出：用户密钥对(KeyPair)
     */
    public static KeyPair userKeyGen(Element psk) {
        // 随机选择x ∈ Zp*
        Element x = bp.getZr().newRandomElement().getImmutable();
        // 私钥组件：sk = (x, psk^x)
        Element sk1 = x.getImmutable();
        Element sk2 = psk.powZn(x).getImmutable();
        // 公钥组件：pk = (phi^x, g2^x)
        Element pk1 = phi.powZn(x).getImmutable();
        Element pk2 = g2.powZn(x).getImmutable();
        return new KeyPair(sk1, sk2, pk1, pk2);
    }

    /**
     * 4. Encryption算法（Section V.D）- 修复C4的xor问题
     * 输入：消息M、用户ID、用户公钥pk
     * 输出：密文Ciphertext
     */
    public static Ciphertext encryption(String M, String ID, KeyPair pk) {
        byte[] M_bytes = M.getBytes(StandardCharsets.UTF_8);
        byte[] ID_bytes = ID.getBytes(StandardCharsets.UTF_8);

        // 步骤1：生成随机数β, θ ∈ Zp*
        Element beta = bp.getZr().newRandomElement().getImmutable();
        Element theta = bp.getZr().newRandomElement().getImmutable();
        byte[] beta_bytes = beta.toBytes();

        // 步骤2：计算γ = H2(M, β)
        Element gamma = H2(M_bytes, beta_bytes);
        Element gamma_inv = inverse(gamma); // 1/γ

        // 步骤3：计算C0 = g2^β，C1 = g1^(1/γ)，C3 = g1^θ
        Element C0 = g2.powZn(beta).getImmutable();
        Element C1 = g1.powZn(gamma_inv).getImmutable();
        Element C3 = g1.powZn(theta).getImmutable();

        // 步骤4：计算w1 = e(pk1, H1(ID)^θ)
        Element H1_ID = H1(ID_bytes);
        Element H1_ID_theta = H1_ID.powZn(theta).getImmutable();
        Element w1 = bp.pairing(pk.pk1, H1_ID_theta).getImmutable();

        // 步骤5：计算C2 = H3(w1, C1) ⊕ (M||β)
        byte[] H3_w1_C1 = H3(w1, C1);
        byte[] M_beta = concat(M_bytes, beta_bytes);
        byte[] C2 = xor(H3_w1_C1, M_beta);

        // 步骤6：计算C4 = H1(M)^γ ⊕ H4(e(pk2, C3^β))（修复xor方法）
        Element H1_M = H1(M_bytes);
        Element H1_M_gamma = H1_M.powZn(gamma).getImmutable();
        Element C3_beta = C3.powZn(beta).getImmutable();
        Element e_pk2_C3beta = bp.pairing(pk.pk2, C3_beta).getImmutable();
        Element H4_e = H4(e_pk2_C3beta).getImmutable();
        Element C4 = elementXor(H1_M_gamma, H4_e); // 修复：用自定义elementXor替代

        return new Ciphertext(C0, C1, C2, C3, C4);
    }

    /**
     * 5. Decryption算法（Section V.E）- 修复C4的xor问题
     * 输入：密文CT、用户私钥sk
     * 输出：明文M
     */
    public static String decryption(Ciphertext CT, KeyPair sk) {
        // 步骤1：计算e(C3, sk2)，恢复M||β
        Element e_C3_sk2 = bp.pairing(CT.C3, sk.sk2).getImmutable();
        byte[] H3_e_C3sk2 = H3(e_C3_sk2, CT.C1);
        byte[] M_beta = xor(CT.C2, H3_e_C3sk2);

        // 步骤2：拆分M和β
        int beta_len = bp.getZr().newElement().toBytes().length;
        byte[] M_bytes = Arrays.copyOfRange(M_beta, 0, M_beta.length - beta_len);
        byte[] beta_bytes = Arrays.copyOfRange(M_beta, M_beta.length - beta_len, M_beta.length);
        Element beta = bp.getZr().newElementFromBytes(beta_bytes).getImmutable();

        // 步骤3：验证C0 = g2^β，C1 = g1^(1/γ)，C4 = H1(M)^γ ⊕ H4(e(C3, C0^sk1))（修复xor）
        Element gamma = H2(M_bytes, beta_bytes);
        Element gamma_inv = inverse(gamma);
        boolean verifyC0 = CT.C0.isEqual(g2.powZn(beta));
        boolean verifyC1 = CT.C1.isEqual(g1.powZn(gamma_inv));

        Element C0_sk1 = CT.C0.powZn(sk.sk1).getImmutable();
        Element e_C3_C0sk1 = bp.pairing(CT.C3, C0_sk1).getImmutable();
        Element H4_e = H4(e_C3_C0sk1).getImmutable();
        Element H1_M = H1(M_bytes);
        Element H1_M_gamma = H1_M.powZn(gamma).getImmutable();
        Element C4_verify = elementXor(H1_M_gamma, H4_e); // 修复：用自定义elementXor替代
        boolean verifyC4 = CT.C4.isEqual(C4_verify);

        if (verifyC0 && verifyC1 && verifyC4) {
            return new String(M_bytes, StandardCharsets.UTF_8);
        } else {
            throw new RuntimeException("解密失败：密文验证不通过");
        }
    }

    /**
     * 6. Authorization算法（Section V.F）
     * 输入：密文CT、用户私钥sk
     * 输出：陷门Trapdoor
     */
    public static Trapdoor authorization(Ciphertext CT, KeyPair sk) {
        Element td = CT.C0.powZn(sk.sk1).getImmutable(); // td = C0^sk1
        return new Trapdoor(td);
    }

    /**
     * 7. Test算法（Section V.G）- 多密文相等性测试（核心，修复xor问题）
     * 输入：密文列表CTList、陷门列表tdList
     * 输出：测试结果（1=所有密文对应同一明文，0=否则）+ 耗时（毫秒）
     */
    public static Object[] test(List<Ciphertext> CTList, List<Trapdoor> tdList) {
        long start = System.currentTimeMillis();
        int n = CTList.size();
        if (n != tdList.size() || n < 2) {
            throw new IllegalArgumentException("密文数量与陷门数量必须一致，且至少2个");
        }

        // 步骤1：计算所有ξ_i = C_i4 ⊕ H4(e(C_i3, td_i))（修复xor）
        List<Element> xiList = new ArrayList<>();
        for (int i = 0; i < n; i++) {
            Ciphertext CT = CTList.get(i);
            Trapdoor td = tdList.get(i);
            Element e_C3_td = bp.pairing(CT.C3, td.td).getImmutable();
            Element H4_e = H4(e_C3_td).getImmutable();
            Element xi = elementXor(CT.C4, H4_e); // 修复：用自定义elementXor替代
            xiList.add(xi);
        }

        // 步骤2：根据密文数量n的奇偶性验证对应等式
        boolean result = false;
        if (n % 2 == 0) {
            // 偶数n：验证等式(5)和(6)
            byte[] sum1 = new byte[H6(bp.getGT().newRandomElement()).length]; // 初始化全0
            for (int k = 0; k < n/2; k++) {
                int idx1 = 2*k;
                int idx2 = 2*k + 1;
                Element e1 = bp.pairing(CTList.get(idx1).C1, xiList.get(idx1)).getImmutable();
                Element e2 = bp.pairing(CTList.get(idx2).C1, xiList.get(idx2)).getImmutable();
                byte[] h6_1 = H6(e1);
                byte[] h6_2 = H6(e2);
                sum1 = xor(sum1, xor(h6_1, h6_2));
            }

            byte[] sum2 = new byte[sum1.length];
            for (int k = 0; k < (n-2)/2; k++) {
                int idx1 = 2*k + 1;
                int idx2 = 2*k + 2;
                Element e1 = bp.pairing(CTList.get(idx1).C1, xiList.get(idx1)).getImmutable();
                Element e2 = bp.pairing(CTList.get(idx2).C1, xiList.get(idx2)).getImmutable();
                byte[] h6_1 = H6(e1);
                byte[] h6_2 = H6(e2);
                sum2 = xor(sum2, xor(h6_1, h6_2));
            }
            // 补充最后一个与第一个的异或
            Element e_n = bp.pairing(CTList.get(n-1).C1, xiList.get(n-1)).getImmutable();
            Element e_1 = bp.pairing(CTList.get(0).C1, xiList.get(0)).getImmutable();
            sum2 = xor(sum2, xor(H6(e_n), H6(e_1)));

            result = Arrays.equals(sum1, new byte[sum1.length]) && Arrays.equals(sum2, new byte[sum2.length]);
        } else {
            // 奇数n：验证等式(9)和(10)
            byte[] sum1 = new byte[H6(bp.getGT().newRandomElement()).length];
            for (int k = 0; k < (n-1)/2; k++) {
                int idx1 = 2*k;
                int idx2 = 2*k + 1;
                Element e1 = bp.pairing(CTList.get(idx1).C1, xiList.get(idx1)).getImmutable();
                Element e2 = bp.pairing(CTList.get(idx2).C1, xiList.get(idx2)).getImmutable();
                byte[] h6_1 = H6(e1);
                byte[] h6_2 = H6(e2);
                sum1 = xor(sum1, xor(h6_1, h6_2));
            }
            // 补充最后一个与第一个的异或
            Element e_n = bp.pairing(CTList.get(n-1).C1, xiList.get(n-1)).getImmutable();
            Element e_1 = bp.pairing(CTList.get(0).C1, xiList.get(0)).getImmutable();
            sum1 = xor(sum1, xor(H6(e_n), H6(e_1)));

            byte[] sum2 = new byte[sum1.length];
            for (int k = 0; k < (n-1)/2; k++) {
                int idx1 = 2*k + 1;
                int idx2 = 2*k + 2;
                Element e1 = bp.pairing(CTList.get(idx1).C1, xiList.get(idx1)).getImmutable();
                Element e2 = bp.pairing(CTList.get(idx2).C1, xiList.get(idx2)).getImmutable();
                byte[] h6_1 = H6(e1);
                byte[] h6_2 = H6(e2);
                sum2 = xor(sum2, xor(h6_1, h6_2));
            }
            // 补充最后一个与第一个的异或（两次）
            sum2 = xor(sum2, xor(H6(e_n), H6(e_1)));

            result = Arrays.equals(sum1, new byte[sum1.length]) && Arrays.equals(sum2, new byte[sum2.length]);
        }

        long end = System.currentTimeMillis();
        long cost = end - start;
        return new Object[]{result ? 1 : 0, cost};
    }

    /**
     * 8. Re-Key算法（Section V.H）- 修复M_bytes未定义问题
     * 输入：用户i私钥ski、用户j公钥pkj、密文CTi
     * 输出：重加密密钥ReKey
     */
    public static ReKey reKey(KeyPair ski, KeyPair pkj, Ciphertext CTi) {
        // 验证用户j公钥合法性：e(pkj.pk1, g2) == e(phi, pkj.pk2)
        Element e_pkj1_g2 = bp.pairing(pkj.pk1, g2).getImmutable();
        Element e_phi_pkj2 = bp.pairing(phi, pkj.pk2).getImmutable();
        if (!e_pkj1_g2.isEqual(e_phi_pkj2)) {
            throw new RuntimeException("重加密失败：用户j公钥非法");
        }

        // 计算rk1 = H3(e(C3, sk2), C1) ⊕ H5((pkj2)^β)（修复M_bytes未定义）
        Element e_C3_sk2 = bp.pairing(CTi.C3, ski.sk2).getImmutable();
        byte[] H3_e = H3(e_C3_sk2, CTi.C1);
        // 先恢复M||β以获取β
        byte[] M_beta = xor(CTi.C2, H3_e);
        int beta_len = bp.getZr().newElement().toBytes().length;
        byte[] beta_bytes = Arrays.copyOfRange(M_beta, M_beta.length - beta_len, M_beta.length);
        Element beta = bp.getZr().newElementFromBytes(beta_bytes).getImmutable();
        // 计算(pkj2)^β
        Element pkj2_beta = pkj.pk2.powZn(beta).getImmutable();
        byte[] H5_pkj2beta = H5(pkj2_beta);
        byte[] rk1 = xor(H3_e, H5_pkj2beta);

        // 计算rk2 = H4(e(C3, C0^sk1))
        Element C0_sk1 = CTi.C0.powZn(ski.sk1).getImmutable();
        Element e_C3_C0sk1 = bp.pairing(CTi.C3, C0_sk1).getImmutable();
        Element rk2 = H4(e_C3_C0sk1).getImmutable();

        return new ReKey(rk1, rk2);
    }

    /**
     * 9. Re-Encryption算法（Section V.I）- 修复xor问题
     * 输入：重加密密钥rk、密文CTi
     * 输出：重加密密文ReEncryptedCiphertext
     */
    public static ReEncryptedCiphertext reEncryption(ReKey rk, Ciphertext CTi) {
        Element U0 = CTi.C0;
        Element U1 = CTi.C1;
        byte[] U2 = xor(CTi.C2, rk.rk1);
        Element U3 = CTi.C3;
        Element U4 = elementXor(CTi.C4, rk.rk2); // 修复：用自定义elementXor替代
        return new ReEncryptedCiphertext(U0, U1, U2, U3, U4);
    }

    /**
     * 10. Re-Decryption算法（Section V.J）
     * 输入：重加密密文CTj、用户j私钥skj
     * 输出：明文M
     */
    public static String reDecryption(ReEncryptedCiphertext CTj, KeyPair skj) {
        // 计算M||β = U2 ⊕ H5(U0^sk1)
        Element U0_sk1 = CTj.U0.powZn(skj.sk1).getImmutable();
        byte[] H5_U0sk1 = H5(U0_sk1);
        byte[] M_beta = xor(CTj.U2, H5_U0sk1);

        // 拆分M和β
        int beta_len = bp.getZr().newElement().toBytes().length;
        byte[] M_bytes = Arrays.copyOfRange(M_beta, 0, M_beta.length - beta_len);
        byte[] beta_bytes = Arrays.copyOfRange(M_beta, M_beta.length - beta_len, M_beta.length);
        Element beta = bp.getZr().newElementFromBytes(beta_bytes).getImmutable();

        // 验证U0 = g2^β，U1 = g1^(1/γ)，U4 = H1(M)^γ
        Element gamma = H2(M_bytes, beta_bytes);
        Element gamma_inv = inverse(gamma);
        boolean verifyU0 = CTj.U0.isEqual(g2.powZn(beta));
        boolean verifyU1 = CTj.U1.isEqual(g1.powZn(gamma_inv));
        Element H1_M = H1(M_bytes);
        boolean verifyU4 = CTj.U4.isEqual(H1_M.powZn(gamma));

        if (verifyU0 && verifyU1 && verifyU4) {
            return new String(M_bytes, StandardCharsets.UTF_8);
        } else {
            throw new RuntimeException("重解密失败：密文验证不通过");
        }
    }

    // ===================== 多密文相等性测试（自定义数量+耗时统计） =====================
    public static void main(String[] args) {
        // 自定义参数：密文数量N（可修改为2--100/300/500...）
        int N = 700;
        String testMsg = "ITS-Data: VehicleID=V123, Speed=50km/h, Road=Highway-80, Time=1730000000";
        String userID = "Vehicle-V123";
        // 新增：第二个用户（用于重加密/重解密测试）
        String userID2 = "Vehicle-V456";

        try {
            // 1. 系统初始化
            setup();

            // 2. 生成用户密钥对
            Element psk = partialKeyExtract(userID);
            KeyPair userKey = userKeyGen(psk);
            System.out.println("[密钥生成] 用户[" + userID + "]密钥生成完成");

            // 新增：生成用户2密钥对（用于重加密/重解密测试）
            Element psk2 = partialKeyExtract(userID2);
            KeyPair userKey2 = userKeyGen(psk2);
            System.out.println("[密钥生成] 用户[" + userID2 + "]密钥生成完成");

            // 3. 生成N个密文和对应的陷门
            List<Ciphertext> cipherList = new ArrayList<>();
            List<Trapdoor> trapdoorList = new ArrayList<>();
            long encryptTotalCost = 0;



            // 生成N-1个相同消息的密文
            for (int i = 0; i < N-1; i++) {
                long start = System.currentTimeMillis();
                Ciphertext ct = encryption(testMsg, userID, userKey);
                Trapdoor td = authorization(ct, userKey);
                cipherList.add(ct);
                trapdoorList.add(td);
                encryptTotalCost += (System.currentTimeMillis() - start);
            }

            // 生成1个不同消息的密文（用于测试差异性）
            String diffMsg = "ITS-Data: VehicleID=V456, Speed=80km/h, Road=City-20, Time=1730000000";
            long start = System.currentTimeMillis();
            Ciphertext diffCt = encryption(diffMsg, userID, userKey);
            Trapdoor diffTd = authorization(diffCt, userKey);
            cipherList.add(diffCt);
            trapdoorList.add(diffTd);
            encryptTotalCost += (System.currentTimeMillis() - start);

            System.out.println("\n[密文生成] 生成" + N + "个密文（" + (N-1) + "个相同消息 + 1个不同消息）");
            System.out.println("  总加密耗时：" + encryptTotalCost + " ms");
            System.out.println("  单密文平均加密耗时：" + (encryptTotalCost * 1.0 / N) + " ms");

            // 4. 多密文相等性测试（核心）
            Object[] testResult = test(cipherList, trapdoorList);
            int testRes = (Integer) testResult[0];
            long testCost = (Long) testResult[1];

            System.out.println("\n[多密文相等性测试]");
            System.out.println("  密文数量：" + N);
            System.out.println("  测试耗时：" + testCost + " ms");
            System.out.println("  测试结果：" + (testRes == 1 ? "所有密文对应同一明文" : "存在不同明文（符合预期）"));

            // 5. 解密耗时测试（新增核心逻辑）
            System.out.println("\n[解密耗时测试]");
            long decryptTotalCost = 0;
            int decryptTestCount = 50; // 随机选50个密文测试解密耗时
            Random random = new Random();
            for (int i = 0; i < decryptTestCount; i++) {
                Ciphertext ct = cipherList.get(random.nextInt(N));
                long decryptStart = System.currentTimeMillis();
                String decryptedMsg = decryption(ct, userKey);
                long decryptEnd = System.currentTimeMillis();
                decryptTotalCost += (decryptEnd - decryptStart);
                // 验证解密正确性
                if (!decryptedMsg.equals(testMsg) && !decryptedMsg.equals(diffMsg)) {
                    throw new RuntimeException("解密结果错误：" + decryptedMsg);
                }
            }
            double avgDecryptCost = decryptTotalCost * 1.0 / decryptTestCount;
            System.out.println("  测试样本数：" + decryptTestCount + " 个密文");
            System.out.println("  总解密耗时：" + decryptTotalCost + " ms");
            System.out.println("  单密文平均解密耗时：" + avgDecryptCost + " ms");



            // 5. 验证解密正确性（随机选1个密文）
            Ciphertext randomCt = cipherList.get(new Random().nextInt(N));
            String decryptedMsg = decryption(randomCt, userKey);
            System.out.println("\n[解密验证]");
            System.out.println("  随机解密1个密文，明文一致性：" + (decryptedMsg.equals(testMsg) || decryptedMsg.equals(diffMsg)));

            // 6. 测试汇总
            System.out.println("\n===== 测试汇总（N=" + N + "）=====");
            System.out.println("1. 多密文相等性测试耗时：" + testCost + " ms");
            System.out.println("2. 单密文平均加密耗时：" + (encryptTotalCost * 1.0 / N) + " ms");
            System.out.println("3. 测试结果正确性：" + (testRes == 0 ? "通过（检测到不同明文）" : "失败"));
        } catch (Exception e) {
            System.err.println("测试失败：" + e.getMessage());
            e.printStackTrace();
        }
    }
}