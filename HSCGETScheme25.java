import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.a.TypeACurveGenerator;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

public class HSCGETScheme25 {

    // 系统全局参数（论文 IV. Construction 1）
    private static Pairing bp;
    private static Element g, U, P_pub;
    private static Element s; // 主密钥 KGC's master secret key
    private static int zrByteLength; // Zr群元素字节长度（动态获取，避免硬编码）

    // 哈希函数定义（严格遵循论文 IV. Construction 1）
    // H0: {0,1}* → G1
    public static Element H0(String id) {
        return hashToG1(id.getBytes(StandardCharsets.UTF_8));
    }

    // H1: {0,1}* → G1
    public static Element H1(String id) {
        return hashToG1(id.getBytes(StandardCharsets.UTF_8));
    }

    // H2: {0,1}^n → G1（直接对消息字节哈希，无字符串转换）
    public static Element H2(byte[] message) {
        return hashToG1(message);
    }

    // H3: G2 → {0,1}^{l1+l2}（G2群元素→SHA-256字节数组）
    public static byte[] H3(Element w) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            return md.digest(w.toBytes());
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("H3哈希函数执行失败", e);
        }
    }

    // H4: {0,1}^n × G1^3 × {0,1}^{l1+l2} × Zp* → Zp*（含r2参数）
    public static Element H4(String m, Element c1, Element c2, Element c3, byte[] c4, Element r2) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            // 拼接所有输入：m字节 + c1字节 + c2字节 + c3字节 + c4字节 + r2字节
            byte[] input = concat(
                    m.getBytes(StandardCharsets.UTF_8),
                    c1.toBytes(),
                    c2.toBytes(),
                    c3.toBytes(),
                    c4,
                    r2.toBytes()
            );
            byte[] hash = md.digest(input);
            // 映射为Zr群元素
            return bp.getZr().newElementFromHash(hash, 0, hash.length).getImmutable();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("H4哈希函数执行失败", e);
        }
    }

    // 辅助函数：字节数组拼接
    private static byte[] concat(byte[]... arrays) {
        int totalLength = 0;
        for (byte[] arr : arrays) {
            if (arr != null) totalLength += arr.length;
        }
        byte[] result = new byte[totalLength];
        int offset = 0;
        for (byte[] arr : arrays) {
            if (arr != null) {
                System.arraycopy(arr, 0, result, offset, arr.length);
                offset += arr.length;
            }
        }
        return result;
    }

    // 辅助函数：哈希到G1群（H0/H1/H2共用）
    private static Element hashToG1(byte[] input) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] hash = md.digest(input);
            return bp.getG1().newElementFromHash(hash, 0, hash.length).getImmutable();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("哈希映射到G1失败", e);
        }
    }

    // 密文结构（论文 IV. Construction 6：C=(C1,C2,C3,C4,C5)）
    public static class Ciphertext {
        Element C1, C2, C3, C5, W;
        byte[] C4;

        public Ciphertext(Element c1, Element c2, Element c3, byte[] c4, Element c5, Element w) {
            this.C1 = c1;
            this.C2 = c2;
            this.C3 = c3;
            this.C4 = c4;
            this.C5 = c5;
            this.W = w;
        }
    }

    // 1. Setup：系统初始化（论文 IV. Construction 1）
    public static void setup() {
        // 生成192位安全级别的Type A曲线（论文 VI. Performance Analyze）
        TypeACurveGenerator pg = new TypeACurveGenerator(192, 192);
        PairingParameters pp = pg.generate();
        bp = PairingFactory.getPairing(pp);

        // 初始化G1群生成元
        g = bp.getG1().newRandomElement().getImmutable();
        U = bp.getG1().newRandomElement().getImmutable();

        // 生成主密钥和系统公钥
        s = bp.getZr().newRandomElement().getImmutable();
        P_pub = g.powZn(s).getImmutable();

        // 获取Zr群元素字节长度（动态适配曲线参数）
        zrByteLength = bp.getZr().newElement().toBytes().length;

        System.out.println("系统初始化完成");
    }

    // 2. IBC-KG：卫星（IBC系统）密钥生成（论文 IV. Construction 2）
    public static Element ibcKg(String idS) {
        Element Qs = H0(idS);
        return Qs.powZn(s).getImmutable(); // sk_s = Qs^s
    }

    // 3. CLC-KG：车辆（CLC系统）密钥生成（论文 IV. Construction 3）
    public static Element[] clcKg(String idR) {
        // a) 部分私钥生成
        Element Qr = H1(idR);
        Element Dr = Qr.powZn(s).getImmutable(); // D_r = Qr^s

        // b) 用户私钥生成
        Element x = bp.getZr().newRandomElement().getImmutable();
        Element skr = Dr.powZn(x).getImmutable(); // sk_r = D_r^x

        // c) 用户公钥生成
        Element PKr = P_pub.powZn(x).getImmutable(); // PK_r = P_pub^x

        return new Element[]{skr, PKr, x}; // 返回：私钥、公钥、用户秘密值x
    }

    // 4. KG-Group：群密钥生成（论文 IV. Construction 4）
    public static Element[] kgGroup() {
        Element s1 = bp.getZr().newRandomElement().getImmutable();
        Element s2 = bp.getZr().newRandomElement().getImmutable();
        return new Element[]{s1, s2}; // gsk = (s1, s2)（两个Zr标量）
    }

    // 5. Join-Group：群公钥生成（论文 IV. Construction 5）
    public static Element[] joinGroup(Element[] gsk, String idR) {
        Element s1 = gsk[0];
        Element s2 = gsk[1];
        Element Qr = H1(idR);
        Element QrS2 = Qr.powZn(s2).getImmutable(); // Qr^s2
        return new Element[]{s1, QrS2}; // gpk_r = (s1, Qr^s2)
    }

    // 6. Signcryption：签密（论文 IV. Construction 6）
    public static Ciphertext signcrypt(String M, Element[] gpk_r, Element sk_s, Element PKr, String idR) {
        // a) 生成随机数 + 计算Qr
        Element r1 = bp.getZr().newRandomElement().getImmutable();
        Element r2 = bp.getZr().newRandomElement().getImmutable();
        Element Qr = H1(idR);

        // b) 计算C1 = g^r1
        Element C1 = g.powZn(r1).getImmutable();

        // c) 计算C2 = Qr^(r2*s2) · H2(M)^s1
        Element s1 = gpk_r[0];
        Element QrS2 = gpk_r[1]; // Qr^s2
        Element r2S2 = r2.mulZn(s1); // 论文中是r2*s2，此处gpk_r[0]是s1（笔误修正，按论文公式）
        Element QrR2S2 = QrS2.powZn(r2).getImmutable(); // Qr^(r2*s2) = (Qr^s2)^r2
        Element H2M = H2(M.getBytes(StandardCharsets.UTF_8));
        Element H2MS1 = H2M.powZn(s1).getImmutable();
        Element C2 = QrR2S2.mul(H2MS1).getImmutable();

        // d) 计算C3 = Qr^r2
        Element C3 = Qr.powZn(r2).getImmutable();

        // e) 计算W = e(PKr, Qr)^r1
        Element ePKrQr = bp.pairing(PKr, Qr);
        Element W = ePKrQr.powZn(r1).getImmutable();

        // f) 计算C4 = H3(W) ⊕ (M || r2)
        byte[] H3W = H3(W);
        byte[] MBytes = M.getBytes(StandardCharsets.UTF_8);
        byte[] R2Bytes = r2.toBytes();
        byte[] M_R2 = concat(MBytes, R2Bytes);
        byte[] C4 = xor(H3W, M_R2);

        // g) 计算h = H4(M || C1 || C2 || C3 || C4 || r2)
        Element h = H4(M, C1, C2, C3, C4, r2);

        // h) 计算C5 = U^r1 · sk_s^h
        Element UR1 = U.powZn(r1).getImmutable();
        Element skSH = sk_s.powZn(h).getImmutable();
        Element C5 = UR1.mul(skSH).getImmutable();

        // i) 返回密文
        return new Ciphertext(C1, C2, C3, C4, C5, W);
    }

    // 7. Unsigncryption：解签密（论文 IV. Construction 7）
    public static String unsigncrypt(Element[] gpk_r, Ciphertext C, Element sk_r, String idS, String idR) {
        // a) 计算Qs = H0(idS)
        Element Qs = H0(idS);

        // b) 计算W' = e(C1, sk_r)
        Element W_prime = bp.pairing(C.C1, sk_r).getImmutable();

        // c) 计算M' || r2' = C4 ⊕ H3(W')
        byte[] H3W_prime = H3(W_prime);
        byte[] M_R2 = xor(C.C4, H3W_prime);

        // 拆分M'和r2'（r2'长度=zrByteLength）
        byte[] M_prime_bytes = Arrays.copyOfRange(M_R2, 0, M_R2.length - zrByteLength);
        byte[] R2_prime_bytes = Arrays.copyOfRange(M_R2, M_R2.length - zrByteLength, M_R2.length);
        Element r2_prime = bp.getZr().newElementFromBytes(R2_prime_bytes).getImmutable();
        String M_prime = new String(M_prime_bytes, StandardCharsets.UTF_8);

        // d) 计算h' = H4(M' || C1 || C2 || C3 || C4 || r2')
        Element h_prime = H4(M_prime, C.C1, C.C2, C.C3, C.C4, r2_prime);

        // e) 验证两个核心等式
        Element Qr = H1(idR);
        // 验证1：C3 == Qr^r2'
        Element rhs1 = Qr.powZn(r2_prime).getImmutable();
        if (!C.C3.isEqual(rhs1)) {
            throw new RuntimeException("解签密失败：C3验证不通过");
        }

        // 验证2：e(C5, g) == e(C1, U) · e(Qs^h', P_pub)
        Element eC5g = bp.pairing(C.C5, g);
        Element eC1U = bp.pairing(C.C1, U);
        Element QsHprime = Qs.powZn(h_prime);
        Element eQsHprimePpub = bp.pairing(QsHprime, P_pub);
        Element rhs2 = eC1U.mul(eQsHprimePpub).getImmutable();
        if (!eC5g.isEqual(rhs2)) {
            throw new RuntimeException("解签密失败：C5验证不通过");
        }

        // 验证W'与签密的W一致（可选，增强安全性）
        if (!W_prime.isEqual(C.W)) {
            throw new RuntimeException("解签密失败：W验证不通过");
        }

        return M_prime;
    }

    // 辅助函数：异或运算（长度不一致时补0）
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

    // 8. Group-TD：生成群陷门（论文 IV. Construction 8）
    public static Element[] groupTD(Element[] gsk) {
        Element s2 = gsk[1];
        Element y = bp.getZr().newRandomElement().getImmutable();
        Element td1 = g.powZn(y).getImmutable();
        Element td2 = g.powZn(s2.mulZn(y)).getImmutable();
        return new Element[]{td1, td2}; // gtd = (g^y, g^(s2*y))
    }

    // 9. Test：群等式测试（论文 IV. Construction 9）
    public static boolean test(Ciphertext CA, Ciphertext CB, Element[] gtd) {
        Element td1 = gtd[0];
        Element td2 = gtd[1];

        // 计算 (CA.C2 / CB.C2) 和 (CA.C3 / CB.C3)
        Element CA2_div_CB2 = CA.C2.div(CB.C2).getImmutable();
        Element CA3_div_CB3 = CA.C3.div(CB.C3).getImmutable();

        // 验证 e(CA2/CB2, td1) == e(CA3/CB3, td2)
        Element lhs = bp.pairing(CA2_div_CB2, td1);
        Element rhs = bp.pairing(CA3_div_CB3, td2);
        return lhs.isEqual(rhs);
    }

    // 测试主函数
    public static void main(String[] args) {
        // 1. 系统初始化
        setup();

        // 2. 生成卫星密钥（IBC系统）
        String idS = "satellite@leo.com";
        Element sk_s = ibcKg(idS);

        // 3. 生成车辆密钥（CLC系统）
        String idR = "vehicle-123@iov.com";
        Element[] clcKeys = clcKg(idR);
        Element sk_r = clcKeys[0];
        Element PKr = clcKeys[1];

        // 4. 生成群密钥和群公钥
        Element[] gsk = kgGroup();
        Element[] gpk_r = joinGroup(gsk, idR);

        // 5. 签密
        String message = "Hello HSC-GET Scheme!";
        long start = System.currentTimeMillis();
        Ciphertext ciphertext = signcrypt(message, gpk_r, sk_s, PKr, idR);
        long signcryptTime = System.currentTimeMillis() - start;
        System.out.println("签密耗时：" + signcryptTime + " ms");

        // 6. 解签密
        start = System.currentTimeMillis();
        String decrypted = unsigncrypt(gpk_r, ciphertext, sk_r, idS, idR);
        long unsigncryptTime = System.currentTimeMillis() - start;
        System.out.println("解签密耗时：" + unsigncryptTime + " ms");

        // 验证结果
        System.out.println("原始消息：" + message);
        System.out.println("解密消息：" + decrypted);
        System.out.println("消息一致性验证：" + message.equals(decrypted));

        // 7. 群等式测试（测试两个相同消息的密文）
        Ciphertext ciphertext2 = signcrypt(message, gpk_r, sk_s, PKr, idR);
        Element[] gtd = groupTD(gsk);
        start = System.currentTimeMillis();
        boolean testResult = test(ciphertext, ciphertext2, gtd);
        long testTime = System.currentTimeMillis() - start;
        System.out.println("群等式测试（相同消息）：" + testResult);
        System.out.println("群等式测试耗时：" + testTime + " ms");

        // 测试不同消息的密文
        Ciphertext ciphertext3 = signcrypt("Different Message", gpk_r, sk_s, PKr, idR);
        boolean testResult2 = test(ciphertext, ciphertext3, gtd);
        System.out.println("群等式测试（不同消息）：" + testResult2);
    }
}
