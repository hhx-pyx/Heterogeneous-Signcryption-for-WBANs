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


public class MyHsc {

    // 系统全局参数
    private static Pairing bp;
    private static Element P; // G1生成元
    private static Element P_pub; // KGC公钥 (s*P)
    private static Element T_pub; // TA公钥 (α*P)
    private static Element C_pub; // CA公钥 (β*P)
    private static Element s; // KGC主密钥（Zr）
    private static Element α; // TA主密钥（Zr）
    private static Element β; // CA主密钥（Zr）
    private static int zrByteLength; // Zr元素字节长度

    // 哈希算法
    private static final String HASH_ALG = "SHA-256";

    // H0: {0,1}* → Zr*
    private static Element H0(byte[] input) {
        return hashToZr(input);
    }

    // H1: {0,1}* → Zr*
    private static Element H1(byte[] input) {
        return hashToZr(input);
    }

    // H2: {0,1}* × G1 × G1 × G1 → Zr*
    private static Element H2(byte[] pid, Element X, Element Y, Element Ppub) {
        byte[] combined = concat(pid, X.toBytes(), Y.toBytes(), Ppub.toBytes());
        return hashToZr(combined);
    }

    // H3: G1 × G1 × {0,1}* × {0,1}* × byte[] → Zr*
    private static Element H3(Element U, Element W, byte[] pidS, byte[] pidR, byte[] t) {
        byte[] combined = concat(U.toBytes(), W.toBytes(), pidS, pidR, t);
        return hashToZr(combined);
    }

    // H4: G1 × Zr × G1 × byte[] → Zr*（C为消息哈希+随机数，满足Element长度）
    private static Element H4(Element U, Element C, Element PKs1, byte[] t) {
        byte[] combined = concat(U.toBytes(), C.toBytes(), PKs1.toBytes(), t);
        return hashToZr(combined);
    }

    // H5: {0,1}* → Zr*（用于消息哈希）
    private static Element H5(byte[] input) {
        return hashToZr(input);
    }

    // 辅助：字节数组拼接
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

    // 辅助：哈希到Zr群
    private static Element hashToZr(byte[] input) {
        try {
            MessageDigest md = MessageDigest.getInstance(HASH_ALG);
            byte[] hash = md.digest(input);
            return bp.getZr().newElementFromHash(hash, 0, hash.length).getImmutable();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("哈希函数执行失败", e);
        }
    }

    // 辅助：异或运算（长度自动对齐）
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

    // 辅助：扩展短密钥到目标长度（解决异或乱码）
    private static byte[] expandKey(byte[] shortKey, int targetLen) {
        List<byte[]> hashParts = new ArrayList<>();
        int totalLen = 0;
        int counter = 0;
        while (totalLen < targetLen) {
            byte[] input = concat(shortKey, String.valueOf(counter).getBytes(StandardCharsets.UTF_8));
            try {
                MessageDigest md = MessageDigest.getInstance(HASH_ALG);
                byte[] hash = md.digest(input);
                hashParts.add(hash);
                totalLen += hash.length;
                counter++;
            } catch (NoSuchAlgorithmException e) {
                throw new RuntimeException("密钥扩展失败", e);
            }
        }
        byte[] expanded = concat(hashParts.toArray(new byte[0][]));
        return Arrays.copyOf(expanded, targetLen);
    }

    // 密文结构（核心修改：拆分C和消息密文）
    public static class Ciphertext {
        Element C;          // Zr：H4输入（消息哈希+随机数，长度固定）
        Element σ;          // Zr：签名组件
        Element U;          // G1：随机点组件
        byte[] CT;          // byte[]：等式测试组件
        Element CW;         // G1：解密辅助组件
        byte[] t;           // byte[]：时间戳
        String pidS;        // 发送者伪身份
        String pidR;        // 接收者伪身份
        byte[] encryptedMsg;// byte[]：消息异或密文（无长度限制，核心新增）
        byte[] mLen;        // 原始消息长度
    }

    // 传感器密钥对（严格你的定义）
    public static class SensorKeyPair {
        Element xs;    // 自有私钥（Zr）
        Element psks;  // KGC部分私钥（psks=rs+s·h2，Zr）
        Element PKs1;  // Xs=xs·P（G1）
        Element PKs2;  // Ys=rs·P（G1）
        String pidS;   // 伪身份
    }

    // 医生密钥对（PKI）
    public static class DoctorKeyPair {
        Element SKr; // Zr：私钥 SKr = xr + yr
        Element PKr; // G1：公钥 PKr = Xr + Yr
        String pidR; // 伪身份
        byte[] cert; // 证书

        public DoctorKeyPair(Element SKr, Element PKr, String pidR, byte[] cert) {
            this.SKr = SKr;
            this.PKr = PKr;
            this.pidR = pidR;
            this.cert = cert;
        }
    }

    // 1. 系统初始化
    public static void setup() {
        TypeACurveGenerator pg = new TypeACurveGenerator(192, 192);
        PairingParameters pp = pg.generate();
        bp = PairingFactory.getPairing(pp);

        P = bp.getG1().newRandomElement().getImmutable();
        s = bp.getZr().newRandomElement().getImmutable();
        P_pub = P.powZn(s).getImmutable();
        α = bp.getZr().newRandomElement().getImmutable();
        T_pub = P.powZn(α).getImmutable();
        β = bp.getZr().newRandomElement().getImmutable();
        C_pub = P.powZn(β).getImmutable();
        zrByteLength = bp.getZr().newElement().toBytes().length;

        System.out.println("=== WBAN系统初始化完成 ===");
    }

    // 2. 生成传感器秘密值
    public static Element[] setSensorSecretValue() {
        Element xs = bp.getZr().newRandomElement().getImmutable();
        Element Xs = P.powZn(xs).getImmutable();
        return new Element[]{xs, Xs};
    }

    // 3. 生成医生秘密值
    public static Element[] setDoctorSecretValue() {
        Element xr = bp.getZr().newRandomElement().getImmutable();
        Element Xr = P.powZn(xr).getImmutable();
        return new Element[]{xr, Xr};
    }

    // 4. 生成伪身份
    public static String generatePseudonym(String ID, Element x, Element X) {
        Element xTpub = X.powZn(α).getImmutable();
        Element h0 = H0(xTpub.toBytes());
        byte[] VID = xor(ID.getBytes(StandardCharsets.UTF_8), h0.toBytes());
        Element h1 = H1(concat(ID.getBytes(StandardCharsets.UTF_8), xTpub.toBytes()));
        byte[] AID = xor(ID.getBytes(StandardCharsets.UTF_8), h1.toBytes());
        return new String(concat(AID, ":".getBytes(), String.valueOf(System.currentTimeMillis()).getBytes()), StandardCharsets.UTF_8);
    }

    // 5. CLC密钥生成
    public static SensorKeyPair clcKeyGen(String pidS, Element xs, Element Xs) {
        Element rs = bp.getZr().newRandomElement().getImmutable();
        Element Ys = P.powZn(rs).getImmutable(); // Ys=rs·P
        Element h2 = H2(pidS.getBytes(StandardCharsets.UTF_8), Xs, Ys, P_pub).getImmutable();
        Element psks = rs.add(s.mulZn(h2)).getImmutable(); // psks=rs+s·h2

        SensorKeyPair keyPair = new SensorKeyPair();
        keyPair.xs = xs;
        keyPair.psks = psks;
        keyPair.PKs1 = Xs;
        keyPair.PKs2 = Ys;
        keyPair.pidS = pidS;
        return keyPair;
    }

    // 6. PKI密钥生成
    public static DoctorKeyPair pkiKeyGen(String pidR, Element xr, Element Xr) {
        Element yr = bp.getZr().newRandomElement().getImmutable();
        Element Yr = P.powZn(yr).getImmutable();
        Element SKr = xr.add(yr).getImmutable();
        Element PKr = Xr.add(Yr).getImmutable();
        Element hPKr = hashToZr(PKr.toBytes());
        byte[] cert = hPKr.mulZn(β).toBytes();

        return new DoctorKeyPair(SKr, PKr, pidR, cert);
    }

    // 7. 加入群组
    public static Element[] joinGroup() {
        Element GSK = bp.getZr().newRandomElement().getImmutable();
        Element GPK = P.mulZn(GSK).getImmutable();
        return new Element[]{GSK, GPK};
    }

    // 8. 生成陷门
    public static Element generateTrapdoor(Element GSK) {
        return GSK.getImmutable();
    }

    // 9. 签密（核心修改：拆分C和消息密文）
    public static Ciphertext signcrypt(String m, String pidS, String pidR,
                                       SensorKeyPair sensorKey, DoctorKeyPair doctorKey, Element GPK) {
//        System.out.println("message length: " + m.length());
        // 1. 生成随机数ui
        Element ui = bp.getZr().newRandomElement().getImmutable();
        Element U = P.powZn(ui).getImmutable();

        // 2. 计算CW和W
        Element CW = U.powZn(sensorKey.xs).getImmutable();
        Element W = doctorKey.PKr.powZn(ui.mulZn(sensorKey.xs).getImmutable()).getImmutable();

        // 3. 处理消息（异或+无长度限制存储）
        byte[] t = String.valueOf(System.currentTimeMillis()).getBytes(StandardCharsets.UTF_8);
        Element h3 = H3(U, W, pidS.getBytes(StandardCharsets.UTF_8), pidR.getBytes(StandardCharsets.UTF_8), t).getImmutable();
        byte[] mBytes = m.getBytes(StandardCharsets.UTF_8);
        byte[] mLen = String.valueOf(mBytes.length).getBytes();
        // 扩展h3密钥到消息长度
        byte[] shortH3 = h3.toBytes();
        byte[] expandedH3 = expandKey(shortH3, mBytes.length);
        byte[] encryptedMsg = xor(mBytes, expandedH3); // 消息密文直接存byte[]（无长度限制）

        // 4. 生成C（H4输入：消息哈希+随机数，长度固定）
        Element msgHash = H5(mBytes).getImmutable();
        Element C = msgHash.add(ui).getImmutable(); // C=消息哈希+ui（Zr Element，长度固定）

        // 5. 计算σ
        Element h4 = H4(U, C, sensorKey.PKs1, t).getImmutable();
        Element h4_xs = h4.mulZn(sensorKey.xs).getImmutable();
        Element σ = ui.add(h4_xs).add(sensorKey.psks).getImmutable();

        // 6. 计算CT
        Element H5m = H5(mBytes).getImmutable();
        Element uiH5m = H5m.mulZn(ui).getImmutable();
        Element uiGPK = GPK.mulZn(ui).getImmutable();
        Element h0 = H0(uiGPK.toBytes());
        byte[] CT = xor(uiH5m.toBytes(), h0.toBytes());


        // 构建密文（拆分C和消息密文）
        Ciphertext ciphertext = new Ciphertext();
        ciphertext.C = C;
        ciphertext.σ = σ;
        ciphertext.U = U;
        ciphertext.CT = CT;
        ciphertext.CW = CW;
        ciphertext.t = t;
        ciphertext.pidS = pidS;
        ciphertext.pidR = pidR;
        ciphertext.encryptedMsg = encryptedMsg; // 消息密文存byte[]
        ciphertext.mLen = mLen;

        return ciphertext;
    }

    // 10. 解签密（核心修改：直接用byte[]消息密文解密）
    public static String unsigncrypt(Ciphertext θ, SensorKeyPair sensorKey, DoctorKeyPair doctorKey) {
        // 1. 证书验证
//        Element hPKr = hashToZr(doctorKey.PKr.toBytes()).getImmutable();
//        Element certElement = bp.getZr().newElementFromBytes(doctorKey.cert).getImmutable();
//        Element certVerify = certElement.mul(β.invert()).getImmutable();
//        if (!certVerify.isEqual(hPKr)) {
//            throw new RuntimeException("医生证书验证失败");
//        }

        long  startTime = System.currentTimeMillis();

        // 2. 提取参数
        Element Ui = θ.U.getImmutable();
        Element Xs = sensorKey.PKs1.getImmutable();
        Element Ys = sensorKey.PKs2.getImmutable();
        String pidS = sensorKey.pidS;
        Element Ppub = P_pub.getImmutable();

        // 3. 计算h4和h2
        Element h4 = H4(Ui, θ.C, Xs, θ.t).getImmutable();
        Element h2 = H2(pidS.getBytes(StandardCharsets.UTF_8), Xs, Ys, Ppub).getImmutable();

        // 4. 验证σ公式
        Element σ = θ.σ.getImmutable();
        Element sigma_P = P.powZn(σ).getImmutable();
        Element h4_Xs = Xs.powZn(h4).getImmutable();
        Element h2_Ppub = Ppub.powZn(h2).getImmutable();
        Element rightSide = Ui.add(h4_Xs).add(Ys).add(h2_Ppub).getImmutable();

        long endTime = System.currentTimeMillis();
//        System.out.println("验证签密耗时：" + (endTime - startTime) + "ms");

        if (!sigma_P.isEqual(rightSide)) {
            throw new RuntimeException("签密验证失败：σ公式不匹配");
        }

        // 5. 解密消息（直接用byte[]密文，无Element截断）
        Element W_prime = θ.CW.powZn(doctorKey.SKr.getImmutable()).getImmutable();
        Element h3 = H3(Ui, W_prime, θ.pidS.getBytes(StandardCharsets.UTF_8),
                θ.pidR.getBytes(StandardCharsets.UTF_8), θ.t).getImmutable();
        // 扩展h3密钥到原始消息长度
        int originalLen = Integer.parseInt(new String(θ.mLen, StandardCharsets.UTF_8));
        byte[] shortH3 = h3.toBytes();
        byte[] expandedH3 = expandKey(shortH3, originalLen);
        // 直接解密byte[]消息密文（无Element截断）
        byte[] mBytes = xor(θ.encryptedMsg, expandedH3);
        mBytes = Arrays.copyOfRange(mBytes, 0, originalLen);

        return new String(mBytes, StandardCharsets.UTF_8);
    }

    // 11. 批量验证
    public static boolean batchVerify(List<Ciphertext> ciphertexts, List<SensorKeyPair> sensorKeys) {
        if (ciphertexts.size() != sensorKeys.size()) {
            throw new IllegalArgumentException("密文与密钥数量不匹配");
        }

        int n = ciphertexts.size();
        Random random = new Random();
//        int[] a = new int[n];
        Element sigma_agg = bp.getZr().newZeroElement().getImmutable();
        Element right_agg = bp.getG1().newZeroElement().getImmutable();

//        for (int i = 0; i < n; i++) {
//            a[i] = i+1;
////            a[i] = bp.getZr().newElement(random.nextInt(1024) + 1).getImmutable();
//        }
//        //打乱顺序
//        for (int i = n - 1; i > 0; i--) {
//            int j = random.nextInt(i + 1); // 生成0~i的随机索引
//            // 交换aInt[i]和aInt[j]
//            int temp = a[i];
//            a[i] = a[j];
//            a[j] = temp;
//        }

        // 生成 (0, 2^80) 范围内的随机 Zr 系数
//        Random random = new Random();
        Element[] a = new Element[n]; // 改为 Element 数组
        for (int i = 0; i < n; i++) {
            // 生成 80 位随机大整数，范围 (0, 2^80)
            BigInteger r = new BigInteger(80, random);
            // 确保 r > 0
            while (r.signum() == 0) {
                r = new BigInteger(80, random);
            }
            a[i] = bp.getZr().newElement(r).getImmutable();
        }

        for (int i = 0; i < n; i++) {
            Ciphertext θ = ciphertexts.get(i);
            SensorKeyPair key = sensorKeys.get(i);
            sigma_agg = sigma_agg.add(θ.σ.mul(a[i])).getImmutable();
//            sigma_agg = sigma_agg.add(θ.σ.mul(BigInteger.valueOf(a[i]))).getImmutable();
//            sigma_agg = sigma_agg.add(θ.σ).getImmutable();

            Element h4 = H4(θ.U, θ.C, key.PKs1, θ.t).getImmutable();
            Element h2 = H2(key.pidS.getBytes(), key.PKs1, key.PKs2, P_pub).getImmutable();
            Element h4_Xs = key.PKs1.powZn(h4).getImmutable();    // h4 · Xs
            Element h2_Ppub = P_pub.powZn(h2).getImmutable();      // h2 · Ppub
            Element singleRight = θ.U.add(h4_Xs).add(key.PKs2).add(h2_Ppub).getImmutable();

            right_agg = right_agg.add(singleRight.powZn(a[i])).getImmutable();
//            right_agg = right_agg.add(singleRight.pow(BigInteger.valueOf(a[i]))).getImmutable();
//            right_agg = right_agg.add(singleRight).getImmutable();

        }

        return P.powZn(sigma_agg).isEqual(right_agg);
    }


    //相等性测试
    public static boolean equalityTest(Ciphertext C, Ciphertext C1, Element td) {
        // 1. 计算 C 的 T（严格匹配公式：T = C_T ⊕ H0(tdU_i)）
        Element tdU = C.U.mulZn(td).getImmutable(); // 公式中的tdU_i
        Element H0_tdU = H0(tdU.toBytes()).getImmutable(); // 公式中的H0(tdU_i)
        byte[] T_bytes = xor(C.CT, H0_tdU.toBytes()); // 公式中的T = C_T ⊕ H0(tdU_i)
        Element T = bp.getZr().newElementFromHash(T_bytes, 0, T_bytes.length).getImmutable(); // T转换为Zr数

        // 2. 计算 C1 的 T'（严格匹配公式：T' = C_T' ⊕ H0(tdU_i')）
        Element tdU1 = C1.U.mulZn(td).getImmutable(); // 公式中的tdU_i'
        Element H0_tdU1 = H0(tdU1.toBytes()).getImmutable(); // 公式中的H0(tdU_i')
        byte[] T1_bytes = xor(C1.CT, H0_tdU1.toBytes()); // 公式中的T' = C_T' ⊕ H0(tdU_i')
        Element T1 = bp.getZr().newElementFromHash(T1_bytes, 0, T1_bytes.length).getImmutable(); // T'转换为Zr数

        // 3. 验证公式：T·U_i' == T'·U_i
        Element left = C1.U.mulZn(T).getImmutable();  // T·U_i'
        Element right = C.U.mulZn(T1).getImmutable(); // T'·U_i

        return left.isEqual(right);
    }

    // 12. 批量等式测试
    public static boolean batchEqualityTest(Ciphertext refCipher, List<Ciphertext> ciphers, Element td) {
        // 步骤1：计算参考密文的 T（公式步骤1：T = C_T ⊕ H0(tdU_i)）
        Element refU_td = refCipher.U.mulZn(td).getImmutable(); // td·U_i（参考密文的U）
        Element H0_refU_td = H0(refU_td.toBytes()).getImmutable(); // H0(tdU_i)
        byte[] T_ref_bytes = xor(refCipher.CT, H0_refU_td.toBytes()); // T = C_T ⊕ H0(tdU_i)
        Element T_ref = bp.getZr().newElementFromHash(T_ref_bytes, 0, T_ref_bytes.length).getImmutable(); // T转换为Zr数

        // 步骤2：计算待测试密文的 T_j 并聚合（公式步骤2-3：T_agg=ΣT_j，U_agg=ΣU_j）
        Element T_agg = bp.getZr().newZeroElement().getImmutable(); // 初始化T的聚合值
        Element U_agg = bp.getG1().newZeroElement().getImmutable(); // 初始化U的聚合值

        for (Ciphertext θ : ciphers) {
            // 计算单个密文的 T_j（公式步骤2：T_j = C_T,j ⊕ H0(tdU_j)）
            Element Uj_td = θ.U.mulZn(td).getImmutable(); // td·U_j
            Element H0_Uj_td = H0(Uj_td.toBytes()).getImmutable(); // H0(tdU_j)
            byte[] Tj_bytes = xor(θ.CT, H0_Uj_td.toBytes()); // T_j = C_T,j ⊕ H0(tdU_j)
            Element Tj = bp.getZr().newElementFromHash(Tj_bytes, 0, Tj_bytes.length).getImmutable(); // T_j转换为Zr数

            // 聚合（公式步骤3：T_agg=ΣT_j，U_agg=ΣU_j）
            T_agg = T_agg.add(Tj).getImmutable();
            U_agg = U_agg.add(θ.U).getImmutable();
        }

        // 步骤3：验证等式（公式步骤4：T·U_agg ≟ T_agg·U_i）
        Element left = U_agg.mulZn(T_ref).getImmutable();  // T·U_agg
        Element right = refCipher.U.mulZn(T_agg).getImmutable(); // T_agg·U_i

        return left.isEqual(right);
    }

    // 13. 异常密文检测
    public static List<Ciphertext> detectAbnormal(Ciphertext refCipher, List<Ciphertext> ciphers, Element td) {
        List<Ciphertext> abnormal = new ArrayList<>();
        if (ciphers.size() <= 1) {
            if (!batchEqualityTest(refCipher, ciphers, td)) {
                abnormal.addAll(ciphers);
            }
            return abnormal;
        }

        int mid = ciphers.size() / 2;
        List<Ciphertext> left = ciphers.subList(0, mid);
        List<Ciphertext> right = ciphers.subList(mid, ciphers.size());

        if (!batchEqualityTest(refCipher, left, td)) {
            abnormal.addAll(detectAbnormal(refCipher, left, td));
        }
        if (!batchEqualityTest(refCipher, right, td)) {
            abnormal.addAll(detectAbnormal(refCipher, right, td));
        }

        return abnormal;
    }

    // 批量验证（支持自定义密文数量n）
    public static void customBatchVerify(int n, String message, String pidS, String pidR,
                                         SensorKeyPair sensorKey, DoctorKeyPair doctorKey, Element GPK) {
        // 1. 自动生成n个密文
        List<Ciphertext> cipherList = new ArrayList<>();
        for (int i = 0; i < n; i++) {
            // 每次调用signcrypt生成新密文（含随机ui）
            Ciphertext cipher = signcrypt(message, pidS, pidR, sensorKey, doctorKey, GPK);
            cipherList.add(cipher);
        }

        // 2. 生成对应的传感器密钥列表（n个相同密钥，与密文数量匹配）
        List<SensorKeyPair> sensorKeyList = new ArrayList<>();
        for (int i = 0; i < n; i++) {
            sensorKeyList.add(sensorKey);
        }

        // 3. 执行批量验证并输出结果
        long start = System.currentTimeMillis();
        boolean batchVerifyResult = batchVerify(cipherList, sensorKeyList);
        long batchVerifyTime = System.currentTimeMillis() - start;

        System.out.println("\n=== 批量验证测试（" + n + "个密文） ===");
        System.out.println("批量验证结果：" + batchVerifyResult);
        System.out.println("批量验证耗时：" + batchVerifyTime + " ms");
    }

    // 主函数测试（新增无异常批量相等性测试）
    public static void main(String[] args) {
        // 1. 初始化
        setup();

        // 2. 生成传感器密钥
        String sensorID = "sensor-001@wbans.com";
        Element[] sensorSecret = setSensorSecretValue();
        Element xs = sensorSecret[0];
        Element Xs = sensorSecret[1];
        String pidS = generatePseudonym(sensorID, xs, Xs);
        SensorKeyPair sensorKey = clcKeyGen(pidS, xs, Xs);

        // 3. 生成医生密钥
        String doctorID = "doctor-001@hospital.com";
        Element[] doctorSecret = setDoctorSecretValue();
        Element xr = doctorSecret[0];
        Element Xr = doctorSecret[1];
        String pidR = generatePseudonym(doctorID, xr, Xr);
        DoctorKeyPair doctorKey = pkiKeyGen(pidR, xr, Xr);

        // 4. 群组初始化
        Element[] groupKeys = joinGroup();
        Element GSK = groupKeys[0];
        Element GPK = groupKeys[1];
        Element td = generateTrapdoor(GSK);

        // 5. 签密测试（超长消息验证乱码修复）
        String message = "Patient: 123, HeartRate: 78, BloodPressure: 135/85, Temperature: 36.5°C, Oxygen: 98%, RespiratoryRate: 18/min, BloodSugar: 5.6mmol/L, ECG: Normal, BMI: 23.5, Age: 45, Gender: Male";
        long start = System.currentTimeMillis();
        Ciphertext ciphertext = signcrypt(message, pidS, pidR, sensorKey, doctorKey, GPK);
        long signcryptTime = System.currentTimeMillis() - start;
        System.out.println("\n=== 基础签密/解签密测试 ===");
        System.out.println("签密耗时：" + signcryptTime + " ms");

        // 6. 解签密测试
        start = System.currentTimeMillis();
        try {
            String decrypted = unsigncrypt(ciphertext, sensorKey, doctorKey);
            long unsigncryptTime = System.currentTimeMillis() - start;
            System.out.println("解签密耗时：" + unsigncryptTime + " ms");
            System.out.println("原始消息：" + message);
            System.out.println("解密消息：" + decrypted);
            System.out.println("消息一致性：" + message.equals(decrypted));
        } catch (RuntimeException e) {
            System.err.println("解签密失败：" + e.getMessage());
            e.printStackTrace();
        }

        // 7. 批量验证
        customBatchVerify(100, message, pidS, pidR, sensorKey, doctorKey, GPK);
        customBatchVerify(300, message, pidS, pidR, sensorKey, doctorKey, GPK);
        customBatchVerify(500, message, pidS, pidR, sensorKey, doctorKey, GPK);
        customBatchVerify(700, message, pidS, pidR, sensorKey, doctorKey, GPK);
        customBatchVerify(1000, message, pidS, pidR, sensorKey, doctorKey, GPK);



        //相等性测试
        Ciphertext C = signcrypt("Patient: 123, HeartRate: 120, BloodPressure: 160/95, Temperature: 37.8°C, Oxygen: 95%", pidS, pidR, sensorKey, doctorKey, GPK);
        Ciphertext C1 = signcrypt("Patient: 123, HeartRate: 120, BloodPressure: 160/95, Temperature: 37.8°C, Oxygen: 95%", pidS, pidR, sensorKey, doctorKey, GPK);
        start = System.currentTimeMillis();
        boolean equalityTest = equalityTest(C1, C, td);
        long equalityTime = System.currentTimeMillis() - start;
        System.out.println("\n=== 相等性测试 ===");
        System.out.println("测试结果：" + equalityTest);
        System.out.println("测试耗时：" + equalityTime + " ms");
//
        // 9. 批量相等性测试2：无异常密文
//        List<Ciphertext> cipherListNoAbnormal = new ArrayList<>();
//        //i=100 300 500 700 1000
//        for (int i = 0; i < 100; i++) {
//            cipherListNoAbnormal.add(signcrypt(message, pidS, pidR, sensorKey, doctorKey, GPK));
//        }
//        start = System.currentTimeMillis();
//        boolean equalityTestNoAbnormal = batchEqualityTest(ciphertext, cipherListNoAbnormal, td);
//        long equalityTimeNoAbnormal = System.currentTimeMillis() - start;
////        System.out.println("\n===("+ cipherListNoAbnormal.toArray().length +"个密文) 批量相等性测试（无异常密文） ===");
////        System.out.println("测试结果：" + equalityTestNoAbnormal);
////        System.out.println("测试耗时：" + equalityTimeNoAbnormal + " ms");
//        System.out.println("\n===("+ cipherListNoAbnormal.toArray().length +" Ciphertexts) Batch Equality Test ===");
//        System.out.println("Test Result：" + equalityTestNoAbnormal);
//        System.out.println("Cost Time：" + equalityTimeNoAbnormal + " ms");
//
        // 8. 批量相等性测试1：含异常密文
        List<Ciphertext> cipherList = new ArrayList<>();
        //最好情况就是仅有单侧存在一个一场密文，算法每层都只需要判断一次相等性测试
//        n = 98, 298, 498, 698, 998 最坏情况头尾分别插入一个异常密文，这样算法就要两侧分叉都进行判断，
//        n = 99, 299, 499, 699, 999 平均情况头或尾插入一个异常密文，这样算法只需要走入一侧分叉，
        int n = 99;
        for (int i = 0; i < n; i++) {
            cipherList.add(signcrypt(message, pidS, pidR, sensorKey, doctorKey, GPK));
        }
        Ciphertext abnormalCipher = signcrypt("Patient: 123, HeartRate: Abnormal, BloodPressure: Normal, Temperature: Normal, Oxygen: Abnormal", pidS, pidR, sensorKey, doctorKey, GPK);
        List<Ciphertext> cipherListWithAbnormal = new ArrayList<>(cipherList);
        cipherListWithAbnormal.add(abnormalCipher);
//        cipherListWithAbnormal.add(0, abnormalCipher);

        start = System.currentTimeMillis();
        boolean equalityTestWithAbnormal = batchEqualityTest(ciphertext, cipherListWithAbnormal, td);
        long equalityTimeWithAbnormal = System.currentTimeMillis() - start;
//        System.out.println("\n=== ("+ cipherListWithAbnormal.toArray().length +"个密文)批量相等性测试（含1个异常密文） ===");
//        System.out.println("测试结果：" + equalityTestWithAbnormal);
//        System.out.println("测试耗时：" + equalityTimeWithAbnormal + " ms");
        System.out.println("\n=== ("+ cipherListWithAbnormal.toArray().length +" Ciphertexts ) Batch Equality Test ===");
        System.out.println("Test result：" + equalityTestWithAbnormal);
        System.out.println("Cost time：" + equalityTimeWithAbnormal + " ms");
//
//
        // 10. 异常密文检测
        start = System.currentTimeMillis();
        List<Ciphertext> abnormalList = detectAbnormal(ciphertext, cipherListWithAbnormal, td);
        long detectTime = System.currentTimeMillis() - start;
        System.out.println("\n===("+ cipherListWithAbnormal.toArray().length +" Ciphertexts) Abnormal Detection ===");
        System.out.println("The number of abnormal ciphertext：" + abnormalList.size());
        System.out.println("Cost time：" + detectTime + " ms");
        for (Ciphertext ac : abnormalList) {
            try {
                String abnormalMsg = unsigncrypt(ac, sensorKey, doctorKey);
                System.out.println("Abnormal Message：" + abnormalMsg);
            } catch (Exception e) {
                System.out.println("异常密文解密失败：" + e.getMessage());
            }
        }
    }
}