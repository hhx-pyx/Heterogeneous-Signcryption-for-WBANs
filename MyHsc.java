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

public class MyHsc {

    // 系统全局参数
    private static ECCurve curve;
    private static ECPoint G;
    private static BigInteger n;
    private static ECPoint P_pub;
    private static ECPoint T_pub;
    private static ECPoint C_pub;
    private static BigInteger s;
    private static BigInteger α;
    private static BigInteger β;
    private static SecureRandom random;

    // 哈希算法
    private static final String HASH_ALG = "SHA-256";

    // H0: {0,1}* → Zr*
    private static BigInteger H0(byte[] input) {
        return hashToZr(input);
    }

    // H1: {0,1}* → Zr*
    private static BigInteger H1(byte[] input) {
        return hashToZr(input);
    }

    // H2: {0,1}* × G1 × G1 × G1 → Zr*
    private static BigInteger H2(byte[] pid, ECPoint X, ECPoint Y, ECPoint Ppub) {
        byte[] combined = concat(pid, X.getEncoded(false), Y.getEncoded(false), Ppub.getEncoded(false));
        return hashToZr(combined);
    }

    // H3: G1 × G1 × {0,1}* × {0,1}* × byte[] → Zr*
    private static BigInteger H3(ECPoint U, ECPoint W, byte[] pidS, byte[] pidR, byte[] t) {
        byte[] combined = concat(U.getEncoded(false), W.getEncoded(false), pidS, pidR, t);
        return hashToZr(combined);
    }

    // H4: G1 × Zr × G1 × byte[] → Zr*
    private static BigInteger H4(ECPoint U, BigInteger C, ECPoint PKs1, byte[] t) {
        byte[] combined = concat(U.getEncoded(false), C.toByteArray(), PKs1.getEncoded(false), t);
        return hashToZr(combined);
    }

    // H5: {0,1}* → Zr*
    private static BigInteger H5(byte[] input) {
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

    // 辅助：哈希到Zr群（对 n 取模）
    private static BigInteger hashToZr(byte[] input) {
        try {
            MessageDigest md = MessageDigest.getInstance(HASH_ALG);
            byte[] hash = md.digest(input);
            return new BigInteger(1, hash).mod(n);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("哈希函数执行失败", e);
        }
    }

    // 辅助：异或运算（长度自动对齐）
    private static byte[] xor(byte[] a, byte[] b) {
        int len = Math.max(a.length, b.length);
        byte[] result = new byte[len];
        for (int i = 0; i < len; i++) {
            // 右对齐：从数组末尾开始对齐
            int aIndex = a.length - len + i;
            int bIndex = b.length - len + i;
            byte aByte = (aIndex >= 0) ? a[aIndex] : 0;
            byte bByte = (bIndex >= 0) ? b[bIndex] : 0;
            result[i] = (byte) (aByte ^ bByte);
        }
        return result;
    }

    // 辅助：扩展短密钥到目标长度
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

    // 密文结构
    public static class Ciphertext {
        BigInteger C;
        BigInteger σ;
        ECPoint U;
        byte[] CT;
        ECPoint CW;
        byte[] t;
        String pidS;
        String pidR;
        byte[] encryptedMsg;
        byte[] mLen;
    }

    // 传感器密钥对
    public static class SensorKeyPair {
        BigInteger xs;
        BigInteger psks;
        ECPoint PKs1;
        ECPoint PKs2;
        String pidS;
    }

    // 医生密钥对（PKI）
    public static class DoctorKeyPair {
        BigInteger SKr;
        ECPoint PKr;
        String pidR;
        byte[] cert;

        public DoctorKeyPair(BigInteger SKr, ECPoint PKr, String pidR, byte[] cert) {
            this.SKr = SKr;
            this.PKr = PKr;
            this.pidR = pidR;
            this.cert = cert;
        }
    }

    // 1. 系统初始化
    public static void setup() {
        random = new SecureRandom();

        // 加载 secp192r1 曲线
        ECNamedCurveParameterSpec spec = ECNamedCurveTable.getParameterSpec("secp192r1");
        curve = spec.getCurve();
        G = spec.getG();
        n = spec.getN();

        // 生成主密钥
        s = new BigInteger(n.bitLength() - 1, random);
        P_pub = G.multiply(s).normalize();
        α = new BigInteger(n.bitLength() - 1, random);
        T_pub = G.multiply(α).normalize();
        β = new BigInteger(n.bitLength() - 1, random);
        C_pub = G.multiply(β).normalize();

        System.out.println("=== WBAN系统初始化完成 (纯 ECC secp192r1) ===");
    }

    // 2. 生成传感器秘密值
    public static Object[] setSensorSecretValue() {
        BigInteger xs = new BigInteger(n.bitLength() - 1, random);
        ECPoint Xs = G.multiply(xs).normalize();
        return new Object[]{xs, Xs};
    }

    // 3. 生成医生秘密值
    public static Object[] setDoctorSecretValue() {
        BigInteger xr = new BigInteger(n.bitLength() - 1, random);
        ECPoint Xr = G.multiply(xr).normalize();
        return new Object[]{xr, Xr};
    }

    // 4. 生成伪身份
    public static String generatePseudonym(String ID, BigInteger x, ECPoint X) {
        ECPoint xTpub = T_pub.multiply(x).normalize();
        BigInteger h0 = H0(xTpub.getEncoded(false));
        byte[] VID = xor(ID.getBytes(StandardCharsets.UTF_8), h0.toByteArray());
        BigInteger h1 = H1(concat(ID.getBytes(StandardCharsets.UTF_8), xTpub.getEncoded(false)));
        byte[] AID = xor(ID.getBytes(StandardCharsets.UTF_8), h1.toByteArray());
        return new String(concat(AID, ":".getBytes(), String.valueOf(System.currentTimeMillis()).getBytes()), StandardCharsets.UTF_8);
    }

    // 5. CLC密钥生成
    public static SensorKeyPair clcKeyGen(String pidS, BigInteger xs, ECPoint Xs) {
        BigInteger rs = new BigInteger(n.bitLength() - 1, random);
        ECPoint Ys = G.multiply(rs).normalize();
        BigInteger h2 = H2(pidS.getBytes(StandardCharsets.UTF_8), Xs, Ys, P_pub);
        BigInteger psks = rs.add(s.multiply(h2).mod(n)).mod(n);

        SensorKeyPair keyPair = new SensorKeyPair();
        keyPair.xs = xs;
        keyPair.psks = psks;
        keyPair.PKs1 = Xs;
        keyPair.PKs2 = Ys;
        keyPair.pidS = pidS;
        return keyPair;
    }

    // 6. PKI密钥生成
    public static DoctorKeyPair pkiKeyGen(String pidR, BigInteger xr, ECPoint Xr) {
        BigInteger yr = new BigInteger(n.bitLength() - 1, random);
        ECPoint Yr = G.multiply(yr).normalize();
        BigInteger SKr = xr.add(yr).mod(n);
        ECPoint PKr = Xr.add(Yr).normalize();
        BigInteger hPKr = hashToZr(PKr.getEncoded(false));
        byte[] cert = hPKr.multiply(β).mod(n).toByteArray();

        return new DoctorKeyPair(SKr, PKr, pidR, cert);
    }

    // 7. 加入群组
    public static Object[] joinGroup() {
        BigInteger GSK = new BigInteger(n.bitLength() - 1, random);
        ECPoint GPK = G.multiply(GSK).normalize();
        return new Object[]{GSK, GPK};
    }

    // 8. 生成陷门
    public static BigInteger generateTrapdoor(BigInteger GSK) {
        return GSK;
    }

    // 9. 签密
    public static Ciphertext signcrypt(String m, String pidS, String pidR,
                                       SensorKeyPair sensorKey, DoctorKeyPair doctorKey, ECPoint GPK) {
        // 1. 生成随机数ui
        BigInteger ui = new BigInteger(n.bitLength() - 1, random);
        ECPoint U = G.multiply(ui).normalize();

        // 2. 计算CW和W
        ECPoint CW = U.multiply(sensorKey.xs).normalize();
        BigInteger ui_xs = ui.multiply(sensorKey.xs).mod(n);
        ECPoint W = doctorKey.PKr.multiply(ui_xs).normalize();

        // 3. 处理消息
        byte[] t = String.valueOf(System.currentTimeMillis()).getBytes(StandardCharsets.UTF_8);
        BigInteger h3 = H3(U, W, pidS.getBytes(StandardCharsets.UTF_8), pidR.getBytes(StandardCharsets.UTF_8), t);
        byte[] mBytes = m.getBytes(StandardCharsets.UTF_8);
        byte[] mLen = String.valueOf(mBytes.length).getBytes();
        byte[] shortH3 = h3.toByteArray();
        byte[] expandedH3 = expandKey(shortH3, mBytes.length);
        byte[] encryptedMsg = xor(mBytes, expandedH3);

        // 4. 生成C
        BigInteger msgHash = H5(mBytes);
        BigInteger C = msgHash.add(ui).mod(n);

        // 5. 计算σ
        BigInteger h4 = H4(U, C, sensorKey.PKs1, t);
        BigInteger h4_xs = h4.multiply(sensorKey.xs).mod(n);
        BigInteger σ = ui.add(h4_xs).add(sensorKey.psks).mod(n);

        // 6. 计算CT
        BigInteger H5m = H5(mBytes);
        BigInteger uiH5m = H5m.multiply(ui).mod(n);
        ECPoint uiGPK = GPK.multiply(ui).normalize();
        BigInteger h0 = H0(uiGPK.getEncoded(false));
        byte[] CT = xor(uiH5m.toByteArray(), h0.toByteArray());

        // 构建密文
        Ciphertext ciphertext = new Ciphertext();
        ciphertext.C = C;
        ciphertext.σ = σ;
        ciphertext.U = U;
        ciphertext.CT = CT;
        ciphertext.CW = CW;
        ciphertext.t = t;
        ciphertext.pidS = pidS;
        ciphertext.pidR = pidR;
        ciphertext.encryptedMsg = encryptedMsg;
        ciphertext.mLen = mLen;

        return ciphertext;
    }

    // 10. 解签密
    public static String unsigncrypt(Ciphertext θ, SensorKeyPair sensorKey, DoctorKeyPair doctorKey) {
        long startTime = System.nanoTime();

        // 2. 提取参数
        ECPoint Ui = θ.U;
        ECPoint Xs = sensorKey.PKs1;
        ECPoint Ys = sensorKey.PKs2;
        String pidS = sensorKey.pidS;
        ECPoint Ppub = P_pub;

        // 3. 计算h4和h2
        BigInteger h4 = H4(Ui, θ.C, Xs, θ.t);
        BigInteger h2 = H2(pidS.getBytes(StandardCharsets.UTF_8), Xs, Ys, Ppub);

        // 4. 验证σ公式
        BigInteger σ = θ.σ;
        ECPoint sigma_P = G.multiply(σ).normalize();
        ECPoint h4_Xs = Xs.multiply(h4).normalize();
        ECPoint h2_Ppub = Ppub.multiply(h2).normalize();
        ECPoint rightSide = Ui.add(h4_Xs).add(Ys).add(h2_Ppub).normalize();

        long endTime = System.nanoTime();

        if (!sigma_P.equals(rightSide)) {
            throw new RuntimeException("签密验证失败：σ公式不匹配");
        }

        // 5. 解密消息
        ECPoint W_prime = θ.CW.multiply(doctorKey.SKr).normalize();
        BigInteger h3 = H3(Ui, W_prime, θ.pidS.getBytes(StandardCharsets.UTF_8),
                θ.pidR.getBytes(StandardCharsets.UTF_8), θ.t);
        int originalLen = Integer.parseInt(new String(θ.mLen, StandardCharsets.UTF_8));
        byte[] shortH3 = h3.toByteArray();
        byte[] expandedH3 = expandKey(shortH3, originalLen);
        byte[] mBytes = xor(θ.encryptedMsg, expandedH3);
        mBytes = Arrays.copyOfRange(mBytes, 0, originalLen);

        return new String(mBytes, StandardCharsets.UTF_8);
    }

    // 11. 批量验证
    public static boolean batchVerify(List<Ciphertext> ciphertexts, List<SensorKeyPair> sensorKeys) {
        if (ciphertexts.size() != sensorKeys.size()) {
            throw new IllegalArgumentException("密文与密钥数量不匹配");
        }

        int n_size = ciphertexts.size();
        BigInteger sigma_agg = BigInteger.ZERO;
        ECPoint right_agg = curve.getInfinity();

        // 生成随机系数
        BigInteger[] a = new BigInteger[n_size];
        for (int i = 0; i < n_size; i++) {
            BigInteger r = new BigInteger(80, random);
            while (r.signum() == 0) {
                r = new BigInteger(80, random);
            }
            a[i] = r;
        }

        for (int i = 0; i < n_size; i++) {
            Ciphertext θ = ciphertexts.get(i);
            SensorKeyPair key = sensorKeys.get(i);
            sigma_agg = sigma_agg.add(θ.σ.multiply(a[i])).mod(n);

            BigInteger h4 = H4(θ.U, θ.C, key.PKs1, θ.t);
            BigInteger h2 = H2(key.pidS.getBytes(), key.PKs1, key.PKs2, P_pub);
            ECPoint h4_Xs = key.PKs1.multiply(h4).normalize();
            ECPoint h2_Ppub = P_pub.multiply(h2).normalize();
            ECPoint singleRight = θ.U.add(h4_Xs).add(key.PKs2).add(h2_Ppub).normalize();

            right_agg = right_agg.add(singleRight.multiply(a[i])).normalize();
        }

        return G.multiply(sigma_agg).normalize().equals(right_agg);
    }

    // 相等性测试
    public static boolean equalityTest(Ciphertext C, Ciphertext C1, BigInteger td) {
        // 计算 C 的 T
        ECPoint tdU = C.U.multiply(td).normalize();
        BigInteger H0_tdU = H0(tdU.getEncoded(false));
        byte[] T_bytes = xor(C.CT, H0_tdU.toByteArray());
        BigInteger T = new BigInteger(1, T_bytes).mod(n);

        // 计算 C1 的 T'
        ECPoint tdU1 = C1.U.multiply(td).normalize();
        BigInteger H0_tdU1 = H0(tdU1.getEncoded(false));
        byte[] T1_bytes = xor(C1.CT, H0_tdU1.toByteArray());
        BigInteger T1 = new BigInteger(1, T1_bytes).mod(n);

        // 验证公式
        ECPoint left = C1.U.multiply(T).normalize();
        ECPoint right = C.U.multiply(T1).normalize();

        return left.equals(right);
    }

    // 12. 批量等式测试
    public static boolean batchEqualityTest(Ciphertext refCipher, List<Ciphertext> ciphers, BigInteger td) {
        // 步骤1：计算参考密文的 T
        ECPoint refU_td = refCipher.U.multiply(td).normalize();
        BigInteger H0_refU_td = H0(refU_td.getEncoded(false));
        byte[] T_ref_bytes = xor(refCipher.CT, H0_refU_td.toByteArray());
        BigInteger T_ref = new BigInteger(1, T_ref_bytes).mod(n);

        // 步骤2：计算待测试密文的 T_j 并聚合
        BigInteger T_agg = BigInteger.ZERO;
        ECPoint U_agg = curve.getInfinity();

        for (Ciphertext θ : ciphers) {
            ECPoint Uj_td = θ.U.multiply(td).normalize();
            BigInteger H0_Uj_td = H0(Uj_td.getEncoded(false));
            byte[] Tj_bytes = xor(θ.CT, H0_Uj_td.toByteArray());
            BigInteger Tj = new BigInteger(1, Tj_bytes).mod(n);

            T_agg = T_agg.add(Tj).mod(n);
            U_agg = U_agg.add(θ.U).normalize();
        }

        // 步骤3：验证等式
        ECPoint left = U_agg.multiply(T_ref).normalize();
        ECPoint right = refCipher.U.multiply(T_agg).normalize();

        return left.equals(right);
    }

    // 13. 异常密文检测
    public static List<Ciphertext> detectAbnormal(Ciphertext refCipher, List<Ciphertext> ciphers, BigInteger td) {
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
                                         SensorKeyPair sensorKey, DoctorKeyPair doctorKey, ECPoint GPK) {
        List<Ciphertext> cipherList = new ArrayList<>();
        for (int i = 0; i < n; i++) {
            Ciphertext cipher = signcrypt(message, pidS, pidR, sensorKey, doctorKey, GPK);
            cipherList.add(cipher);
        }

        List<SensorKeyPair> sensorKeyList = new ArrayList<>();
        for (int i = 0; i < n; i++) {
            sensorKeyList.add(sensorKey);
        }

        long start = System.nanoTime();
        boolean batchVerifyResult = batchVerify(cipherList, sensorKeyList);
        long batchVerifyTime = System.nanoTime() - start;

        System.out.println("\n=== 批量验证测试（" + n + "个密文） ===");
        System.out.println("批量验证结果：" + batchVerifyResult);
        System.out.println("批量验证耗时：" + String.format("%.3f", batchVerifyTime / 1_000_000.0) + " ms");
    }



    // 主函数测试
    public static void main(String[] args) {
        // 1. 初始化
        setup();

        // 2. 生成传感器密钥
        String sensorID = "sensor-001@wbans.com";
        Object[] sensorSecret = setSensorSecretValue();
        BigInteger xs = (BigInteger) sensorSecret[0];
        ECPoint Xs = (ECPoint) sensorSecret[1];
        String pidS = generatePseudonym(sensorID, xs, Xs);
        SensorKeyPair sensorKey = clcKeyGen(pidS, xs, Xs);

        // 3. 生成医生密钥
        String doctorID = "doctor-001@hospital.com";
        Object[] doctorSecret = setDoctorSecretValue();
        BigInteger xr = (BigInteger) doctorSecret[0];
        ECPoint Xr = (ECPoint) doctorSecret[1];
        String pidR = generatePseudonym(doctorID, xr, Xr);
        DoctorKeyPair doctorKey = pkiKeyGen(pidR, xr, Xr);

        // 4. 群组初始化
        Object[] groupKeys = joinGroup();
        BigInteger GSK = (BigInteger) groupKeys[0];
        ECPoint GPK = (ECPoint) groupKeys[1];
        BigInteger td = generateTrapdoor(GSK);

        // 5. 签密测试
        String message = "Patient: Normal, HeartRate: Normal, BloodPressure: Normal, Temperature: Normal, Oxygen: Normal, RespiratoryRate: Normal, BloodSugar: Normal, ECG: Normal, BMI: Normal, Age: 45, Gender: Male";
        long start = System.nanoTime();
        Ciphertext ciphertext = signcrypt(message, pidS, pidR, sensorKey, doctorKey, GPK);
        long signcryptTime = System.nanoTime() - start;
        System.out.println("\n=== 基础签密/解签密测试 ===");
        System.out.println("签密耗时：" + String.format("%.3f", signcryptTime / 1_000_000.0) + " ms");

        // 6. 解签密测试
        start = System.nanoTime();
        try {
            String decrypted = unsigncrypt(ciphertext, sensorKey, doctorKey);
            long unsigncryptTime = System.nanoTime() - start;
            System.out.println("解签密耗时：" + String.format("%.3f", unsigncryptTime / 1_000_000.0) + " ms");
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

        // 相等性测试
        Ciphertext C = signcrypt("Patient: Normal, HeartRate: Normal, BloodPressure: Normal, Temperature: Normal, Oxygen: Normal", pidS, pidR, sensorKey, doctorKey, GPK);
        Ciphertext C1 = signcrypt("Patient: Normal, HeartRate: Normal, BloodPressure: Normal, Temperature: Normal, Oxygen: Normal", pidS, pidR, sensorKey, doctorKey, GPK);
        start = System.nanoTime();
        boolean equalityTest = equalityTest(C1, C, td);
        long equalityTime = System.nanoTime() - start;
        System.out.println("\n=== 相等性测试 ===");
        System.out.println("测试结果：" + equalityTest);
        System.out.println("测试耗时：" + String.format("%.3f", equalityTime / 1_000_000.0) + " ms");

        // 批量相等性测试：无异常密文
        // 批量相等性测试（不含异常密文）
        System.out.println("\n=== 批量相等性测试（不含异常密文） ===");
        List<Ciphertext> cipherListNormal = new ArrayList<>();
        //num = 100, 300, 500, 700, 1000
        int num = 100;
        for (int i = 0; i < num; i++) {
            cipherListNormal.add(signcrypt(message, pidS, pidR, sensorKey, doctorKey, GPK));
        }
        start = System.nanoTime();
        boolean equalityTestWithNormal = batchEqualityTest(ciphertext, cipherListNormal, td);
        long equalityTimeWithNormal = System.nanoTime() - start;
        System.out.println("\n=== ("+ cipherListNormal.toArray().length +" Ciphertexts ) Batch Equality Test ===");
        System.out.println("Test result：" + equalityTestWithNormal);
        System.out.println("Cost time：" + String.format("%.3f", equalityTimeWithNormal / 1_000_000.0) + " ms");

        // 8. 批量相等性测试：含异常密文
        System.out.println("\n=== 批量相等性测试（含异常密文） ===");
        List<Ciphertext> cipherList = new ArrayList<>();
        Ciphertext abnormalCipher = signcrypt("Patient: 123, HeartRate: Abnormal, BloodPressure: Normal, Temperature: Normal, Oxygen: Abnormal", pidS, pidR, sensorKey, doctorKey, GPK);
        int n = 99;
        for (int i = 0; i < n; i++) {
//            cipherList.add(signcrypt(message, pidS, pidR, sensorKey, doctorKey, GPK)); //best case, only one abnormal ciphertext
            cipherList.add(abnormalCipher); //worst case, all ciphertexts are abnormal
        }
        List<Ciphertext> cipherListWithAbnormal = new ArrayList<>(cipherList);
        cipherListWithAbnormal.add(abnormalCipher);

        //average case, one half normal ciphertexts
//        int m = 1000;
//        for (int i = 0; i < m/2; i++) {
//            cipherList.add(signcrypt(message, pidS, pidR, sensorKey, doctorKey, GPK));
//
//        }
//        for (int i = m/2; i < m; i++) {
//            cipherList.add(abnormalCipher);
//        }
//        List<Ciphertext> cipherListWithAbnormal = new ArrayList<>(cipherList);

        start = System.nanoTime();
        boolean equalityTestWithAbnormal = batchEqualityTest(ciphertext, cipherListWithAbnormal, td);
        long equalityTimeWithAbnormal = System.nanoTime() - start;
        System.out.println("\n=== ("+ cipherListWithAbnormal.toArray().length +" Ciphertexts ) Batch Equality Test ===");
        System.out.println("Test result：" + equalityTestWithAbnormal);
        System.out.println("Cost time：" + String.format("%.3f", equalityTimeWithAbnormal / 1_000_000.0) + " ms");

        // 10. 异常密文检测
        start = System.nanoTime();
        List<Ciphertext> abnormalList = detectAbnormal(ciphertext, cipherListWithAbnormal, td);
        long detectTime = System.nanoTime() - start;
        System.out.println("\n===("+ cipherListWithAbnormal.toArray().length +" Ciphertexts) Abnormal Detection ===");
        System.out.println("The number of abnormal ciphertext：" + abnormalList.size());
        System.out.println("Cost time：" + String.format("%.3f", detectTime / 1_000_000.0) + " ms");
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
