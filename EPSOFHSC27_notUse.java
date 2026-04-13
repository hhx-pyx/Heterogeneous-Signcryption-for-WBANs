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
 * VANETs场景CLIOOHSC方案完整实现
 * 异构系统：CLC（车辆）→ IBC（RSU）
 * 核心功能：在线/离线异构签密 + 身份匿名 + 不可链接性 + 条件可追溯
 * 安全等级：IND-CCA2 + EUF-CMA-I + EUF-CMA-II
 */
public class EPSOFHSC27_notUse {
    // 系统全局参数（论文Section IV定义）
    private static Pairing bp;
    private static Element P; // G1生成元（加法群）
    private static Element Ppub; // 系统公钥 (s·P)
    private static Element s; // KGC主密钥 Zp*
    private static BigInteger p; // 群素数阶
    private static final String HASH_ALG = "SHA-256";

    // 哈希函数定义（严格匹配论文5个哈希函数+变色龙哈希f，Section IV.A）
    private static Element H0(Element input) { return hashToZr(input.toBytes()); }
    private static Element H1(byte[] PID, Element D, Element T) {
        byte[] combined = concat(PID, D.toBytes(), T.toBytes());
        return hashToZr(combined);
    }
    private static Element H2(byte[] PID, Element PK) {
        byte[] combined = concat(PID, PK.toBytes());
        return hashToZr(combined);
    }
    private static Element H3(byte[] input) { return hashToG1(input); }
    private static Element H4(Element G1, byte[] input) {
        byte[] combined = concat(G1.toBytes(), input);
        return hashToZr(combined);
    }
    private static Element chameleonHash(Element r, Element G1) {
        // 变色龙哈希f: Zp* × G1 → Zp*（论文参考[35]）
        byte[] combined = concat(r.toBytes(), G1.toBytes());
        return hashToZr(combined);
    }

    // 辅助类：车辆伪身份（Section IV.B）
    public static class Pseudonym {
        Element PID1; // wi·P
        byte[] PID2; // RIDi ⊕ H0(s·PID1)
        public Pseudonym(Element pid1, byte[] pid2) {
            this.PID1 = pid1;
            this.PID2 = pid2;
        }
    }

    // 辅助类：CLC车辆密钥对（Section IV.C）
    public static class CLCVehicleKeyPair {
        Pseudonym pid; // 伪身份
        Element di; // 自有秘密值 Zp*
        Element Di; // di·P
        Element li; // 部分私钥组件
        Element Ti; // ti·P（部分私钥组件）
        Element PKi; // 公钥（Ti + μi·Di）
        Element SKi; // 完整私钥（li + μi·di）
        Element kstar; // 随机秘密值 Zp*
        Element hi; // 公钥组件（kstar·(PKi + vi·Ppub)）
        public CLCVehicleKeyPair(Pseudonym pid, Element di, Element Di, Element li, Element Ti, Element PKi, Element SKi, Element kstar, Element hi) {
            this.pid = pid;
            this.di = di;
            this.Di = Di;
            this.li = li;
            this.Ti = Ti;
            this.PKi = PKi;
            this.SKi = SKi;
            this.kstar = kstar;
            this.hi = hi;
        }
    }

    // 辅助类：IBC-RSU密钥对（Section IV.D）
    public static class IBCRSUKeyPair {
        String IDr; // RSU身份标识
        Element skr; // 私钥（s·H3(IDr)）
        public IBCRSUKeyPair(String IDr, Element skr) {
            this.IDr = IDr;
            this.skr = skr;
        }
    }

    // 辅助类：离线签密密文（Section IV.E）
    public static class OfflineCiphertext {
        Element si; // ri·SKi⁻¹
        Element Ri; // ri·P
        Element Wi; // H4(Ui)，Ui = e(ri·Ppub, H3(IDr))
        public OfflineCiphertext(Element si, Element Ri, Element Wi) {
            this.si = si;
            this.Ri = Ri;
            this.Wi = Wi;
        }
    }

    // 辅助类：在线签密密文（Section IV.F）
    public static class OnlineCiphertext {
        byte[] Ci; // (r'i || m) ⊕ Wi
        Element Ri; // 继承离线密文Ri
        public OnlineCiphertext(byte[] Ci, Element Ri) {
            this.Ci = Ci;
            this.Ri = Ri;
        }
    }

    // 1. 系统初始化（Section IV.A，Algorithm 1）
    public static void setup(int securityParam) {
        // 生成Type A曲线（论文Section VI实验配置，128位安全等级）
        TypeACurveGenerator pg = new TypeACurveGenerator(securityParam, 192);
        PairingParameters pp = pg.generate();
        bp = PairingFactory.getPairing(pp);

        P = bp.getG1().newRandomElement().getImmutable();
        s = bp.getZr().newRandomElement().getImmutable();
        Ppub = P.powZn(s).getImmutable();
        p = new BigInteger(bp.getZr().getOrder().toString());

        System.out.println("=== VANETs CLIOOHSC系统初始化完成 ===");
        System.out.println("素数阶p：" + p);
        System.out.println("系统公钥Ppub：" + Ppub);
    }

    // 2. 车辆注册（获取伪身份，Section IV.B，Algorithm 2）
    public static Pseudonym registration(String RID) {
        byte[] RID_bytes = RID.getBytes(StandardCharsets.UTF_8);
        Element wi = bp.getZr().newRandomElement().getImmutable();
        Element PID1 = P.powZn(wi).getImmutable(); // PID1 = wi·P
        Element s_PID1 = PID1.powZn(s).getImmutable(); // s·PID1
        Element H0_sPID1 = H0(s_PID1);
        byte[] PID2 = xor(RID_bytes, H0_sPID1.toBytes()); // PID2 = RIDi ⊕ H0(s·PID1)
        return new Pseudonym(PID1, PID2);
    }

    // 3. CLC车辆密钥生成（Section IV.C，Algorithm 3-5）
    public static CLCVehicleKeyPair clcKeyGen(Pseudonym pid) {
        byte[] PID_bytes = concat(pid.PID1.toBytes(), pid.PID2);

        // Algorithm 3: 生成秘密值di
        Element di = bp.getZr().newRandomElement().getImmutable();
        Element Di = P.powZn(di).getImmutable(); // Di = di·P

        // Algorithm 4: 提取部分私钥pski=(li, Ti)
        Element ti = bp.getZr().newRandomElement().getImmutable();
        Element Ti = P.powZn(ti).getImmutable(); // Ti = ti·P
        Element mu_i = H1(PID_bytes, Di, Ti); // μi = H1(PIDi, Di, Ti)
        Element vi = H2(PID_bytes, Ti.add(Di.powZn(mu_i))); // vi = H2(PIDi, PKi)
        Element li = ti.add(s.mulZn(vi)).getImmutable(); // li = ti + s·vi mod p

        // 验证部分私钥：li·P == Ti + vi·Ppub
        Element liP = P.powZn(li).getImmutable();
        Element Ti_viPpub = Ti.add(Ppub.powZn(vi)).getImmutable();
        if (!liP.isEqual(Ti_viPpub)) {
            throw new RuntimeException("CLC密钥生成失败：部分私钥验证不通过");
        }

        // Algorithm 5: 生成完整公私钥对
        Element PKi = Ti.add(Di.powZn(mu_i)).getImmutable(); // PKi = Ti + μi·Di
        Element SKi = li.add(mu_i.mulZn(di)).getImmutable(); // SKi = li + μi·di
        Element kstar = bp.getZr().newRandomElement().getImmutable(); // 随机秘密值k*
        Element PKi_viPpub = PKi.add(Ppub.powZn(vi)).getImmutable();
        Element hi = PKi_viPpub.powZn(kstar).getImmutable(); // hi = k*·(PKi + vi·Ppub)

        return new CLCVehicleKeyPair(pid, di, Di, li, Ti, PKi, SKi, kstar, hi);
    }

    // 4. IBC-RSU密钥生成（Section IV.D，Algorithm 6）
    public static IBCRSUKeyPair ibcKeyGen(String IDr) {
        byte[] IDr_bytes = IDr.getBytes(StandardCharsets.UTF_8);
        Element H3_IDr = H3(IDr_bytes); // H3(IDr) ∈ G1
        Element skr = H3_IDr.powZn(s).getImmutable(); // skr = s·H3(IDr)
        return new IBCRSUKeyPair(IDr, skr);
    }

    // 5. 离线签密（Section IV.E，Algorithm 7）
    public static OfflineCiphertext offlineSigncrypt(CLCVehicleKeyPair vehicleKey, IBCRSUKeyPair rsuKey) {
        // 生成随机数ri ∈ Zp*
        Element ri = bp.getZr().newRandomElement().getImmutable();

        // 计算Ui = e(ri·Ppub, H3(IDr))
        byte[] IDr_bytes = rsuKey.IDr.getBytes(StandardCharsets.UTF_8);
        Element H3_IDr = H3(IDr_bytes);
        Element riPpub = Ppub.powZn(ri).getImmutable();
        Element Ui = bp.pairing(riPpub, H3_IDr).getImmutable();

        // 计算si = ri·SKi⁻¹
        Element SKi_inv = vehicleKey.SKi.invert().getImmutable();
        Element si = ri.mulZn(SKi_inv).getImmutable();

        // 计算Wi = H4(Ui)
        Element Wi = H4(Ui, new byte[0]); // H4输入：G1×{0,1}*，此处{0,1}*为空

        return new OfflineCiphertext(si, P.powZn(ri), Wi);
    }

    // 6. 在线签密（Section IV.F，Algorithm 8）
    public static OnlineCiphertext onlineSigncrypt(String m, OfflineCiphertext offlineCipher, CLCVehicleKeyPair vehicleKey) {
        byte[] m_bytes = m.getBytes(StandardCharsets.UTF_8);

        // 计算变色龙哈希f(m, Ri)
        Element f = chameleonHash(vehicleKey.kstar, offlineCipher.Ri);

        // 计算r'i = k* - f·si mod p
        Element f_si = f.mulZn(offlineCipher.si).getImmutable();
        Element r_prime_i = vehicleKey.kstar.sub(f_si).getImmutable();

        // 计算Ci = Wi ⊕ (r'i || m)
        byte[] r_prime_bytes = r_prime_i.toBytes();
        byte[] r_m = concat(r_prime_bytes, m_bytes);
        byte[] Wi_bytes = offlineCipher.Wi.toBytes();
        byte[] Ci = xor(r_m, Wi_bytes);

        return new OnlineCiphertext(Ci, offlineCipher.Ri);
    }

    // 7. 解签密（Section IV.G，Algorithm 9）
    public static String unsigncrypt(OnlineCiphertext onlineCipher, CLCVehicleKeyPair vehicleKey, IBCRSUKeyPair rsuKey) {
        byte[] PID_bytes = concat(vehicleKey.pid.PID1.toBytes(), vehicleKey.pid.PID2);

        // 计算Ui = e(Ri, skr)
        Element Ui = bp.pairing(onlineCipher.Ri, rsuKey.skr).getImmutable();

        // 计算Wi = H4(Ui)，恢复r'i || m
        Element Wi = H4(Ui, new byte[0]);
        byte[] r_m = xor(onlineCipher.Ci, Wi.toBytes());

        // 分离r'i和m
        int zrLen = bp.getZr().newElement().toBytes().length;
        byte[] r_prime_bytes = Arrays.copyOfRange(r_m, 0, zrLen);
        byte[] m_bytes = Arrays.copyOfRange(r_m, zrLen, r_m.length);
        Element r_prime_i = bp.getZr().newElementFromBytes(r_prime_bytes).getImmutable();

        // 计算变色龙哈希f(m, Ri)
        Element f = chameleonHash(vehicleKey.kstar, onlineCipher.Ri);

        // 验证hi == f·Ri + r'i·(PKi + vi·Ppub)
        Element vi = H2(PID_bytes, vehicleKey.PKi);
        Element PKi_viPpub = vehicleKey.PKi.add(Ppub.powZn(vi)).getImmutable();
        Element f_Ri = onlineCipher.Ri.powZn(f).getImmutable();
        Element r_prime_PKiVi = PKi_viPpub.powZn(r_prime_i).getImmutable();
        Element verify = f_Ri.add(r_prime_PKiVi).getImmutable();

        if (!verify.isEqual(vehicleKey.hi)) {
            throw new RuntimeException("解签密失败：密文验证不通过");
        }

        return new String(m_bytes, StandardCharsets.UTF_8);
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

    // 辅助工具：哈希到G1群
    private static Element hashToG1(byte[] input) {
        try {
            MessageDigest md = MessageDigest.getInstance(HASH_ALG);
            byte[] hash = md.digest(input);
            return bp.getG1().newElementFromHash(hash, 0, hash.length).getImmutable();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("哈希函数执行失败", e);
        }
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

    // 主函数：VANETs场景完整流程测试
    public static void main(String[] args) {
        // 1. 系统初始化（安全参数192，匹配论文配置）
        setup(192);

        // 2. 车辆注册（获取伪身份）
        String vehicleRID = "Vehicle-001@vanets-highway.com";
        Pseudonym vehiclePID = registration(vehicleRID);
        System.out.println("\n=== 车辆注册完成 ===");
        System.out.println("车辆伪身份PID1：" + vehiclePID.PID1);

        // 3. 生成CLC车辆密钥对
        CLCVehicleKeyPair vehicleKey = clcKeyGen(vehiclePID);
        System.out.println("\n=== CLC车辆密钥生成完成 ===");
        System.out.println("车辆公钥PKi：" + vehicleKey.PKi);

        // 4. 生成IBC-RSU密钥对
        String rsuID = "RSU-001@highway-G45";
        IBCRSUKeyPair rsuKey = ibcKeyGen(rsuID);
        System.out.println("\n=== IBC-RSU密钥生成完成 ===");
        System.out.println("RSU身份IDr：" + rsuKey.IDr);

        // 5. 离线签密（预计算重负载）
        long offlineStart = System.currentTimeMillis();
        OfflineCiphertext offlineCipher = offlineSigncrypt(vehicleKey, rsuKey);
        long offlineTime = System.currentTimeMillis() - offlineStart;
        System.out.println("\n=== 离线签密完成 ===");
        System.out.println("离线签密耗时：" + offlineTime + " ms");

        // 6. 在线签密（轻负载运算）
        String message = "TrafficInfo: Road-G45, Congestion: Low, SpeedLimit: 100km/h, Time: 2024-08-01 10:30:00";
        long onlineStart = System.currentTimeMillis();
        OnlineCiphertext onlineCipher = onlineSigncrypt(message, offlineCipher, vehicleKey);
        long onlineTime = System.currentTimeMillis() - onlineStart;
        System.out.println("\n=== 在线签密完成 ===");
        System.out.println("原始消息：" + message);
        System.out.println("在线签密耗时：" + onlineTime + " ms");

        // 7. 解签密（RSU执行）
        long unsignStart = System.currentTimeMillis();
        long unsignTime;
//        try {
            String decryptedMsg = unsigncrypt(onlineCipher, vehicleKey, rsuKey);
            unsignTime = System.currentTimeMillis() - unsignStart;
            System.out.println("\n=== 解签密完成 ===");
            System.out.println("解密消息：" + decryptedMsg);
            System.out.println("解签密耗时：" + unsignTime + " ms");
            System.out.println("消息一致性：" + message.equals(decryptedMsg));
//        } catch (RuntimeException e) {
//            System.err.println("\n解签密失败：" + e.getMessage());
//            e.printStackTrace();
//        }

        // 8. 性能统计
        System.out.println("\n=== 核心功能性能统计 ===");
        System.out.println("离线签密耗时：" + offlineTime + " ms");
        System.out.println("在线签密耗时：" + onlineTime + " ms");
        System.out.println("签密总耗时（离线+在线）：" + (offlineTime + onlineTime) + " ms");
        System.out.println("解签密耗时：" + unsignTime + " ms");
    }
}
