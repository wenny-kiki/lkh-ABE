package com.duwei.cp.abe.test;

import com.duwei.cp.abe.attribute.Attribute;
import com.duwei.cp.abe.engine.CpAneEngine;
import com.duwei.cp.abe.parameter.*;
import com.duwei.cp.abe.structure.AccessTree;
import com.duwei.cp.abe.structure.AccessTreeBuildModel;
import com.duwei.cp.abe.structure.AccessTreeNode;
import com.duwei.cp.abe.text.CipherOwn;
import com.duwei.cp.abe.text.CipherVer;
import com.duwei.cp.abe.text.PlainText;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

import java.util.Arrays;
import java.util.List;

/**
 * @BelongsProject: CP-ABE
 * @BelongsPackage: com.duwei.cp.abe.text
 * @Author: duwei
 * @Date: 2022/7/25 16:32
 * @Description: 测试类
 */
public class Test {


    public static void test1() {
        // 1.系统初始化
        SystemKey systemKey = SystemKey.build();
        //设置用户属性
        List<Attribute> attributes = Arrays.asList(
                new Attribute("硕士", systemKey.getPublicKey().getPairingParameter().getG2()),
                new Attribute("护士", systemKey.getPublicKey().getPairingParameter().getG2())
        );
        // 2.用户私钥生成
        CpAneEngine cpAneEngine = new CpAneEngine();
        UserPrivateKey userPrivateKey = cpAneEngine.keyGen(systemKey.getMasterPrivateKey(), attributes);
        // 生成组密钥
        GroupKey gk = GroupKey.build(systemKey.getPublicKey().getPairingParameter());
        // 明文
        String plainTextStr = "神秘明文";
        PlainText plainText = new PlainText(plainTextStr, systemKey.getPublicKey());
        System.out.println("plainTextStr : " + plainTextStr);
        // 构建访问树
        AccessTree accessTree = getAccessTree(systemKey.getPublicKey());
        // 3.加密
        CipherOwn cipherOwn = cpAneEngine.encryptOne(systemKey.getPublicKey(), gk, plainText, accessTree);
        CipherVer cipherVer = cpAneEngine.encryptTwo(cipherOwn,systemKey.getPublicKey());
        System.out.println("cipherText : " + cipherVer);

        Element ctPro = cpAneEngine.transform(systemKey.getPublicKey(),userPrivateKey,cipherVer,gk);
        // 4.解密
        String decryptStr = cpAneEngine.decryptToStr(userPrivateKey, ctPro, cipherVer);
        System.out.println("decryptStr : " + decryptStr);

        // 5.重加密
        Element k_0 = gk.getGsk().getImmutable();
        gk = GroupKey.build(systemKey.getPublicKey().getPairingParameter());
        Element rk = systemKey.getPublicKey().getPairingParameter().getGenerator1().powZn(gk.getGsk().duplicate().div(k_0));
        cpAneEngine.reEncrypt(cipherVer,rk,systemKey.getPublicKey());
        System.out.println("Version:" + cipherVer.getVer());
    }

    public static void test() {
        int repet = 5;
        long initTimeTotal = 0;
        long keyGenTimeTotal = 0;
        long encryptTimeTotal = 0;
        long decryptTimeTotal = 0;
        long reEncryptTimeTotal = 0;

        for(int i=0; i<repet; i++) {
            // 1.系统初始化
            long startTime = System.nanoTime();
            SystemKey systemKey = SystemKey.build();
            long endTime = System.nanoTime();
            initTimeTotal += (endTime - startTime);
            System.out.println("系统初始化时间: " + (endTime - startTime) / 1e6 + " 毫秒");

            //设置用户属性
            List<Attribute> attributes = Arrays.asList(
                    new Attribute("硕士", systemKey.getPublicKey().getPairingParameter().getG2()),
                    new Attribute("护士", systemKey.getPublicKey().getPairingParameter().getG2())
            );

            // 2.用户私钥生成
            CpAneEngine cpAneEngine = new CpAneEngine();
            startTime = System.nanoTime();
            UserPrivateKey userPrivateKey = cpAneEngine.keyGen(systemKey.getMasterPrivateKey(), attributes);
            endTime = System.nanoTime();
            keyGenTimeTotal += (endTime - startTime);
            System.out.println("用户私钥生成时间: " + (endTime - startTime) / 1e6 + " 毫秒");

            // 生成组密钥
            GroupKey gk = GroupKey.build(systemKey.getPublicKey().getPairingParameter());
            // 明文
            String plainTextStr = "神秘明文";
            PlainText plainText = new PlainText(plainTextStr, systemKey.getPublicKey());
            System.out.println("plainTextStr : " + plainTextStr);

            // 构建访问树
            AccessTree accessTree = getAccessTree(systemKey.getPublicKey());

            // 3.加密
            startTime = System.nanoTime();
            CipherOwn cipherOwn = cpAneEngine.encryptOne(systemKey.getPublicKey(), gk, plainText, accessTree);
            endTime = System.nanoTime();
            encryptTimeTotal += (endTime - startTime);
            CipherVer cipherVer = cpAneEngine.encryptTwo(cipherOwn, systemKey.getPublicKey());
            System.out.println("cipherText : " + cipherVer);
            System.out.println("加密时间: " + (endTime - startTime) / 1e6 + " 毫秒");

            Element ctPro = cpAneEngine.transform(systemKey.getPublicKey(), userPrivateKey, cipherVer, gk);
            // 4.解密
            startTime = System.nanoTime();
            String decryptStr = cpAneEngine.decryptToStr(userPrivateKey, ctPro, cipherVer);
            endTime = System.nanoTime();
            decryptTimeTotal += (endTime - startTime);
            System.out.println("decryptStr : " + decryptStr);
            System.out.println("解密时间: " + (endTime - startTime) / 1e6 + " 毫秒");

            // 5.重加密
            Element k_0 = gk.getGsk().getImmutable();
            gk = GroupKey.build(systemKey.getPublicKey().getPairingParameter());
            Element rk = systemKey.getPublicKey().getPairingParameter().getGenerator1().powZn(gk.getGsk().duplicate().div(k_0));
            startTime = System.nanoTime();
            cpAneEngine.reEncrypt(cipherVer, rk, systemKey.getPublicKey());
            endTime = System.nanoTime();
            reEncryptTimeTotal += (endTime - startTime);
            System.out.println("Version:" + cipherVer.getVer());
            System.out.println("重加密时间: " + (endTime - startTime) / 1e6 + " 毫秒");
        }

        System.out.println("系统初始化平均时间: " + (initTimeTotal / repet) / 1e6 + " 毫秒");
        System.out.println("用户私钥生成平均时间: " + (keyGenTimeTotal / repet) / 1e6 + " 毫秒");
        System.out.println("加密平均时间: " + (encryptTimeTotal / repet) / 1e6 + " 毫秒");
        System.out.println("解密平均时间: " + (decryptTimeTotal / repet) / 1e6 + " 毫秒");
        System.out.println("重加密平均时间: " + (reEncryptTimeTotal / repet) / 1e6 + " 毫秒");
    }

    public static void main(String[] args) {
        test();
    }


    public static AccessTree getAccessTree(PublicKey publicKey) {
        AccessTreeBuildModel[] accessTreeBuildModels = new AccessTreeBuildModel[7];
        //根节点ID必须为1
        accessTreeBuildModels[0] = AccessTreeBuildModel.innerAccessTreeBuildModel(1, 2, 1, -1);
        accessTreeBuildModels[1] = AccessTreeBuildModel.leafAccessTreeBuildModel(2, 1, "学生", 1);
        accessTreeBuildModels[2] = AccessTreeBuildModel.leafAccessTreeBuildModel(3, 2, "老师", 1);
        accessTreeBuildModels[3] = AccessTreeBuildModel.leafAccessTreeBuildModel(4, 3, "硕士", 1);
        accessTreeBuildModels[4] = AccessTreeBuildModel.innerAccessTreeBuildModel(5, 1, 4, 1);
        accessTreeBuildModels[5] = AccessTreeBuildModel.leafAccessTreeBuildModel(6, 1, "二班", 5);
        accessTreeBuildModels[6] = AccessTreeBuildModel.leafAccessTreeBuildModel(7, 2, "护士", 5);
        return AccessTree.build(publicKey, accessTreeBuildModels);
    }

    public static Pairing getPairing() {
        return PairingFactory.getPairing("params/curves/a.properties");
    }

    public static void pre(AccessTreeNode node) {
        System.out.println(node);
        for (AccessTreeNode child : node.getChildren()) {
            pre(child);
        }
    }

}
