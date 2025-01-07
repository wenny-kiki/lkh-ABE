package com.duwei.cp.abe.engine;

import com.duwei.cp.abe.attribute.Attribute;
import com.duwei.cp.abe.parameter.*;
import com.duwei.cp.abe.polynomial.Polynomial;
import com.duwei.cp.abe.structure.*;
import com.duwei.cp.abe.text.CipherOwn;
import com.duwei.cp.abe.text.CipherText;
import com.duwei.cp.abe.text.CipherVer;
import com.duwei.cp.abe.text.PlainText;
import com.duwei.cp.abe.util.ConvertUtils;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Field;
import it.unisa.dia.gas.jpbc.Pairing;

import java.security.acl.Group;
import java.util.*;

/**
 * @BelongsProject: JPBC-ABE
 * @BelongsPackage: com.duwei.jpbc.cp.abe
 * @Author: duwei
 * @Date: 2022/7/21 16:30
 * @Description: 算法引擎
 */
public class CpAneEngine {

    /**
     * 在Z_r上选取随机元素
     *
     * @param publicKey
     * @return
     */
    private Element getRandomElementInZr(PublicKey publicKey) {
        return publicKey.getPairingParameter().getZr().newRandomElement().getImmutable();
    }

//    private void compute(AccessTreeNode node, PublicKey publicKey, CipherText cipherText) {
//        Field z_r = publicKey.getPairingParameter().getZr();
//        Element secretNumber = node.getSecretNumber();
//        int childrenSize = node.getChildrenSize();
//        if (node.getAccessTreeNodeType() == AccessTreeNodeType.INNER_NODE) {
//            //节点选择的多项式
//            Polynomial polynomial = new Polynomial(((InnerAccessTreeNode)node).getThreshold() - 1, secretNumber, z_r);
//            for (AccessTreeNode child : node.getChildren()) {
//                int index = child.getIndex();
//                Element childSecret = polynomial.getValue(z_r.newElement(index).getImmutable());
//                child.setParent(node);
//                child.setSecretNumber(childSecret);
//                //递归去设置子节点
//                compute(child, publicKey, cipherText);
//            }
//        }
//
//        //节点是叶节点
//        if (node.getAccessTreeNodeType() == AccessTreeNodeType.LEAF_NODE) {
//            LeafAccessTreeNode leafNode = (LeafAccessTreeNode) node;
//            //属性
//            Attribute attribute = leafNode.getAttribute();
//            //属性值
//            Element attributeValue = attribute.getAttributeValue();
//            Element c_y = (publicKey.getPairingParameter().getGenerator().powZn(leafNode.getSecretNumber())).getImmutable();
//            Element c_y_pie = (publicKey.hash(
//                    attributeValue.powZn(leafNode.getSecretNumber())
//            ).getImmutable());
//            cipherText.putCy(attribute, c_y);
//            cipherText.putCyPie(attribute, c_y_pie);
//        }
//    }

    /**
     * 递归获取密文组件
     *
     * @param node
     * @param publicKey
     * @param cipherOwn
     */
    private void compute(AccessTreeNode node, PublicKey publicKey, CipherOwn cipherOwn) {
        Field z_r = publicKey.getPairingParameter().getZr();
        Element secretNumber = node.getSecretNumber();
        int childrenSize = node.getChildrenSize();
        if (node.getAccessTreeNodeType() == AccessTreeNodeType.INNER_NODE) {
            //节点选择的多项式
            Polynomial polynomial = new Polynomial(((InnerAccessTreeNode)node).getThreshold() - 1, secretNumber, z_r);
            for (AccessTreeNode child : node.getChildren()) {
                int index = child.getIndex();
                Element childSecret = polynomial.getValue(z_r.newElement(index).getImmutable());
                child.setParent(node);
                child.setSecretNumber(childSecret);
                //递归去设置子节点
                compute(child, publicKey, cipherOwn);
            }
        }

        //节点是叶节点
        if (node.getAccessTreeNodeType() == AccessTreeNodeType.LEAF_NODE) {
            LeafAccessTreeNode leafNode = (LeafAccessTreeNode) node;
            //属性
            Attribute attribute = leafNode.getAttribute();
            //属性值
            Element attributeValue = attribute.getAttributeValue();
            Element c_y = (publicKey.getPairingParameter().getGenerator().powZn(leafNode.getSecretNumber())).getImmutable();
            Element c_y_pie = (publicKey.hash(
                    attributeValue).powZn(leafNode.getSecretNumber()).getImmutable());
            cipherOwn.putCy(attribute, c_y);
            cipherOwn.putCyPie(attribute, c_y_pie);
        }
    }

    /**
     * 基于系统密钥和属性集合生成用户私钥
     *
     * @param masterPrivateKey
     * @param attributes
     * @return
     */
    public UserPrivateKey keyGen(MasterPrivateKey masterPrivateKey, List<Attribute> attributes) {
        return UserPrivateKey.build(masterPrivateKey, attributes);
    }


    /**
     * 基于公共参数和访问树结构加密消息
     *
     * @param pk
     * @param plainText
     * @param accessTree
     * @return
     */
//    public CipherText encrypt(PublicKey pk, PlainText plainText, AccessTree accessTree) {
//        AccessTreeNode root = accessTree.getRoot();
//        //根节点的秘密数
//        Element s = getRandomElementInZr(pk);
//        root.setSecretNumber(s);
//
//        CipherText cipherText = new CipherText();
//        //1.设置密文第一部分
//
//
//        Element c_ware = (plainText.getMessageValue().mul(pk.getEgg_a().powZn(s).getImmutable())).getImmutable();
//        cipherText.setC_wave(c_ware);
//
//        //2.设置密文第二部分
//        Element c = pk.getH().powZn(s).getImmutable();
//        cipherText.setC(c);
//
//        //3.递归设置子节点
//        compute(root, pk, cipherText);
//
//        //设置访问树
//        cipherText.setAccessTree(accessTree);
//        return cipherText;
//    }

    /**
     * 加密第一阶段
     *
     * @param pk
     * @param plainText
     * @param accessTree
     * @return
     */
    public CipherOwn encryptOne(PublicKey pk, GroupKey gk, PlainText plainText, AccessTree accessTree){
        AccessTreeNode root = accessTree.getRoot();
        //根节点的秘密值
        Element s = getRandomElementInZr(pk);
        root.setSecretNumber(s);

        CipherOwn cipherOwn = new CipherOwn();

        //设置密文第一部分
        cipherOwn.setVer(0);
        cipherOwn.setAccessTree(accessTree);
        Element c_msg = (plainText.getMessageValue().mul(pk.getEgg_a().powZn(s).getImmutable())).getImmutable();
        cipherOwn.setC_msg(c_msg);
        Element c_pie = pk.getH().powZn(s).getImmutable();
        cipherOwn.setC_pie(c_pie);
        Element c_grp = gk.getGpk().powZn(s).getImmutable();
        cipherOwn.setC_grp(c_grp);

        //递归设置密文第二部分
        compute(root, pk, cipherOwn);

        return cipherOwn;
    }

    /**
     * 加密第二阶段
     *
     * @param cipherOwn
     * @param pk
     * @return
     */
    public CipherVer encryptTwo(CipherOwn cipherOwn, PublicKey pk){
        CipherVer cipherVer = new CipherVer(cipherOwn);
        PairingParameter pp = pk.getPairingParameter();
        cipherVer.setC(pp.getPairing().pairing(pp.getGenerator(),cipherVer.getC_grp().duplicate()).mul(cipherVer.getC_msg()));
        return cipherVer;
    }

    /**
     *  代理重加密
     *
     * @param cipherVer
     * @param rk
     * @param publicKey
     */
    public void reEncrypt(CipherVer cipherVer, Element rk, PublicKey publicKey){
        cipherVer.setC(publicKey.getPairingParameter().getPairing().pairing(cipherVer.getC_grp(),rk).mul(cipherVer.getC_msg()));
        cipherVer.setVer(cipherVer.getVer()+1);
    }

    /**
     * 解密得到明文字符串
     *
     * @param publicKey
     * @param userPrivateKey
     * @param cipherVer
     * @return
     */
    public String decryptToStr(PublicKey publicKey, UserPrivateKey userPrivateKey, Element ctPro, CipherVer cipherVer){
        if (ctPro != null){
            Element decrypt = ctPro.powZn(userPrivateKey.getSK()).mul(cipherVer.getC());
            return new String(ConvertUtils.byteToStr(decrypt.toBytes()));
        }
        else{
            throw new IllegalStateException("Decryption failed: invalid cipherText or userPrivateKey.");
        }
//        return null;
    }


    /**
     * 解密核心算法
     *
     * @param publicKey
     * @param userPrivateKey
     * @param cipherText
     * @return
     */
//    private Element decrypt(PublicKey publicKey, UserPrivateKey userPrivateKey, CipherText cipherText) {
//        Element decryptNode = decryptNode(publicKey, userPrivateKey, cipherText, cipherText.getAccessTree().getRoot(), userPrivateKey.getUserAttributes());
//        if (decryptNode != null) {
//            Element D = userPrivateKey.getD();
//            Element C = cipherText.getC();
//            Element c_wave = cipherText.getC_wave();
//            Pairing pairing = publicKey.getPairingParameter().getPairing();
//            return c_wave.div(pairing.pairing(C, D).div(decryptNode));
//        }
//        return null;
//    }

    /**
     * 解密前转换算法
     *
     * @param publicKey
     * @param userPrivateKey
     * @param cipherVer
     * @return
     */
    public Element transform(PublicKey publicKey, UserPrivateKey userPrivateKey, CipherVer cipherVer, GroupKey gk) {
        Element decryptNode = decryptNode(publicKey, userPrivateKey, cipherVer, cipherVer.getAccessTree().getRoot(), userPrivateKey.getUserAttributes());
        if (decryptNode != null) {
            Element D = userPrivateKey.getD().getImmutable();
            Element c_pie = cipherVer.getC_pie().getImmutable();
            Element create = userPrivateKey.getG_z().powZn(gk.getGsk()).getImmutable();
            Pairing pairing = publicKey.getPairingParameter().getPairing();
            return decryptNode.div(pairing.pairing(c_pie,D).mul(pairing.pairing(c_pie,create)));
        }
        return null;
    }

    /**
     * 递归判断用户属性是否满足访问树，解密到G1上
     *
     * @param publicKey
     * @param userPrivateKey
     * @param cipherVer
     * @param x
     * @param attributes
     * @return
     */
    private Element decryptNode(PublicKey publicKey, UserPrivateKey userPrivateKey, CipherVer cipherVer, AccessTreeNode x, List<Attribute> attributes) {
        //叶子节点
        if (x.getAccessTreeNodeType() == AccessTreeNodeType.LEAF_NODE) {
            LeafAccessTreeNode leafNode = ((LeafAccessTreeNode) x);
            Attribute attribute = leafNode.getAttribute();
            if (attributes.contains(attribute)) {
                Element cy = cipherVer.getCy(attribute);
                Element cyPie = cipherVer.getCyPie(attribute);
                Element dj = userPrivateKey.getDj(attribute);
                Element djPie = userPrivateKey.getDjPie(attribute);
                Pairing pairing = userPrivateKey.getPairingParameter().getPairing();
                return pairing.pairing(dj, cy).div(pairing.pairing(djPie, cyPie)).getImmutable();
            } else {
                return null;
            }
        }
        //内部节点
        else {
            InnerAccessTreeNode innerNode = ((InnerAccessTreeNode) x);
            int threshold = innerNode.getThreshold();
            int satisfyCount = 0;

            // 节点处理
            Map<Element, Element> indexFzMap = new HashMap<>();
            for (AccessTreeNode child : innerNode.getChildren()) {
                Element decryptNode = decryptNode(publicKey, userPrivateKey, cipherVer, child, attributes);
                if (decryptNode != null) {
                    satisfyCount++;
                    Element index = publicKey.getPairingParameter().getZr().newElement(child.getIndex()).getImmutable();
                    indexFzMap.put(index, decryptNode);
                }
            }
            if (satisfyCount < threshold) {
                return null;
            }

            // 插值重构
            Element result = publicKey.getPairingParameter().getG1().newOneElement();
            Element zero = publicKey.getPairingParameter().getZr().newZeroElement().getImmutable();
            List<Element> Sx = new ArrayList<>(indexFzMap.keySet());
            for (Map.Entry<Element, Element> entry : indexFzMap.entrySet()) {
                Element curIndex = entry.getKey();
                Element curFz = entry.getValue();
                Element powZn = Polynomial.lagrangeCoefficient(curIndex, Sx, zero, publicKey.getPairingParameter().getZr());
                result.mul((curFz.powZn(powZn)));
            }
            return result.getImmutable();
        }
    }
}
