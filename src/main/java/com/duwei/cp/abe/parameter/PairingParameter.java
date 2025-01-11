package com.duwei.cp.abe.parameter;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Field;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import it.unisa.dia.gas.plaf.jpbc.pairing.a1.TypeA1CurveGenerator;
import lombok.Data;
import lombok.ToString;

/**
 * @BelongsProject: JPBC-ABE
 * @BelongsPackage: com.duwei.jpbc.cp.abe.parameter
 * @Author: duwei
 * @Date: 2022/7/22 15:06
 * @Description: 双线性对参数
 */
@Data
@ToString
public class PairingParameter {
    private Pairing pairing;
//    private Field G0;
    private Field G1;
    private Field G2;
    private Field GT;
    private Field Zr;
    private Element generator1;
    private Element generator2;

    private PairingParameter() {

    }


    public static PairingParameter getInstance() {
        PairingParameter pairingParameter = new PairingParameter();
        Pairing pairing = PairingFactory.getPairing("params/curves/a.properties");
        pairingParameter.setPairing(pairing);
        pairingParameter.setG1(pairing.getG1());
//        pairingParameter.setG2(pairing.getG2());
        pairingParameter.setG2(pairing.getG1());
        pairingParameter.setGT(pairing.getGT());
        pairingParameter.setZr(pairing.getZr());
        pairingParameter.setGenerator1(pairingParameter.getG1().newRandomElement().getImmutable());
        pairingParameter.setGenerator2(pairingParameter.getG2().newRandomElement().getImmutable());
        return pairingParameter;
    }


}
