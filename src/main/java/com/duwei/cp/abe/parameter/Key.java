package com.duwei.cp.abe.parameter;

import it.unisa.dia.gas.jpbc.Element;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * @BelongsProject: CP-ABE
 * @BelongsPackage: com.duwei.cp.abe.parameter
 * @Author: duwei
 * @Date: 2022/7/26 10:22
 * @Description: 密钥抽象类
 */
@Data
@NoArgsConstructor
public abstract class Key {
    private PairingParameter pairingParameter;

    protected Key(PairingParameter pairingParameter) {
        this.pairingParameter = pairingParameter;
    }

    /**
     * 把元素映射到G0上
     * @param element
     * @return
     */
    public Element hashG1(Element element) {
        return pairingParameter.getG1().newElementFromBytes(element.toBytes()).getImmutable();
    }

    public Element hashG2(Element element) {
        return pairingParameter.getG2().newElementFromBytes(element.toBytes()).getImmutable();
    }
}
