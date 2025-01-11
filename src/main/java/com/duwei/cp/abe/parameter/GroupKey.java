package com.duwei.cp.abe.parameter;

import it.unisa.dia.gas.jpbc.Element;
import lombok.Data;
import lombok.ToString;

@Data
@ToString
public class GroupKey extends Key {
    private Element gsk;
    private Element gpk;

    private GroupKey() {

    }

    private GroupKey(PairingParameter parameter) {
        super(parameter);
    }

    public static GroupKey build(PairingParameter parameter) {
        GroupKey groupKey = new GroupKey(parameter);
        groupKey.setGsk(parameter.getZr().newRandomElement().getImmutable());
        groupKey.setGpk(parameter.getGenerator2().powZn(groupKey.getGsk()).getImmutable());
        return groupKey;
    }
}
