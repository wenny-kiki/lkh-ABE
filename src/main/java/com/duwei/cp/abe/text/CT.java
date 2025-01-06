package com.duwei.cp.abe.text;

import com.duwei.cp.abe.attribute.Attribute;
import com.duwei.cp.abe.parameter.PairingParameter;
import com.duwei.cp.abe.structure.AccessTree;
import it.unisa.dia.gas.jpbc.Element;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.HashMap;
import java.util.Map;

@Data
public abstract class CT {
    private int ver;
    private AccessTree accessTree;
    private Element c_msg;
    private Element c_pie;
    private Element c_grp;
    private Map<Attribute,Element> c_y_map;
    private Map<Attribute,Element> c_y_pie_map;
    public void putCy(Attribute attribute,Element cy){
        c_y_map.put(attribute,cy);
    }

    public void putCyPie(Attribute attribute,Element cy_pie){
        c_y_pie_map.put(attribute,cy_pie);
    }

    public Element getCy(Attribute attribute){
        return c_y_map.get(attribute);
    }

    public Element getCyPie(Attribute attribute){
        return c_y_pie_map.get(attribute);
    }

//    protected CT(PairingParameter pairingParameter) {
//        this.pairingParameter = pairingParameter;
//    }

    protected CT() {
        c_y_map = new HashMap<>();
        c_y_pie_map = new HashMap<>();
    }
}
