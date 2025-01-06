package com.duwei.cp.abe.text;

import it.unisa.dia.gas.jpbc.Element;
import lombok.Data;
import lombok.ToString;

@Data
@ToString
public class CipherVer extends CT{
    private Element c;
    public CipherVer(){
        super();
    }
}
