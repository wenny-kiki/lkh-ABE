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

    public CipherVer(CipherOwn cipherOwn){
        super();
        this.setVer(cipherOwn.getVer());
        this.setAccessTree(cipherOwn.getAccessTree());
        this.setC_msg(cipherOwn.getC_msg().getImmutable());
        this.setC_pie(cipherOwn.getC_pie().getImmutable());
        this.setC_grp(cipherOwn.getC_grp().getImmutable());
        this.setC_y_map(cipherOwn.getC_y_map());
        this.setC_y_pie_map(cipherOwn.getC_y_pie_map());
    }
}
