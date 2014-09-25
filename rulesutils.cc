#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <list>
#include <map>
#include <unordered_map>
#include <iostream>
#include <algorithm>
#include <sstream>
#include <cmath>
#include <vector>
#include <arpa/inet.h>
#include <string.h>


#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "rulesutils.h"
#include "rtrie.h"
#include "prefix.h"

void init_boundary(rule_boundary & rb)
{
    rb.field[0].low = 0;
    rb.field[0].high = 0xFFFFFFFF;
    rb.field[1].low = 0;
    rb.field[1].high = 0xFFFFFFFF;
    rb.field[2].low = 0;
    rb.field[2].high = 0xFFFF;
    rb.field[3].low = 0;
    rb.field[3].high = 0xFFFF;
    rb.field[4].low = 0;
    rb.field[4].high = 0xFF;
}

int CheckIPBounds(range fld)
{
    if (fld.low > 0xFFFFFFFF)
    {
        printf("Error: IPRange is buggy!(%llu)\n",fld.low);
        return 1;
    }
    if (fld.high > 0xFFFFFFFF)
    {
        printf("Error: IPRange is buggy!(%llu)\n",fld.high);
        return 1;
    }
    if (fld.low > fld.high)
    {
        printf("Error: IPRange is buggy!(%llu - %llu)\n",fld.low,fld.high);
        return 1;
    }
    return 0;
}

void IP2Range(unsigned ip1,unsigned ip2,unsigned ip3,unsigned ip4,unsigned iplen,pc_rule *rule,int index)
{
    unsigned tmp;
    unsigned Lo,Hi;

    if(iplen == 0){
        Lo = 0;
        Hi = 0xFFFFFFFF;

    }else if(iplen > 0 && iplen <= 8) {
        tmp = ip1 << 24;
        tmp &= (0xffffffff << (32-iplen));

        Lo = tmp;
        Hi = Lo + (1<<(32-iplen)) - 1;
    }else if(iplen > 8 && iplen <= 16){
        tmp =  ip1 << 24; 
        tmp += ip2 << 16;
        tmp &= (0xffffffff << (32-iplen));

        Lo = tmp;
        Hi = Lo + (1<<(32-iplen)) - 1;
    }else if(iplen > 16 && iplen <= 24){
        tmp = ip1 << 24; 
        tmp += ip2 << 16; 
        tmp += ip3 << 8; 
        tmp &= (0xffffffff << (32-iplen));

        Lo = tmp;
        Hi = Lo + (1<<(32-iplen)) - 1;
    }else if(iplen > 24 && iplen <= 32){
        tmp = ip1 << 24; 
        tmp += ip2 << 16; 
        tmp += ip3 << 8; 
        tmp += ip4;
        tmp &= (0xffffffff << (32-iplen));

        Lo = tmp;
        Hi = Lo + (1<<(32-iplen)) - 1;
    }else{
        printf("Error: Src IP length exceeds 32\n");
        exit(1);
    }

    rule->field[index].low  = Lo;
    rule->field[index].high = Hi;

    if (CheckIPBounds(rule->field[index]))
    {
        printf("Error: IP2Range bounds check for %d failed\n",index);
        exit(1);
    }

}

int loadrules(FILE *fp, vector<pc_rule> &classifier) {
    int i = 0;
    int wild = 0;
    unsigned sip1, sip2, sip3, sip4, siplen;
    unsigned dip1, dip2, dip3, dip4, diplen;
    unsigned proto, protomask;
    unsigned junk, junkmask;

    pc_rule rule;

    while(1) {
        wild = 0;
        if(fscanf(fp,"@%u.%u.%u.%u/%u\t%u.%u.%u.%u/%u\t%llu : %llu\t%llu : %llu\t%x/%x\t%x/%x\n",
                    &sip1, &sip2, &sip3, &sip4, &siplen, &dip1, &dip2, &dip3, &dip4, &diplen, 
                    &rule.field[2].low, &rule.field[2].high, &rule.field[3].low, &rule.field[3].high,
                    &proto, &protomask, &junk, &junkmask) != 18) break;

        /*if(fscanf(fp,"@%u.%u.%u.%u/%u %u.%u.%u.%u/%u %llu : %llu %llu : %llu %x/%x\n",
                   &sip1, &sip2, &sip3, &sip4, &siplen, &dip1, &dip2, &dip3, &dip4, &diplen, 
                   &rule.field[2].low, &rule.field[2].high, &rule.field[3].low, &rule.field[3].high,
                   &proto, & protomask) != 16) break;*/
        rule.siplen = siplen;
        rule.diplen = diplen;
        rule.sip[0] = sip1;
        rule.sip[1] = sip2;
        rule.sip[2] = sip3;
        rule.sip[3] = sip4;
        rule.dip[0] = dip1;
        rule.dip[1] = dip2;
        rule.dip[2] = dip3;
        rule.dip[3] = dip4;

        IP2Range(sip1,sip2,sip3,sip4,siplen,&rule,0);
        IP2Range(dip1,dip2,dip3,dip4,diplen,&rule,1);

        if(protomask == 0xFF){
            rule.field[4].low = proto;
            rule.field[4].high = proto;
        }else if(protomask == 0){
            rule.field[4].low = 0;
            rule.field[4].high = 0xFF;
            wild++;
        }else{
            printf("Protocol mask error\n");
            return 0;
        }
        rule.priority = i;
        if ((rule.field[0].low == 0) && (rule.field[0].high == 0xffffffff)) {
            wild++;
        }
        if ((rule.field[1].low == 0) && (rule.field[1].high == 0xffffffff)) {
            wild++;
        }
        if ((rule.field[2].low == 0) && (rule.field[2].high == 65535)) {
            wild++;
        }
        if ((rule.field[3].low == 0) && (rule.field[3].high == 65535)) {
            wild++;
        }
        if (wild != 5) {
            classifier.push_back(rule);
            i++;
        }
    }
    return i;
}

range range_in_boundary_1D(range r, range boundary)
{
    range ret;
    if (r.low > boundary.low) {
        ret.low = r.low; 
    }
    else {
        ret.low = boundary.low;
    }

    if (r.high < boundary.high) {
        ret.high = r.high;
    }
    else {
        ret.high = boundary.high;
    }
    return ret;
}

bool is_equal(pc_rule rule1, pc_rule rule2, rule_boundary boundary)
{
    int count = 0;
    range r1, r2;
    for (int i = 0;i < MAXDIMENSIONS;i++)
    {

        r1 = range_in_boundary_1D(rule1.field[i], boundary.field[i]);

        r2 = range_in_boundary_1D(rule2.field[i], boundary.field[i]);

        if (r1.low <= r2.low && r1.high >= r2.high)

        {
            count++;
        }
    }

    if (count == MAXDIMENSIONS)
        return true;
    else
        return false;
}

void init_rnode(rnode *n, rule_boundary &b) 
{
    rg sip(b.field[0].low, b.field[0].high);
    rg dip(b.field[1].low, b.field[1].high);

    n[0].setb(sip);
    n[1].setb(dip);

}

void remove_redund_rt(vector<pc_rule*> &pr, rule_boundary &b, bool large) 
{
    vector<pc_rule*> rulelist;
    
    range br;
    
    rnode rt[2];
    vector<pc_rule*> set[2];
    //map<int, int> sect;
    vector<pc_rule*> sect;

    init_rnode(rt, b);
    //int count = 0;

    for(auto rule = pr.begin(); rule != pr.end(); ++ rule) {
        sect.clear();
        for(int i = 0; i < 2; i++) {
            br = range_in_boundary_1D((*rule)->field[i], b.field[i]); 
            set[i].clear();
            rt_qry_insert(rt+i, rg(br.low, 
                    br.high), set[i], (*rule));
        }

        sort(set[0].begin(), set[0].end());
        sort(set[1].begin(), set[1].end());
        set_intersection(set[0].begin(), set[0].end(),
                set[1].begin(), set[1].end(),
                back_inserter(sect));

        if(sect.empty()) {
            rulelist.push_back(*rule);
        }
        else {
            bool found = false;
            for(auto check_rule = sect.begin();
                    check_rule != sect.end();
                    check_rule++) {
                if(is_equal(**check_rule, **rule, b)) {
                    found = true;
                    //count++;
                    //cout<<(*rule)->priority<<" was hide by " <<*check_rule<<endl;
                    break;
                }
            }

            if(!found) {
                rulelist.push_back(*rule);
            }
        }

    }

    rt_destory(rt[0].left);
    rt_destory(rt[0].right);
    rt_destory(rt[1].left);
    rt_destory(rt[1].right);

    pr = move(rulelist);
}

struct prefix *extend_prefix(unsigned ai, unsigned aj)
{
  struct prefix *pf = new prefix();
  int i = 0;  

  if(ai == aj) {
    pf->value[i] = ai;
    pf->length[i] = 16;
    pf->fullpf = ai;
    pf->fpf_len = 16;
    pf->nvalid = 1;

    pf->cmplvalue[i] = ai;
    pf->cmpllength[i] = 16;
    pf->ninvalid = 1; 
    return pf;
  } 
 
  int k;
  bool flag = false;
  pf->ninvalid = 0;         
  while(1) {
    for(k = 0; (ai & (int)pow(2,k)) == 0 && k <= 15 ; k ++);
    if(ai + pow(2,k) - 1 == aj) {       
      pf->value[i] = ai>>k<<k;
      pf->length[i] = 16 - k;
      pf->nvalid = i + 1;

      if( i  == 0) {
        pf->fullpf = ai>>k<<k;
        pf->fpf_len = 16 - k;

        pf->cmplvalue[i] = ai>>k<<k;
        pf->cmpllength[i] = 16 - k;
        pf->ninvalid = 1;
      }
      else {
        pf->fullpf = ai>>(k + 1)<<(k + 1);
        pf->fpf_len = 16 - k - 1;
        
        int numcmpl = pf->length[i - 1] - pf->length[i] - 1;
        while(numcmpl > 0) {
            pf->cmplvalue[pf->ninvalid] = (ai - (int)pow(2,k))>>(k - numcmpl)<<(k - numcmpl);
            pf->cmpllength[pf->ninvalid] = 16 - k + numcmpl;
            numcmpl --;
            pf->ninvalid ++;
        }
      }
      return pf;
    }
    else if (ai + pow(2,k) - 1 < aj) {
      pf->value[i] = ai>>k<<k;
      pf->length[i] = 16 - k;
      if(i == 0) {
        pf->cmplvalue[pf->ninvalid] = (ai - (int)pow(2,k))>>k<<k;
        pf->cmpllength[pf->ninvalid] = 16 - k;
        pf->ninvalid ++;
      }
      else {
        int numcmpl = pf->length[i - 1] - pf->length[i] - 1;
        while(numcmpl > 0) {
            pf->cmplvalue[pf->ninvalid] = (ai - (int)pow(2,k))>>(k - numcmpl)<<(k - numcmpl);
            pf->cmpllength[pf->ninvalid] = 16 - k + numcmpl;
            numcmpl --;
            pf->ninvalid ++;
        }
      }
      ai = ai + (int)pow(2, k);
    }
    else{
        if(i != 0) {
            flag = true;
            pf->fullpf = ai>>(k + 1)<<(k + 1);
            pf->fpf_len = 16 - k - 1; 

            int numcmpl = pf->length[i - 1] - pf->fpf_len - 2;
            while(numcmpl > 0) {
                pf->cmplvalue[pf->ninvalid] = (ai - (int)pow(2,k))>>(k - numcmpl)<<(k - numcmpl);
                pf->cmpllength[pf->ninvalid] = 16 - k + numcmpl;
                numcmpl --;
                pf->ninvalid ++;
            }
        }
      break;
    }        
    i++;
  } 

  if(ai == aj){
    pf->value[i] = ai;
    pf->length[i] = 16;
    pf->nvalid = i + 1;

    pf->cmplvalue[pf->ninvalid] = ai + 1;
    pf->cmpllength[pf->ninvalid] = 16;
    pf->ninvalid ++; 
    return pf;
  } 

  while(ai < aj) {
    for(k = 15; ((ai ^ aj) & (int)pow(2,k)) == 0 ; k --);
    if(ai + pow(2,k + 1) - 1 == aj) {
      pf->value[i] = ai>>(k+1)<<(k+1);
      pf->length[i] = 15 - k;
      pf->nvalid = i + 1;

      if(!flag) {
        if(i == 0){
            pf->fullpf = ai>>(k+1)<<(k+1);
            pf->fpf_len = 15 - k;
        }
        else {
            pf->fullpf = pf->value[0]>>(15 - pf->length[0])<<(15 - pf->length[0]);
            pf->fpf_len = pf->length[0] - 1;
        }
      }

      pf->cmplvalue[pf->ninvalid] = (ai + (int)pow(2, k + 1))>>(k + 1)<<(k + 1);
      pf->cmpllength[pf->ninvalid] = 15 - k;
      pf->ninvalid ++;
      i--;
      while((pf->value[i] >> (16 - pf->length[i])) % 2 == 0 && i > 0) {
        int numcmpl = pf->length[i + 1] - pf->length[i] - 1;
        while(numcmpl > 0) {
            int move = 16 - pf->length[i] - numcmpl;
            pf->cmplvalue[pf->ninvalid] = (ai + (int)pow(2, move))>>move<<move;
            pf->cmpllength[pf->ninvalid] = pf->length[i] + numcmpl;
            numcmpl--;
            pf->ninvalid ++;
        }
        i--;
      }
      int numcmpl = pf->length[i + 1] - pf->fpf_len - 2;
      int tmp = 1;
      while(numcmpl >= tmp ) {
        int move = 16 - pf->length[i + 1] + tmp; 
        pf->cmplvalue[pf->ninvalid] = (ai + (int)pow(2, move))>>move<<move;
        pf->cmpllength[pf->ninvalid] = pf->length[i + 1] - tmp;
        tmp ++;
        pf->ninvalid ++;
      }
      return pf;
    } 
    else {
      pf->value[i]=ai>>k<<k;
      pf->length[i]=16 - k;
      ai = ai + (int)pow(2,k);
    }
    i++;        
  } 

  pf->value[i] = ai;
  pf->length[i] = 16;
  pf->nvalid = i + 1;
  
  if(!flag) {
    pf->fullpf = pf->value[0]>>(15 - pf->length[0])<<(15 - pf->length[0]);
    pf->fpf_len = pf->length[0] - 1;
  }

  pf->cmplvalue[pf->ninvalid] = ai + (int)pow(2, 0);
  pf->cmpllength[pf->ninvalid] = 16;
  pf->ninvalid ++;
  i--;
  while((pf->value[i] >> (16 - pf->length[i])) % 2 == 0 && i > 0) {
    int numcmpl = pf->length[i + 1] - pf->length[i] - 1;
    while(numcmpl > 0) {
        int move = 16 - pf->length[i] - numcmpl;
        pf->cmplvalue[pf->ninvalid] = (ai + (int)pow(2, move))>>move<<move;
        pf->cmpllength[pf->ninvalid] = pf->length[i] + numcmpl;
        numcmpl--;
        pf->ninvalid ++;
    }
    i--;
  }
  int numcmpl = pf->length[i + 1] - pf->fpf_len - 2;
  int tmp = 1;
  while(numcmpl >= tmp ) {
    int move = 16 - pf->length[i + 1] + tmp; 
    pf->cmplvalue[pf->ninvalid] = (ai + (int)pow(2, move))>>move<<move;
    pf->cmpllength[pf->ninvalid] = pf->length[i + 1] - tmp;
    tmp ++;
    pf->ninvalid ++;
  }

  return pf;
}

bool check_cmpl(struct prefix *pf) 
{
    int rangelen = 0;
    if(pf->nvalid != 1) {
        for(size_t i = 0; i < pf->nvalid; i ++) {
            rangelen += (int)pow(2, 16 - pf->length[i]);
        }
        for(size_t i = 0; i < pf->ninvalid; i ++) {
            rangelen += (int)pow(2, 16 - pf->cmpllength[i]);
        }
    }
    else {
        rangelen = (int)pow(2, 16 - pf->length[0]);
    }
    if(rangelen == (int)pow(2, 16 - pf->fpf_len)) {
        return true;
    }
    else {
        cout<<pf->nvalid<<endl;
        cout<<rangelen<<" "<<pf->fpf_len<<" "<<(int)pow(2, 16 - pf->fpf_len)<<endl;
        return false;
    }
}

void extend_rules(vector<pc_rule*> &in, vector<pc_rule> &out) 
{
    cout<<"Input ruleset: "<<in.size()<<endl;
    struct prefix *srcpf = new prefix();
    struct prefix *dstpf = new prefix();
    int numext;
    int numcmpl_vext;
    int numcmpl_hext;
    for(size_t i = 0; i < in.size(); i++) {
        srcpf = extend_prefix(in[i]->field[2].low, in[i]->field[2].high);
        dstpf = extend_prefix(in[i]->field[3].low, in[i]->field[3].high);
        if(check_cmpl(srcpf) == false || check_cmpl(dstpf) == false) {
            cout<<in[i]->priority<<" complement prefix error"<<endl;
            getchar();
        }
        numext = srcpf->nvalid * dstpf->nvalid;
        if(srcpf->nvalid > 1 && dstpf->nvalid > 1) {
            numcmpl_vext = srcpf->nvalid * dstpf->ninvalid + srcpf->ninvalid + 1;
            numcmpl_hext = dstpf->nvalid * srcpf->ninvalid + dstpf->ninvalid + 1;
        }
        else{
            numcmpl_vext = srcpf->nvalid * dstpf->ninvalid + srcpf->ninvalid;
            numcmpl_hext = dstpf->nvalid * srcpf->ninvalid + dstpf->ninvalid;
        }
        if(numext <=numcmpl_vext && numext <= numcmpl_hext) {
            for(size_t j = 0; j < srcpf->nvalid; j ++) {
              for(size_t k = 0; k < dstpf->nvalid; k ++) {
                if(numext > 32) {
                    cout<<"The theory may be wrong"<<endl;
                }
                pc_rule extrule;
                extrule.priority = in[i]->priority;
                extrule.field[0].low = in[i]->field[0].low;
                extrule.field[0].high = in[i]->field[0].high;
                extrule.field[1].low = in[i]->field[1].low;
                extrule.field[1].high = in[i]->field[1].high;
                extrule.field[2].low = srcpf->value[j];
                extrule.field[2].high = srcpf->value[j] + (int)pow(2, 16 - srcpf->length[j]) - 1;
                extrule.field[3].low = dstpf->value[k];
                extrule.field[3].high = dstpf->value[k] + (int)pow(2, 16 - dstpf->length[k]) - 1;
                extrule.field[4].low = in[i]->field[4].low;
                extrule.field[4].high = in[i]->field[4].high;
                out.push_back(extrule);
            }
        }
        }
        if(numcmpl_vext < numext && numcmpl_vext <= numcmpl_hext) {
            if(numcmpl_vext > 32) {
                cout<<"The theory may be wrong"<<endl;
            }
            if(srcpf->nvalid > 1 && dstpf->nvalid > 1) {
                pc_rule extrule;
                extrule.priority = in[i]->priority;
                extrule.field[0].low = in[i]->field[0].low;
                extrule.field[0].high = in[i]->field[0].high;
                extrule.field[1].low = in[i]->field[1].low;
                extrule.field[1].high = in[i]->field[1].high;
                extrule.field[2].low = srcpf->fullpf;
                extrule.field[2].high = srcpf->fullpf + (int)pow(2, 16 - srcpf->fpf_len) - 1;
                extrule.field[3].low = dstpf->fullpf;
                extrule.field[3].high = dstpf->fullpf + (int)pow(2, 16 - dstpf->fpf_len) - 1;
                extrule.field[4].low = in[i]->field[4].low;
                extrule.field[4].high = in[i]->field[4].high;
                out.push_back(extrule);
            }
            for(size_t j = 0; j < srcpf->ninvalid; j ++) {
                pc_rule extrule;
                extrule.priority = in[i]->priority;
                extrule.field[0].low = in[i]->field[0].low;
                extrule.field[0].high = in[i]->field[0].high;
                extrule.field[1].low = in[i]->field[1].low;
                extrule.field[1].high = in[i]->field[1].high;
                extrule.field[2].low = srcpf->cmplvalue[j];
                extrule.field[2].high = srcpf->cmplvalue[j] + (int)pow(2, 16-srcpf->cmpllength[j]) - 1;
                //output the fullpf
                extrule.field[3].low = dstpf->fullpf;
                extrule.field[3].high = dstpf->fullpf + (int)pow(2, 16-dstpf->fpf_len) - 1;
                extrule.field[4].low = in[i]->field[4].low;
                extrule.field[4].high = in[i]->field[4].high;
                out.push_back(extrule);
            }
            for(size_t j = 0; j < srcpf->nvalid; j ++) {
              for(size_t k = 0; k < dstpf->ninvalid; k ++) {
                pc_rule extrule;
                extrule.priority = in[i]->priority;
                extrule.field[0].low = in[i]->field[0].low;
                extrule.field[0].high = in[i]->field[0].high;
                extrule.field[1].low = in[i]->field[1].low;
                extrule.field[1].high = in[i]->field[1].high;
                extrule.field[2].low = srcpf->value[j];
                extrule.field[2].high = srcpf->value[j] + (int)pow(2, 16-srcpf->length[j]) - 1;
                extrule.field[3].low = dstpf->cmplvalue[k];
                extrule.field[3].high = dstpf->cmplvalue[k] + (int)pow(2, 16-dstpf->cmpllength[k]) - 1;
                extrule.field[4].low = in[i]->field[4].low;
                extrule.field[4].high = in[i]->field[4].high;
                out.push_back(extrule);
            }
        }
        }
        if(numcmpl_hext < numext && numcmpl_hext < numcmpl_vext) {
            if(numcmpl_hext > 32) {
                cout<<"The theory may be wrong"<<endl;
            }
            if(srcpf->nvalid > 1 && dstpf->nvalid > 1) {
                pc_rule extrule;
                extrule.priority = in[i]->priority;
                extrule.field[0].low = in[i]->field[0].low;
                extrule.field[0].high = in[i]->field[0].high;
                extrule.field[1].low = in[i]->field[1].low;
                extrule.field[1].high = in[i]->field[1].high;
                extrule.field[2].low = srcpf->fullpf;
                extrule.field[2].high = srcpf->fullpf + (int)pow(2, 16 - srcpf->fpf_len) - 1;
                extrule.field[3].low = dstpf->fullpf;
                extrule.field[3].high = dstpf->fullpf + (int)pow(2, 16 - dstpf->fpf_len) - 1;
                extrule.field[4].low = in[i]->field[4].low;
                extrule.field[4].high = in[i]->field[4].high;
                out.push_back(extrule);
            }
            for(size_t k = 0; k < dstpf->ninvalid; k ++) {
                pc_rule extrule;
                extrule.priority = in[i]->priority;
                extrule.field[0].low = in[i]->field[0].low;
                extrule.field[0].high = in[i]->field[0].high;
                extrule.field[1].low = in[i]->field[1].low;
                extrule.field[1].high = in[i]->field[1].high;
                extrule.field[2].low = srcpf->fullpf;
                extrule.field[2].high = srcpf->fullpf + (int)pow(2, 16-srcpf->fpf_len) - 1;
                extrule.field[3].low = dstpf->cmplvalue[k];
                extrule.field[3].high = dstpf->cmplvalue[k] + (int)pow(2, 16 - dstpf->cmpllength[k]) - 1;
                extrule.field[4].low = in[i]->field[4].low;
                extrule.field[4].high = in[i]->field[4].high;
                out.push_back(extrule);
            }
            for(size_t j = 0; j < srcpf->ninvalid; j ++) {
              for(size_t k = 0; k < dstpf->nvalid; k ++) {
                pc_rule extrule;
                extrule.priority = in[i]->priority;
                extrule.field[0].low = in[i]->field[0].low;
                extrule.field[0].high = in[i]->field[0].high;
                extrule.field[1].low = in[i]->field[1].low;
                extrule.field[1].high = in[i]->field[1].high;
                extrule.field[2].low = srcpf->cmplvalue[j];
                extrule.field[2].high = srcpf->cmplvalue[j] + (int)pow(2, 16 - srcpf->cmpllength[j]) - 1;
                extrule.field[3].low = dstpf->value[k];
                extrule.field[3].high = dstpf->value[k] + (int)pow(2, 16 - dstpf->length[k]) - 1;
                extrule.field[4].low = in[i]->field[4].low;
                extrule.field[4].high = in[i]->field[4].high;
                out.push_back(extrule);
            }
        }
        }
    }
}




