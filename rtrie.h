#ifndef RTRIE_H_
#define RTRIE_H_

#include <string>
#include <list>
#include <map>
#include <iostream>
#include <algorithm>
#include <sstream>
#include <cmath>
#include <vector>
#include <stdint.h>
#include "rulesutils.h"

using namespace std;


struct rg{
    uint32_t low;
    uint32_t high;

    rg(uint32_t l, uint32_t h): low(l), high(h) {

    };
    rg() {
        low =0;
        high = 0;
    }
    rg(const rg &a) {
        low = a.low;
        high = a.high;
    }
};


struct rnode{
    rg b;
    vector<pc_rule*> rlist;
    struct rnode *right, *left;

    rnode(rg a) : b(a) {
        right = NULL;
        left = NULL;
    };
    rnode(): b(0,0) { 
        right = NULL;
        left = NULL;
    }

    void setb(const rg &sb) {
        b = sb;
    }
};

struct overlap_trees{
    struct rnode roots[MAXDIMENSIONS]; 
};


bool rt_qry_insert(rnode *n, rg r, vector<pc_rule*> &set, pc_rule* index);
void rt_query_or(rnode *n, rg r, vector<pc_rule*> &set);
void rt_destory(rnode *n);
void rt_insert(rnode *n, rg r, pc_rule* index);
void rt_query_or(rnode *n, rg r, vector<pc_rule*> &set, int l, int h);
#endif
