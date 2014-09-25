#ifndef _DT_TSS_H_
#define _DT_TSS_H_

#include<vector>
#include<array>

struct dt_node{
    int pos;
    //std::vector<std::array<char, MAXBITS> > ruleset;
    struct dt_node *left;
    struct dt_node *right;

    dt_node() : pos(-1), left(nullptr), right(nullptr) {

    }
};


#endif
