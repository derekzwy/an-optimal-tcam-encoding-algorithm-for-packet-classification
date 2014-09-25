#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <list>
#include <map>
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
#include <unistd.h>
#include <array>
#include <queue>
#include <set>


using namespace std;

#include "rulesutils.h"
#include "rtrie.h"
#include "cps-tss.h"

FILE *fpr;

void parseargs(int argc, char *argv[]) {
    int	c;
    while ((c = getopt(argc, argv, "r:")) != -1) {
        switch (c) {
            case 'r':
                fpr = fopen(optarg, "r");
                break;
            default:
                break;
        }
    }

    
    if(fpr == NULL){
        printf("can't open ruleset file\n");
        exit(-1);
    }

}

vector<pc_rule*> remove_redund_pkg(vector<pc_rule> &pc, vector<pc_rule> &pc_prefix) 
{
    rule_boundary rb;
    init_boundary(rb);
    
    //pc_prefix = pc;
    
    vector<pc_rule*> pcr;
    for_each(pc.begin(), pc.end(), [&pcr](pc_rule &r){pcr.push_back(&r);});
    cout<<"Orignal ruleset "<<pc.size()<<endl;

    remove_redund_rt(pcr, rb, false);
    extend_rules(pcr, pc_prefix);
    
    cout<<"After prefix explanation: "<< pc_prefix.size()<<endl;

    vector<pc_rule*> pc_pprefix;
    for_each(pc_prefix.begin(), pc_prefix.end(), [&pc_pprefix](pc_rule &r){pc_pprefix.push_back(&r);});

    return move(pc_pprefix);
}

void tuples_num(vector<pc_rule*> &pc) 
{ 
    array<int, MAXDIMENSIONS> tuple;
    map<array<int, MAXDIMENSIONS>, int> tuple_map;


    for(auto rule = pc.begin(); rule != pc.end(); rule++) {
        for(int i = 0; i< MAXDIMENSIONS; i++) {
            int prefixlen;
            if(i == 0 || i == 1) 
                prefixlen = 32 - __builtin_popcount((*rule)->field[i].high - (*rule)->field[i].low);
            if(i == 2 || i == 3)
                prefixlen = 16 - __builtin_popcount((*rule)->field[i].high - (*rule)->field[i].low);
            if( i == 4) 
                prefixlen = 8 - __builtin_popcount((*rule)->field[i].high - (*rule)->field[i].low);
            tuple[i] = prefixlen;
        }

        tuple_map[tuple] ++;
    }

    cout <<"tuple numbers: "<< tuple_map.size()<< endl;

    /*for(auto tuple_pair = tuple_map.begin(); tuple_pair != tuple_map.end(); tuple_pair ++) {
        for_each(tuple_pair->first.begin(), tuple_pair->first.end(), [](int i ){cout<<i<<" ";});
        cout<< "  " << tuple_pair->second<<endl;
    }*/
}

#define MAX_BITS 32

array<char, MAX_BITS> bitstring_from_rule(pc_rule *rule) 
{
    array<char, MAX_BITS> bitstring;
    int pos = 0;
    for(int i = 2; i < 4; i++) {
        int prefixlen;
        if(i == 0 || i == 1) 
            prefixlen = 32 - __builtin_popcount(rule->field[i].high - rule->field[i].low);
        if(i == 2 || i == 3)
            prefixlen = 16 - __builtin_popcount(rule->field[i].high - rule->field[i].low);
        if( i == 4) 
            prefixlen = 8 - __builtin_popcount(rule->field[i].high - rule->field[i].low);

        int tail = __builtin_popcount(rule->field[i].high - rule->field[i].low);

        uint32_t bits = rule->field[i].high >> tail;
        for(int j = prefixlen -1; j >= 0; j--) {
            //from high to low bits 
            if(bits & (1ULL<< j)) {
                bitstring[pos + prefixlen-j-1] = '1';
            }
            else {
                bitstring[pos + prefixlen-j-1] = '0';
            }
        }
        for(int j = 0; j< tail; j++) {
            bitstring[j+prefixlen+pos] = '*';
        }

        if(i==0 || i == 1) {
            pos += 32;
        }
        if(i==2 || i == 3) {
            pos += 16;
        }
        if(i==4)
            pos += 8;
    }
    return move(bitstring);
}

void print_bitstring(vector<pc_rule*> &pc) 
{
    array<char, MAX_BITS> bitstring;
    int old_priority;
    for(auto rule = pc.begin(); rule != pc.end(); rule ++) {
        if((*rule)->priority != old_priority) {
            old_priority = (*rule)->priority;
            cout<<endl;
            cout<<(*rule)->priority<<endl;
        }
        bitstring = bitstring_from_rule(*rule);
        for_each(bitstring.begin(), bitstring.begin() + 32, [](char c){cout<<c<<" ";});
        cout<<endl;
    }
}

array<int, MAXDIMENSIONS> get_tuple(array<char, MAX_BITS> &bitstring) 
{
    array<int, MAXDIMENSIONS> field_prefixlen;
    field_prefixlen.fill(0);
    int start_pos[MAXDIMENSIONS] = {0, 32, 64, 80, 96}; 
    int bits[MAXDIMENSIONS] = {32,32,16,16,8};
    for(int i = 0; i < MAXDIMENSIONS; i++) {    
        int spos = start_pos[i];
        for(int j = spos; j < spos + bits[i]; j++) {
            if(bitstring[j] != '*') {
                field_prefixlen[i]++;
            }
        }

    }
    return move(field_prefixlen);
}

int main(int argc, char *argv[])
{

    vector<pc_rule> pc_orig;
    vector<pc_rule> pc_prefix;
    vector<pc_rule*> pc;

    parseargs(argc, argv);
    loadrules(fpr, pc_orig);

    vector<pc_rule*> pc_r = remove_redund_pkg(pc_orig, pc_prefix);
    cout<<"load "<<pc_r.size()<<" rules"<<endl;

    //freopen ("tuple.txt","w",stdout);
    tuples_num(pc_r);
    freopen ("prefix.txt","w",stdout);
    print_bitstring(pc_r);
    fclose(stdout);

    return 0;
}

