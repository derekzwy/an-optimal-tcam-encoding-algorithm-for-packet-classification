#ifndef __RULES_UTIL_H__
#define __RULES_UTIL_H__

#include <string>
#include <list>
#include <map>
#include <iostream>
#include <algorithm>
#include <sstream>
#include <cmath>
#include <vector>
#include "range.h"
//#include "rtrie.h"


#define MAXDIMENSIONS 5


struct rule_boundary
{
    struct range field[MAXDIMENSIONS];
};

struct pc_rule{
  int priority;
  struct range field[MAXDIMENSIONS];
  int siplen, diplen;
  unsigned sip[4], dip[4];
  struct pc_rule *expand;
};


using namespace std;

typedef unsigned int field_type;
void remove_redund(list<pc_rule*> &pr, rule_boundary &rb);
int loadrules(FILE *fp, vector<pc_rule> &classifier);

void load_rule_ptr(vector <pc_rule> &rule_list,list <pc_rule*> &ruleptr_list,int start,int end);

void init_boundary(rule_boundary & rb);
void dump_rules(list<pc_rule*> ruleset, string str);
bool is_equal(pc_rule rule1, pc_rule rule2, rule_boundary boundary);
int linear_search(list<pc_rule*> &p_classifier, field_type *ft);
int load_ft(FILE *fpt, field_type *ft);
range range_in_boundary_1D(range r, range boundary);
int check_rule(pc_rule *r, field_type *ft);
void remove_redund_rt(vector<pc_rule*> &pr, rule_boundary &b, bool large);
bool overlap(pc_rule *r1, pc_rule *r2);
void find_overlap_rules(struct overlap_trees *ots, vector<pc_rule*> &pc, pc_rule * rule, int l, int h, vector<int> &rset);
void init_overlap_trees(struct overlap_trees *ots, rule_boundary &rb, vector<pc_rule*> pc);
void find_overlap_rules_slow(vector<pc_rule*> &pc, pc_rule* rule, int l, int h, vector<int> &set);
void range2prefix(range r, vector<range> &prefixes);
void extend_rules(vector<pc_rule*> &in, vector<pc_rule> &out);
int check_range_size(const range & check, int index);
#endif
