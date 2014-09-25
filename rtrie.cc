#include "rtrie.h"


void rt_insert(rnode *n, rg r, pc_rule* index)
{
    if(r.high >= n->b.high && r.low <= n->b.low) {
        n->rlist.push_back(index);
        return;
    }

    uint32_t m = (n->b.high -  n->b.low + 1ULL)/2 + n->b.low - 1;

    if(r.low <= m) {
        if(!n->left) {
            n->left = new rnode(rg(n->b.low, m));
        }

        rt_insert(n->left, r, index);
    }

    if(r.high > m) {
        if(!n->right) {
            n->right = new rnode(rg(m+1, n->b.high)); 
        }
        rt_insert(n->right, r, index);
    }
}

void rt_destory(rnode *n)
{
    if(!n)
        return;

    if(n->right){
        rt_destory(n->right);
        n->right = NULL;
    }

    if(n->left){
        rt_destory(n->left);
        n->left = NULL;
    }

    n->rlist.clear();
    delete n;
}

bool rt_qry_insert(rnode *n, rg r, vector<pc_rule*> &set, pc_rule* index)
{
    vector<pc_rule*> set_right;
    vector<pc_rule*> set_left;
    bool br= true,bl = true;

    //for_each(n->rlist.begin(), n->rlist.end(), 
    //        [&set](int index) {set.push_back(index);} );
    copy(n->rlist.begin(), n->rlist.end(), back_inserter(set));

    if(r.high >= n->b.high && r.low <= n->b.low) {
        //stop
        n->rlist.push_back(index);
        return !set.empty();
    }

    //uint32_t m = (n->b.low + n->b.high)>>1;
    uint32_t m = (n->b.high -  n->b.low + 1ULL)/2 + n->b.low - 1;

    if(r.low <= m) {
        if(!n->left) {
            n->left = new rnode(rg(n->b.low, m));
            rt_insert(n->left, r, index);
            return !set.empty();
        }
        br =  rt_qry_insert(n->left, r, set_left, index);
    }
    if(r.high > m) {
        if(!n->right) {
            n->right = new rnode(rg(m+1, n->b.high));
            rt_insert(n->right, r, index);
            return !set.empty();
        }
        bl = rt_qry_insert(n->right, r, set_right, index);
    }
    //intersection
    int rl = 0;
    if(bl && br) {
        if(!set_right.empty()) {
            sort(set_right.begin(),set_right.end()); 
            rl |= 1;
        }
        if(!set_left.empty()) {
            sort(set_left.begin(),set_left.end()); 
            rl |= 2;
        }

        if(rl == 3) {
            set_intersection(set_right.begin(), set_right.end(),
                    set_left.begin(), set_left.end(),
                    back_inserter(set));
        }
        else if( rl == 1) {
            copy(set_right.begin(), set_right.end(), back_inserter(set));
        }
        else if( rl == 2)  
            copy(set_left.begin(), set_left.end(), back_inserter(set));
    }
    return !set.empty();

}

void rt_query_or(rnode *n, rg r, vector<pc_rule*> &set) 
{
    if(!n){ 
        return;
    }
    vector<pc_rule*> set_left;
    vector<pc_rule*> set_right;
    

    copy(n->rlist.begin(), n->rlist.end(), back_inserter(set));
    uint32_t m = ((uint64_t)n->b.high -  (uint64_t)n->b.low + 1ULL)/2 + n->b.low - 1;

    if(r.low <= m) {
        rt_query_or(n->left, r, set_left);
    }
    if(r.high > m) {
        rt_query_or(n->right, r, set_right);
    }

    if(!set_left.empty() && !set_right.empty()) {
        sort(set_left.begin(), set_left.end());
        sort(set_right.begin(), set_right.end());

        set_union(set_left.begin(), set_left.end(),
                set_right.begin(), set_right.end(),
                back_inserter(set));
    }
    else if(!set_left.empty()) {
        copy(set_left.begin(), set_left.end(), back_inserter(set));
    }
    else if(!set_right.empty()) {
        copy(set_right.begin(), set_right.end(), back_inserter(set));
    }


}

void rt_query_or(rnode *n, rg r, vector<pc_rule*> &set, int l, int h) 
{
    if(!n){ 
        return;
    }
    vector<pc_rule*> set_left;
    vector<pc_rule*> set_right;
    

    copy_if(n->rlist.begin(), n->rlist.end(), back_inserter(set), [&l, &h](pc_rule *r){return r->priority >=l && r->priority < h;});
    uint32_t m = ((uint64_t)n->b.high -  (uint64_t)n->b.low + 1ULL)/2 + n->b.low - 1;

    if(r.low <= m) {
        rt_query_or(n->left, r, set_left, l,h);
    }
    if(r.high > m) {
        rt_query_or(n->right, r, set_right,l,h);
    }

    if(!set_left.empty() && !set_right.empty()) {
        sort(set_left.begin(), set_left.end());
        sort(set_right.begin(), set_right.end());

        set_union(set_left.begin(), set_left.end(),
                set_right.begin(), set_right.end(),
                back_inserter(set));
    }
    else if(!set_left.empty()) {
        copy(set_left.begin(), set_left.end(), back_inserter(set));
    }
    else if(!set_right.empty()) {
        copy(set_right.begin(), set_right.end(), back_inserter(set));
    }


}


//#define TEST
#ifdef TEST

int main()
{
    rnode root(rg(0,15));
    vector<int> set;
    bool ret;

    rt_insert(&root, rg(0,2), 0);
    rt_insert(&root, rg(0,7), 1);
    rt_insert(&root, rg(0,9), 2);

    ret = rt_qry_insert(&root, rg(5,7), set, 3);
    cout<<"ret "<< ret<<endl;;
    for_each(set.begin(), set.end(), 
            [](int a){cout<<a<<" ";});
    cout<<endl;

    set.clear();
    ret = rt_qry_insert(&root, rg(4,7), set, 4);
    cout<<"ret "<< ret<<endl;;
    for_each(set.begin(), set.end(), 
            [](int a){cout<<a<<" ";});
    cout<<endl;

    set.clear();
    ret = rt_qry_insert(&root, rg(9,10), set, 5);
    cout<<"ret "<< ret<<endl;;
    for_each(set.begin(), set.end(), 
            [](int a){cout<<a<<" ";});
    cout<<endl;
    
    set.clear();
    ret = rt_qry_insert(&root, rg(9,15), set, 6);
    cout<<"ret "<< ret<<endl;;
    for_each(set.begin(), set.end(), 
            [](int a){cout<<a<<" ";});
    cout<<endl;

    set.clear();
    ret = rt_qry_insert(&root, rg(0,7), set, 7);
    cout<<"ret "<< ret<<endl;;
    for_each(set.begin(), set.end(), 
            [](int a){cout<<a<<" ";});
    cout<<endl;

}
#endif
