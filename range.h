#ifndef __RANGE_H__
#define __RANGE_H__

struct range{
    unsigned long long low;
    unsigned long long high;


    range(unsigned long l, 
            unsigned long h): low(l),high(h) {
    }
    range() {
        low = 0;
        high = 0;
    }
    
};

#endif

