CPP = g++
CFLGA =  -g -Wall -Wsign-compare -Wformat -std=c++0x 
LFLGA = -lm

SRC=cps-tss.cc rulesutils.cc rtrie.cc 
OBJ=$(SRC:.cc=.o)


%.o: %.cc
	${CPP} ${CFLGA} -c $^ -o $@ 

dt-tss: ${OBJ}
	${CPP} ${LFLGA} ${CFLGA} -o cps-tss ${OBJ} 

all: cps-tss 

clean: 
	rm -f *.o
	rm -f cps-tss 
