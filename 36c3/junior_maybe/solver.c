#include <stdio.h>
#include <stdlib.h>

int main(int argc, char *argv[]){
    char junior[] = "junior-totally_the_flag_or_maybe_not";
    unsigned char criba[] =
    {
        0,  30,   0,  26,   0,   0,   0,  54,   0,  10, 
        0,  16,   0,  84,   0,   0,   0,   1,   0,  51, 
        0,  23,   0,  28,   0,   0,   0,   9,   0,  20, 
        0,  30,   0,  57,   0,  52,   0,  42,   0,   5, 
        0,   4,   0,   4,   0,   9,   0,  61,   0,   3, 
        0,  23,   0,  60,   0,   5,   0,  62,   0,  20, 
        0,   3,   0,   3,   0,  54,   0,  15,   0,  78, 
        0,  85
    };
    int i = 0;
    for(i=0;i<36;i++){
        junior[i] = junior[35 - i];
    }
    for(i=0;i<36;i++){
        junior[i] ^= criba[i * 2 + 1];
    }
    fprintf(stdout, "Flag: %s\n", junior);
    return 0;
}