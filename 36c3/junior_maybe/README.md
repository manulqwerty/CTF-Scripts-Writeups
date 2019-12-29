# Maybe
This is a reverse challenge from CCC CTF (36C3 Junior).
After opening the binary with any disassembler we see a main function that does nothing usefull but printing "wrong".
But if we execute the binary we see something else:
```
$ ./chal1-a27148a64d65f6d6fd062a09468c4003 Argv_1
    wrong!
    aber es ist nur noch eine sache von sekunden!
````
So let's review the other functions and find out how the program works.

## Pseude-C
```c
i = 0;
while (i < 0x24) {
    junior[i] = junior[0x23 - i];
    i = i + 1;
}
while (i < 0x24) {
    junior[i] = junior[i] ^ argv_1[i];
    i = i + 1;
}
flag = true;
j = 0;
while (j < 0x24) {
    if (junior[j] != &xor_const[j * 2 + 1]) {
        flag = false;
    }
    j = j + 1;
}
sleep(10);
puts("aber es ist nur noch eine sache von sekunden!");
if (flag) {
    puts("correct!");
}
```

## Solver
```c
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
```
Execution: 
```
 » gcc solver.c -o solver
 » ./solver
Flag: junior-alles_nur_kuchenblech_mafia!!
```
