
# Criptografía
## OTP (HackCon 2019)
### Descripción
```
hackerman is so dank that he decided to play around with OTPs.
he did the following:
message1 ^ key = cipher1
message2 ^ key = cipher2

He gives you cipher1 and cipher2 and challenges you to find the concatenation of messages 1 and 2.
Are you dank enough to find this?
Oh and also, 'meme' is so popular that hackerman used the word in both his messages.
cipher1 is '\x05F\x17\x12\x14\x18\x01\x0c\x0b4'
cipher2 is '>\x1f\x00\x14\n\x08\x07Q\n\x0e'
Both without quotes
```
### Solución
Se sabe que el formato del flag es **d4rk{FLAG}c0de** así que podemos obtener los 5 primeros y últimos caracteres de la key:
```
'd4rk{' ^ '\x05F\x17\x12\x14' = key1
'}c0de' ^ '\x08\x07Q\n\x0e' = key2
```


```python
import itertools
def xor(s1, s2):
    if len(s1) < len(s2):
        s1 = itertools.cycle(s1)
    elif len(s1) > len(s2):
        s2 = itertools.cycle(s2)
    return ''.join(chr(ord(a) ^ ord(b)) for a, b in zip(s1, s2))

c1 = '\x05F\x17\x12\x14\x18\x01\x0c\x0b4'
c2 = '>\x1f\x00\x14\n\x08\x07Q\n\x0e'
c = c1 + c2
k1 = xor(c[:5], 'd4rk{')
k2 = xor(c[-5:], '}c0de')
k1, k2
```




    ('areyo', 'udank')



```
'd4rk{' ^ '\x05F\x17\x12\x14' = 'areyo'
'}c0de' ^ '\x08\x07Q\n\x0e' = 'udank'
key = 'areyoudank'
```
Obtenemos **areyoudank**, vamos a probar esta clave:


```python
key = k1 + k2
print("Flag: {}".format(xor(c, key)))
```

    Flag: d4rk{meme__meme}c0de


## Noki (HackCon 2019)
### Descripción
```
I was told Vigenère Cipher is secure as long as length(key) == length(message). So I did just that!

Break this: g4iu{ocs_oaeiiamqqi_qk_moam!}e0gi
```
### Solución
Se sabe que el formato del flag es **d4rk{FLAG}c0de** así que usando cualquier web para [descifrar Vigenére](http://rumkin.com/tools/cipher/vigenere.php) podemos ver que la clave coincide con el texto descifrado:
> g4iu{ x d4rk{ -> d4rk{

> }e0gi x }c0de -> }c0de

Así que basta con ver en qué casos ocurre este e ir completando la flag.


```python
from string import ascii_lowercase as lowcase
def decrypt(cipher_text, key): # https://www.geeksforgeeks.org/vigenere-cipher/
    orig_text = [] 
    for i in range(len(cipher_text)):
        if cipher_text[i].isalpha():
            x = (ord(cipher_text[i]) - 
                 ord(key[i]) + 26) % 26
            x += ord('A') 
            orig_text.append(chr(x)) 
        else:
            orig_text.append(cipher_text[i])
    return("" . join(orig_text)) 

ciphertext = "g4iu{ocs_oaeiiamqqi_qk_moam!}e0gi"
flag = []
pos = []
for c in ciphertext:
    if c.isalpha():
        for i in lowcase:
            d = decrypt(c, i)
            if d.lower() == i:
                pos.append(i)
        flag.append(pos)
        pos = []
    else:
        flag.append([c, c])
        
f1 = ''.join(i[0] for i in flag)
f2 = ''.join(i[1] for i in flag)
print ("{}\n{}".format(f1, f2))
```

    d4ek{hbj_haceeagiie_if_ghag!}c0de
    q4rx{uow_unprrntvvr_vs_tunt!}p0qr


Utilizando este método obtuve dos alternativas para cada caracter asi que se necesita un poco de "guessing".

**Flag: d4rk{how_uncreative_is_that!}c0de**

## Weird Text (HackCon 2019)
### Descripción
```
Someone sent me this file (mysterious.txt) .It contains only ><+-.,[] symbols and no other letters or numbers.
```
### Solución
Para solucionar este tipo de retos (lenguajes de programación esotéricos) os recomiendo [este post](https://medium.com/@sermmor/lenguajes-de-programaci%C3%B3n-del-infierno-a17b664240d0).

Viendo el enunciado sabemos que se trata del lenguaje **brainfuck**.
> ++++++++++[>+>+++>+++++++>++++++++++<<<< [...]

Para ejeuctar el codigo podemos utilizar: https://www.splitbrain.org/_static/ook/

> D'\`$@"][[ZX{Wx0/S-t1O\`on&m*6jF3ge{SRQ\`_ [...]

Obtenemos otro código de un lenguaje esotérico, en este caso **Malbolge**.
Para ejecutarlo: http://www.malbolge.doleczek.pl/

> 0011 0002 0000 0010 0001 [...]

Obtenemos un hexadecimal que debemos transformar a ascii.


```python
from binascii import unhexlify
unhexlify("0011 0002 0000 0010 0001 000f 0001 0004 0000 000e 000c 000d 000b 0006 000a 0003 0009 0000 0004 0012 0000 000b 0001 0000 00b1 0500 b62b 0400 b24c 0312 4c02 120e 0000 0002 0002 0032 0000 000a 0002 000d 000c 0009 0005 0000 0001 0006 0000 000b 0001 0000 00b1 0100 b72a 0500 0000 0100 0100 1d00 0000 0a00 0100 0900 0800 0000 0200 0000 0000 0700 0600 2000 5629 3b67 6e69 7274 532f 676e 616c 2f61 7661 6a4c 2815 0001 6e6c 746e 6972 7007 0001 6d61 6572 7453 746e 6972 502f 6f69 2f61 7661 6a13 0001 3b6d 6165 7274 5374 6e69 7250 2f6f 692f 6176 616a 4c15 0001 7475 6f03 0001 6d65 7473 7953 2f67 6e61 6c2f 6176 616a 1000 016e 6f69 7470 6563 7845 2f67 6e61 6c2f 6176 616a 1300 0174 6365 6a62 4f2f 676e 616c 2f61 7661 6a10 0001 6e65 675f 6761 6c66 0800 0121 0020 000c 1f00 071e 001d 000c 1c00 0765 6430 637d 7435 3362 5f35 7431 5f74 405f 3362 4062 5f33 6640 635f 6874 3177 5f33 6741 7567 6e41 6c5f 6331 7233 7430 3565 7b6b 7234 6436 0001 0000 0109 0008 000c 6176 616a 2e6e 6567 5f67 616c 660d 0001 656c 6946 6563 7275 6f53 0a00 011b 0007 736e 6f69 7470 6563 7845 0a00 0156 293b 676e 6972 7453 2f67 6e61 6c2f 6176 616a 4c5b 2816 0001 6e69 616d 0400 0165 6c62 6154 7265 626d 754e 656e 694c 0f00 0165 646f 4304 0001 5629 2803 0001 3e74 696e 693c 0600 011a 0007 1900 0718 0017 000a 1600 1500 0914 0008 1300 0812 0007 000a 2200 3700 0000 beba feca ".replace(" ", ""))
```




    b'\x00\x11\x00\x02\x00\x00\x00\x10\x00\x01\x00\x0f\x00\x01\x00\x04\x00\x00\x00\x0e\x00\x0c\x00\r\x00\x0b\x00\x06\x00\n\x00\x03\x00\t\x00\x00\x00\x04\x00\x12\x00\x00\x00\x0b\x00\x01\x00\x00\x00\xb1\x05\x00\xb6+\x04\x00\xb2L\x03\x12L\x02\x12\x0e\x00\x00\x00\x02\x00\x02\x002\x00\x00\x00\n\x00\x02\x00\r\x00\x0c\x00\t\x00\x05\x00\x00\x00\x01\x00\x06\x00\x00\x00\x0b\x00\x01\x00\x00\x00\xb1\x01\x00\xb7*\x05\x00\x00\x00\x01\x00\x01\x00\x1d\x00\x00\x00\n\x00\x01\x00\t\x00\x08\x00\x00\x00\x02\x00\x00\x00\x00\x00\x07\x00\x06\x00 \x00V);gnirtS/gnal/avajL(\x15\x00\x01nltnirp\x07\x00\x01maertStnirP/oi/avaj\x13\x00\x01;maertStnirP/oi/avajL\x15\x00\x01tuo\x03\x00\x01metsyS/gnal/avaj\x10\x00\x01noitpecxE/gnal/avaj\x13\x00\x01tcejbO/gnal/avaj\x10\x00\x01neg_galf\x08\x00\x01!\x00 \x00\x0c\x1f\x00\x07\x1e\x00\x1d\x00\x0c\x1c\x00\x07ed0c}t53b_5t1_t@_3b@b_3f@c_ht1w_3gAugnAl_c1r3t05e{kr4d6\x00\x01\x00\x00\x01\t\x00\x08\x00\x0cavaj.neg_galf\r\x00\x01eliFecruoS\n\x00\x01\x1b\x00\x07snoitpecxE\n\x00\x01V);gnirtS/gnal/avajL[(\x16\x00\x01niam\x04\x00\x01elbaTrebmuNeniL\x0f\x00\x01edoC\x04\x00\x01V)(\x03\x00\x01>tini<\x06\x00\x01\x1a\x00\x07\x19\x00\x07\x18\x00\x17\x00\n\x16\x00\x15\x00\t\x14\x00\x08\x13\x00\x08\x12\x00\x07\x00\n"\x007\x00\x00\x00\xbe\xba\xfe\xca'




```python
print ("Flag: " + "ed0c}t53b_5t1_t@_3b@b_3f@c_ht1w_3gAugnAl_c1r3t05e{kr4d"[::-1])
```

    Flag: d4rk{e50t3r1c_lAnguAg3_w1th_c@f3_b@b3_@t_1t5_b35t}c0de


# Reversing
## babyrev (HackCon 2019)
### Descripción
```
What comes before main , I wonder .... Note: flag format : flag{XXXXXXX}
```
### Solución
Además del enunciado, se nos proporciona un ejecutable de linux llamado **q1.**
```bash
$ file q1          
q1: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=d512b6d2f7f365ed9b284385aedd44db142dd818, not stripped

$ ./q1
Password : AAAAAAAA
Wrong , Password
```
Siguiendo la ejecución del programa con **gdb** vemos que el orden de ejecución de las funciones es: begin, main, end y check. Lo abrimos con algún decompilador como **GHIDRA** o **IDA** para ver qué hacen dichas funciones:
```c
void begin()
{
  byte_201460 = 0x3B;
  byte_201461 = 0x38;
  pass = (__int128)_mm_load_si128((const __m128i *)&xmmword_AE0); // xmmword_AE0 = 272D20263A152970741E70741E023375
  byte_201462 = 0x3C;
}
```
Tras la función **begin()**, la variable **pass** vale **272D20263A152970741E70741E023375 + 3b + 38 + 3c** = **"'- &:\x15)pt\x1ept\x1e\x023u;8<"**
```c
void main(void)
{
  printf("Password : ");
  fflush(stdout);
  read(0, user, 1000);
  return;
}
```
En el **main()** se pide la variable **user** que valdrá para comprobar si hemos introducido la contraseña correcta. Esta comprobación se hace en la función **end()** y **check()**.
```c
void end(void)
{
  [...]
  
  lVar19 = 1;
  result = *ruser ^ pass[0] ^ 0x41 | result;
  do {
    pbVar1 = ruser + lVar19;
    pbVar2 = pass + lVar19;
    lVar3 = lVar19 + 1;
    lVar4 = lVar19 + 1;
    lVar5 = lVar19 + 2;
    lVar6 = lVar19 + 2;
    lVar7 = lVar19 + 3;
    lVar8 = lVar19 + 3;
    lVar9 = lVar19 + 4;
    lVar10 = lVar19 + 4;
    lVar11 = lVar19 + 5;
    lVar12 = lVar19 + 5;
    lVar13 = lVar19 + 6;
    lVar14 = lVar19 + 6;
    lVar15 = lVar19 + 7;
    lVar16 = lVar19 + 7;
    lVar17 = lVar19 + 8;
    lVar18 = lVar19 + 8;
    lVar19 = lVar19 + 9;
    result = result | *pbVar1 ^ *pbVar2 ^ 0x41 | ruser[lVar3] ^ pass[lVar4] ^ 0x41 |
             ruser[lVar5] ^ pass[lVar6] ^ 0x41 | ruser[lVar7] ^ pass[lVar8] ^ 0x41 |
             ruser[lVar9] ^ pass[lVar10] ^ 0x41 | ruser[lVar11] ^ pass[lVar12] ^ 0x41 |
             ruser[lVar13] ^ pass[lVar14] ^ 0x41 | ruser[lVar15] ^ pass[lVar16] ^ 0x41 |
             ruser[lVar17] ^ pass[lVar18] ^ 0x41;
  } while (lVar19 != 0x13);
  return;
}
```
En **end()** se hace un **XOR** a cada caracter de las variable **pass**, **user** y **0x41**. Podemos obtener el valor del **flag** ejecutando **xor(pass, 0x41)**


```python
from binascii import unhexlify, hexlify
passwd = unhexlify("272D20263A152970741E70741E0233753b383c")
flag = ""
for i in passwd:
    flag += chr(i ^ 0x41)
print("Flag: %s" % flag)
```

    Flag: flag{Th15_15_Cr4zy}


## Break It Baby (HackCon 2019)
### Descripción
```
Just break the password and submit in the flag format: d4rk{PASSWORD}c0de
```
### Solución
Además del enunciado, se nos proporciona un ejecutable de linux llamado ctfQues.
```bash
$ file ctfQues       
ctfQues: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 2.6.24, BuildID[sha1]=c9f07b581bd8d97cdc7c0ff1a288e20aea2df0f5, stripped

$ ./ctfQues    
.---------------------------.
Solve this easy. Dare use IDA
'---------------------------'

Password: AAAAAA

Invalid Password!
```
Vamos a hacerle caso y lo abrimos con **IDA**.
Al intentar obtener el **pseudo-C** que genera IDA nos da error **"8048C68: positive sp value has been found"**.
Esto se soluciona modificando el valor del **SP** (**ALT + k**), en este caso debemos poner **-0x08.**
```c
int main(int argc, const char **argv)
{
  unsigned int v3;
  int v5;

  v3 = time(0);
  srand(v3);
  puts(".---------------------------.");
  puts("Solve this easy. Dare use IDA");
  puts("'---------------------------'");
  printf("\nPassword: ");
  scanf("%d", &v5);
  test(v5, 23541344);
  return 0;
}
int test(int a1, int a2)
{
  int result;
  int v3;
  int v4;

  v4 = a2 - a1; // a2 = 23541344
  if (v4 > 0 && v4 < 22){
      result = decrypt(v4);
  } else {
      v3 = rand();
      result = decrypt(v3);
      break;
  }
  return result;
}

int decrypt(char a1)
{
  size_t i; // [esp+10h] [ebp-28h]
  size_t v3; // [esp+14h] [ebp-24h]
  char s[4]; // [esp+1Bh] [ebp-1Dh]
  unsigned int v5; // [esp+2Ch] [ebp-Ch]

  v5 = __readgsdword(0x14u);
  strcpy(s, "Q}|u`sfg~sf{}|a3");
  v3 = strlen(s);
  for ( i = 0; i < v3; ++i )
    s[i] ^= a1;
  if ( !strcmp(s, "Congratulations!") )
    puts("Submit!");
  else
    puts("\nInvalid Password!");
  return __readgsdword(0x14u) ^ v5;
}
```
Lo importarte de este codigo está aqui:
```c
  for ( i = 0; i < v3; ++i )
    s[i] ^= a1;
  if ( !strcmp(s, "Congratulations!") )
```
Sabemos que **a1 = 23541344 - flag**, así que debemos calcular el número a1 tal que 'Q' ^ a1 = 'C', '}' ^ a1 = 'o', ...
Y una vez tengamos ese numero debemos restarselo a 23541344 y así obtendremos el **flag**.


```python
s1 = "Q}|u`sfg~sf{}|a3"
s2 = "Congratulations!"
f = []
a1 = 0
for i in range(len(s1)):
    f.append(ord(s1[i]) ^ ord(s2[i])) # En una lista para comprobar que es el mismo valor para todos los caracteres
print(f)
```

    [18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18, 18]



```python
print("Flag: d4rk{%d}c0de" % (23541344 - 18))
```
```
    Flag: d4rk{23541326}c0de
```
