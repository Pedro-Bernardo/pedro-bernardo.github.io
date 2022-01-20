---
title: Heap Basics Lecture (v2)
categories: [Lectures]
tags: [pwn, heap]
date: 2021-01-19
---

Second rendition of the *Glibc's Heap basics and how to exploit it* lecture.

We covered the following topics:
- Chunks and chunk implementation
- Coalescing
- Main arena and Bins
- Tcache
- Common attacks
- Exploit development walktgrough


## Demo

We solved *gradebook* from the [K3RN3L CTF 2021](https://ctf.k3rn3l4rmy.com/Challenges) via a Tcache Poison attack (unintended solution). This solution walks through obtaining libc leaks and how to forge heap layouts favorable for using the Tcache Poison technique and obtain code execution. 

Binary: https://ctf.k3rn3l4rmy.com/kernelctf-distribution-challs/gradebook/gradebook
Libc: https://ctf.k3rn3l4rmy.com/kernelctf-distribution-challs/gradebook/libc.so.6

### Solution Summary
1. Allocate a large chunk (0x1000 bytes) 
2. Allocate a padding chunk so the previous large chunk isn't merged with the wilderness
3. Leak backwards pointer through the binary's `list` functionality
4. Create students and names of different sizes to lign up a Tcache entry immediately after our large chunk
5. Use the overflow bug in the binary to poison the tcache
6. Allocate a chunk in the `__free_hook` and assign it to `system`
7. Free a chunk containing the string `/bin/sh\x00`
8. Win

Exploit script: [exploit.py]({{ "/assets/code/hap_basics/exploit-reference.py" | relative_url }})

## References

- Malloc security checks - https://heap-exploitation.dhavalkapil.com/diving_into_glibc_heap/security_checks
- Malloc internals - https://www.sourceware.org/glibc/wiki/MallocInternals
- How2heap - https://github.com/shellphish/how2heap
- Glibc source code - https://elixir.bootlin.com/glibc/latest/source
- Temple of PWN - https://www.youtube.com/playlist?list=PLiCcguURxSpbD9M0ha-Mvs-vLYt-VKlWt
- LiveOverflow - https://www.youtube.com/playlist?list=PLhixgUqwRTjxglIswKp9mpkfPNfHkzyeN
- GEF gdb extension - https://github.com/hugsy/gef


Lecture Slides: [Heap_Basics.pdf]({{ "/assets/pdf/PWN_Heap_Basics2.pdf" | relative_url }})
