---
title: Heap Basics Lecture 
tags: [pwn, heap]
date: 2022-01-19
description: ""
---

The second rendition of the [Glibc's Heap Basics and How to Exploit it](https://pedro-bernardo.github.io/posts/Heap_Exploitation_Lecture/)* lecture.

We covered the following topics:
- Chunks and chunk implementation
- Coalescing
- Main arena and Bins
- Tcache
- Common attacks
- Exploit development walkthrough


## Demo

We solved *gradebook* from the [K3RN3L CTF 2021](https://ctf.k3rn3l4rmy.com/Challenges) via a Tcache Poison attack (unintended solution). This solution walks through obtaining libc leaks and how to forge heap layouts favorable for using the Tcache Poison technique to obtain code execution. 

Download the binary and libc here: [gradebook](https://ctf.k3rn3l4rmy.com/kernelctf-distribution-challs/gradebook/gradebook), [libc.so.6](https://ctf.k3rn3l4rmy.com/kernelctf-distribution-challs/gradebook/libc.so.6)

### Solution Summary
1. Allocate a large chunk (0x1000 bytes) 
2. Allocate a padding chunk so the previous large chunk isn't merged with the wilderness
3. Free all chunks
4. Allocate a large chunk (will re-use the last large chunk) and overwrite the first 8 bytes only
5. Leak backward pointer through the binary's `list` functionality
6. Create students and names of different sizes to get a Tcache entry immediately after our large chunk
7. Use the overflow bug in the binary to poison the tcache
8. Allocate a chunk in the `__free_hook` and assign it to `system`
9. Free a chunk containing the string `/bin/sh\x00`
10. Win

Exploit script: [exploit.py]({{ "/assets/code/heap_basics/exploit-reference.py" | relative_url }})

## References

- [Malloc security checks](https://heap-exploitation.dhavalkapil.com/diving_into_glibc_heap/security_checks)
- [Malloc internals](https://www.sourceware.org/glibc/wiki/MallocInternals)
- [How2heap](https://github.com/shellphish/how2heap)
- [Glibc source code](https://elixir.bootlin.com/glibc/latest/source)
- [Temple of PWN](https://www.youtube.com/playlist?list=PLiCcguURxSpbD9M0ha-Mvs-vLYt-VKlWt)
- [LiveOverflow](https://www.youtube.com/playlist?list=PLhixgUqwRTjxglIswKp9mpkfPNfHkzyeN)
- [GEF gdb extension](https://github.com/hugsy/gef)

<!-- Lecture Slides: [Heap_Basics.pdf]({{ "/assets/pdf/PWN_Heap_Basics2.pdf" | relative_url }}) -->
[Lecture slides](PWN_Heap_Basics2.pdf)   
