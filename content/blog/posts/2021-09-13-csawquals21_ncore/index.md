---
title: ncore 
ctf: "CSAW Quals 2021"
tags: ["csawquals21", "rev", "verilog", "writeup"]
date: 2021-09-13
authors: ["pedro-bernardo"]
description: "Reverse engineer a Verilog VM and bruteforce an authentication key."
---

**Points:** 484 (dynamic)  

**Solves:** 53  

**Description:**  

> We have a very safe core with a very safe enclave

# Problem:
## Server
We are given a `server.py` file that is running on the server that reads user input and stores it in a `ram.hex` file. The server then uses `vvp` (Icarus Verilog vvp runtime engine) to run a compiled `SystemVerilog` file called `nco`.

For debugging, you can install the `iverilog` compiler, which compiles `SystemVerilog` source files to `vvp assembly`, which can then be executed by `vvp`.

You can compile `SystemVerilog` with the following command:
```
iverilog -g2009 -o nco ncore_tb.v
```

The `-g2009` flag informs the compiler of the language generation to support, being `SystemVerilog` supported since `g2009`.

## Verilog VM
We are also given the file `ncore_tb.v` containing the `Verilog` source code.

Reading through the code we can see that it implements a sort of VM that runs commands stored in its ram, which the user provides.

The VM's structures are the following:
``` 
safe_rom - 256 byte array 
ram      - 256 byte array
key      - 32 bit array
emode    - 1 bit
regfile  - array with 4 32-bit entries
```

The startup sequence looks like this:
``` verilog 
initial 
    begin: initial_block
        init_regs();
        emode = 0;
        set_key();
        load_safeROM();
        load_ram();
        
        #1500000;
        // after 1500000 time units, call print_res
        print_res(); 
        $finish;
    end :initial_block
```

- `init_regs` - initializes the 4 registers in `regfile` to 0
- `set_key` - reads 32 bits from `/dev/urandom` and stores it in `key`
- `load_safeROM` - reads the contents of a file called `flag.txt` into `safe_rom`
- `load_ram` - reads the contents of the `ram.hex` file into `ram`. 
- `print_res` - print the last 64 bytes of `ram`

## Instructions
The main loop of the VM is parsing the user-provided `ram` for instructions.

The instructions are 2 bytes long and the opcode is always the first 4 bits.

These instructions can be used:
#### ADD (opcode 0)
```
regfile[DD] = regfile[R1] + regfile[R2]; pc += 2;
idx:     0123456701234567
content: 0000DDR1R2------
``` 

#### INC (opcode 12)
```
regfile[DD] = regfile[DD] + 1 ; pc += 2;
idx:     0123456701234567
content: 1100DD----------
``` 

#### SUB  (opcode 1)
```
regfile[DD] = regfile[R1] - regfile[R2]  ; pc += 2;
idx:     0123456701234567
content: 0000DDR1R2------
``` 

#### MOVF (opcode 5)

``` 
regfile[DD] = ram[RAM_ADDR] ; pc += 2;
idx:     0123456701234567
content: 0101DD--RAM_ADDR
```

#### MOVFS (opcode 13)
- Only in emode
``` 
regfile[DD] = safe_rom[FLAGADDR] ; pc += 2;
idx:     0123456701234567
content: 1101DD--FLAGADDR
```

#### MOVT (opcode 6)

``` 
ram[RAM_ADDR] = regfile[DD][0:7] ; pc += 2;
idx:     0123456701234567
content: 0110DD--RAM_ADDR
```

#### JGT (opcode 9)
```
pc = regfile[r1] > regfile[r2] ? RAM_ADDR : pc+2 
idx:     0123456701234567
content: 1001R1R2RAM_ADDR
```

#### JEQ (opcode 10)
```
pc = regfile[r1] == regfile[r2] ? RAM_ADDR : pc+2
idx:     0123456701234567
content: 1010R1R2RAM_ADDR
```

#### JMP (opcode 11)
```
pc = ram[RAM_ADDR] ; 
idx:     0123456701234567
content: 1011----RAM_ADDR
```

#### ENT (opcode 7)
```
if key[0:13] == regfile[0]:
    emode = 1
    regfile[3] = 0
else:
    regfile[3] = 1

pc += 2;

idx:     0123456701234567
content: 0111------------
```

#### EXT (opcode 8)

```
emode = 0 ; pc += 2

idx:     0123456701234567
content: 1000--------
```

## Extracting the Flag


- We cannot access the `safe_rom` where the flag is stored unless `emode = 1`
- `emode` is set to 1 if regfile[0] contains the first 14 bits of secret key obtained from `/dev/urandom`.


The plan:
1. Brute force the first 14 bits of the key by repeatedly calling `ENT` with regfile[0] = 1..2^14
2. When `regfile[3] == 1` stop the brute force
3. Write the content of `safe_rom` in the last 64 bytes of `ram`
4. Wait for timeout

---
# The Solution

``` python
def code_at(ram, addr, code):
    ram[addr]   = p8(code[0])
    ram[addr+1] = p8(code[1])
    
def go():
    s = remote(HOST, PORT)
    
    ram = [b'\x00' for i in range(256)]

    # create an infinite loop
    code_at(ram, 150, JMP(154))
    code_at(ram, 154, JMP(150))

    # try to enter emode (reg0 == key? reg3 = 1 else reg3 = 0)
    code_at(ram, 0, ENT())
    code_at(ram, 2, JEQ(8, 2, 3))
    code_at(ram, 4, INC(0))
    code_at(ram, 6, JMP(0))

    # hardcode the flag leakage instructions for simplicity
    pc = 8
    for i in range(0, 32):
        code_at(ram, pc, MOVFS(2, i))
        pc += 2
        code_at(ram, pc, STORE(2, 255-i))
        pc += 2
    

    # jump to infinite loop and wait for timeout
    code_at(ram, pc, JMP(150))

    # separate each character by a space
    bytestrm = " ".join([c.hex() for c in ram])


    s.sendlineafter(b'WELCOME', bytestrm)
    s.interactive()

go()
```
Running the script, the server outputs the following:
``` 
ENT
66 6c 61 67 7b 64 30 6e 54 5f 6d 45 53 73 5f 77 69 54 68 5f 74 48 65 5f 73 43 68 4c 41 6d 69 7d 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
```

From which we can decode the flag: `flag{d0nT_mESs_wiTh_tHe_sChLAmi}`

The full solution can be found in [solve.py]({{ "/assets/code/csawquals21/ncore/solve.py" | relative_url }}).

