from pwn import *

HOST = 'rev.chal.csaw.io'
PORT = 5002

def ADD(dst, reg1, reg2):
    cmd = 0 
    dstb = (dst  & 3) << 4
    r1b  = (reg1 & 3) << 6
    r2b  = (reg2 & 3) << 8
    return p16(cmd + dstb + r1b + r2b)

def SUB(dst, reg1, reg2):
    cmd = 1 
    dstb = (dst  & 3) << 4
    r1b  = (reg1 & 3) << 6
    r2b  = (reg2 & 3) << 8
    return p16(cmd + dstb + r1b + r2b)

def INC(reg):
    cmd = 12 + (reg << 4)
    return p16(cmd)

def MOVF(reg, addr):
    cmd = 5
    dst = reg << 4
    return p8(cmd) + p8(addr)

def MOVFS(reg, addr):
    cmd = 13
    dst = reg << 4
    return p8(cmd) + p8(addr)

def STORE(reg, addr):
    """
    MOVT
    """
    cmd = 6
    dst = reg << 4
    return p8(cmd) + p8(addr)

def JGT(dst, reg1, reg2):
    cmd = 9
    r1b = reg1 << 4
    r2b = reg2 << 6
    
    return p8(cmd + r1b + r2b) + p8(dst)

def JEQ(dst, reg1, reg2):
    cmd = 10
    r1b = reg1 << 4
    r2b = reg2 << 6
    
    return p8(cmd + r1b + r2b) + p8(dst)

def JMP(addr):
    cmd = 11
    return p8(cmd) + p8(addr)

def ENT():
    return p16(7)

def EXT():
    return p16(8)

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
    code_ctr = 8
    for i in range(0, 32):
        code_at(ram, code_ctr, MOVFS(2, i))
        code_ctr += 2
        code_at(ram, code_ctr, STORE(2, 255-i))
        code_ctr += 2
    

    # jump to infinite loop and wait for timeout
    code_at(ram, code_ctr, JMP(150))

    bytestrm = " ".join([c.hex() for c in ram])

    with open("ram.hex", "w") as f:
        f.write(bytestrm)


    s.sendlineafter(b'WELCOME', bytestrm)
    s.interactive()

go()

# flag{d0nT_mESs_wiTh_tHe_sChLAmi}