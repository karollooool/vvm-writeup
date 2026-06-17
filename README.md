# VVM — Hack The Box Crackme Writeup          

So I sat down with this little ELF called `vvm`, version `v0.0.3` according to its banner, and it turned out to be one of those virtual machine crackmes where the author writes their own tiny bytecode language on top of x86, obfuscates the handlers, and hides the password check inside the bytecode. The whole thing is only about 23 KB. Small, but dense.

Here is how I worked through it, start to finish.

## First impressions

Basic triage. The file is a stripped 64 bit Linux PIE. Running it just prints a banner and asks for a password, which is about the most boring response an executable can give you, so I went straight to IDA.

The `main` function is almost embarrassingly short:

```c
int main() {
    sub_2910();   // banner
    sub_1530();   // VM init
    sub_2870();   // VM dispatch loop
    return 0;
}
```

`sub_2870` is the interesting one. Cleaned up a little, it looks like this:

```c
int *ip = (int *)&unk_5544;
int i   = dword_5540;          // starts at 25
while (i != 28) {
    qword_74E0[i](&dword_5540, &ip, &unk_6220, &unk_6200);
    i = *ip;                    // next opcode lives at ip
    ++ip;                       // step past it
}
```

So we have a classic threaded VM. Opcodes are 4 byte integers. `qword_74E0` is the dispatch table, `unk_6220` is a value stack, `unk_6200` holds the stack pointer, and the initial opcode `25` is stuffed into `dword_5540` so the first instruction can sit right at `0x5540` with its operand at `0x5544`. 

Opcode `28` is the halt marker. The table has 29 slots but slot 28 is never dispatched.

## The dispatch table is built at runtime

`qword_74E0` lives in `.bss`, so a static dump just gives you zeros. The initializer, `sub_1530`, is a hulking thing with a hundred plus local variables and a bunch of SSE shuffling noise, but the pattern is the same for every handler:

1. Read N bytes from some `byte_XXXX` blob in `.data`.
2. XOR each one against a rolling key.
3. `mmap` an executable page.
4. Copy the decoded bytes in.
5. Store the page pointer into a slot of `qword_74E0`.

Four of the 29 handlers are not XOR encoded at all. Those are the ones that talk to libc:

| opcode | function | job |
|---|---|---|
| 3  | `sub_1320` | READ via `getline` |
| 7  | `sub_13E0` | `ptrace(PTRACE_TRACEME)` anti debug |
| 10 | `sub_13A0` | PRINT + free |
| 15 | `sub_12A0` | PACK (convert N qwords into a byte array) |

The rest, 24 handlers, are XOR obfuscated.

## Decoding the handlers

The XOR loop looks, in Hex Rays, roughly like:

```c
v2 = 42;
i  = 555813674;
v201 = 10829;
for (v1 = 1; v1 != N; v1++) {
    out[v1 - 1] = src[v1] ^ v2;
    v2 = *((BYTE *)&i + (v1 % 6));
}
```

The key stream lives in the raw bytes of the integer `i` (4 bytes) concatenated with `v201` (2 bytes). The existing report in the folder had those bytes wrong, which is why my first decode produced garbage. The actual little endian layout is:

```
i     = 0x21210B2A   → 2A 0B 21 21
v201  = 0x2A4D       → 4D 2A
window = [0x2A, 0x0B, 0x21, 0x21, 0x4D, 0x2A]
```

And the effective key stream for output byte `j` is:

```
j = 0 : 0x2A                 (initial v2)
j ≥ 1 : window[j % 6]
```

My sanity check was easy. Every x86 function in the binary begins with `endbr64`, which is `f3 0f 1e fa`. If my decoder produced that as the first four bytes of every handler, I had the right key. It did.

## Reading the handlers

Once decoded, the handlers are tiny. Each one is 20 to 60 bytes, most of them under 40. Here is opcode 5, which is about as typical as they come:

```
endbr64
movsxd  rax, [rcx]              ; rax = sp
shl     rax, 3
mov     rsi, [rdx + rax  8]     ; top value
add     [rdx + rax  16], rsi    ; second from top += top
sub     dword [rcx], 1          ; sp
ret
```

So opcode 5 is ADD. I walked through all 24 encoded handlers and two of the native ones, and worked out the full instruction set:

| op | name | op | name |
|----|------|----|------|
| 0  | STRLEN  | 14 | POP |
| 1  | SHL     | 15 | PACK `imm` (native) |
| 2  | MOD     | 16 | PICK `imm` |
| 3  | READ `imm` (native) | 17 | CALL `target, argc` |
| 4  | DIV     | 18 | INDEX `imm` |
| 5  | ADD     | 19 | EQ |
| 6  | MUL     | 20 | NE |
| 7  | PTRACE (native) | 21 | top = top*8 + 24 |
| 8  | OR (32 bit) | 22 | JNZ `imm` (pop, jump if nonzero) |
| 9  | top = (top + 17) % 3 | 23 | DUP |
| 10 | PRINT (native) | 24 | SUB |
| 11 | JMP `imm` | 25 | PUSH `imm` |
| 12 | top = 6*top   12 | 26 | SHR |
| 13 | STRIP (trim trailing newline) | 27 | JMPB `imm` (jump back) |
| | | 28 | HALT |

A few notes on the quirks that bit me later:

* `PICK imm` pushes `stack[sp  1  imm]`. So `PICK 0` is DUP, `PICK 1` is second from top, and so on.
* `INDEX imm` is `stack[sp 1] = (signed char)top[imm]`. Sign extension from byte. Relevant because any flag byte with bit 7 set would sign extend to `0xFFFF...FF` and wreck the 32 bit packing we are about to see. So the flag must be plain ASCII.
* `JMP` does not advance past its own operand. `JNZ` does. So the two opcodes compute their targets relative to different anchors. This cost me a few minutes of head scratching.
* `CALL target, argc` is the fun one. It saves the return ip, switches to bytecode at `target`, and runs the main dispatch loop recursively until the callee hits `HALT`. Then it takes the top of stack as the return value, writes it back `argc` slots down, and pops `argc` entries. In other words HALT doubles as RET. Classic.

## Disassembling the bytecode

The bytecode runs from `0x5540` to the end of `.data` at `0x61E0`. That is about 800 dwords. I wrote a one page linear disassembler, since every instruction is exactly `1 + nargs` dwords wide, and output looked like this (first few lines):

```
5540 [dw   0]: PUSH   174
5548 [dw   2]: PUSH     2
5550 [dw   4]: DIV
5554 [dw   5]: PUSH    52
...
```

The high level layout jumped out after a skim:

1. **Prologue, dw 0 to ~180.** A long parade of PUSH / ADD / SUB / MUL / DIV / MOD that builds two byte arrays via PACK, prints the banner, and along the way calls PTRACE for anti debug. The arithmetic salad is just obfuscation for the constants `"vvm v0.0.3\n"` and `"What is the password: "`.
2. **READ 32** at dw 150. Reads up to 32 bytes from stdin.
3. **STRIP** shortly after, to kill the trailing newline.
4. **JNZ 97** at dw 181, which unconditionally jumps (the top is the input pointer, which is nonzero) to a forwarding **JMP 22** at dw 280, which lands at dw 303 where the real work starts.
5. **dw 282 to 302: function F1.** This is the callee for all the `CALL 282, 4` invocations further down.
6. **dw 303 to 454: eight F1 calls**, each packing four input bytes into one dword.
7. **JMP 16** at dw 454 to skip over F2.
8. **dw 456 to 470: function F2.**
9. **dw 471 to ~555: eight F2 calls**, rotating each dword by some fixed amount.
10. **dw 555 to 591: eight subtractions** against hard coded constants.
11. **dw 593 to 607: a chain of eight JNZ** that all branch to the same failure block if any difference is nonzero.
12. **Success path**: more PACK and PRINT for the `"Correct!"` string.

So the check is basically, in pseudocode:

```
dN = pack(input[pN0], input[pN1], input[pN2], input[pN3])     for N in 0..7
assert rotl32(dN, sN) == constN                                for N in 0..7
```

## What F1 and F2 actually do

**F1** takes four bytes `a, b, c, d` off the top of the stack and returns `a | b<<8 | c<<16 | d<<24`. Little endian dword packing. I traced it instruction by instruction to make sure the 32 bit OR really was 32 bit and that the sign extended qword inputs would not leak high bits, and yes, every `SHL` and `OR` handler stores back as a zero extended 32 bit value. So as long as the input bytes are plain ASCII, F1 gives you exactly the dword you would expect.

**F2** takes `(x, n)` and returns `rotl32(x, n)`. The whole body is literally `(x << n) | (x >> (32  n))`, composed from five picks, a shift left, a shift right, and an OR. Nothing clever.

## Pulling out the index permutation

Each of the eight F1 call sites has four `INDEX` ops with literal offsets. I walked through the disassembly and pulled them out by hand:

```
d0 ← input[24], input[14], input[27], input[15]
d1 ← input[11], input[7],  input[12], input[4]
d2 ← input[6],  input[9],  input[2],  input[18]
d3 ← input[19], input[13], input[20], input[26]
d4 ← input[28], input[16], input[23], input[8]
d5 ← input[3],  input[30], input[21], input[22]
d6 ← input[25], input[5],  input[10], input[31]
d7 ← input[29], input[1],  input[0],  input[17]
```

All 32 indices `0..31` appear exactly once across the eight groups, which was a nice consistency check. The flag is 32 characters.

The shifts for the eight rotations, read off the F2 call sites:

```
d7 ← shift 15
d6 ← shift 19
d5 ← shift 7
d4 ← shift 18
d3 ← shift 12
d2 ← shift 20
d1 ← shift 14
d0 ← shift 7
```

And the eight constants, read off the `PUSH imm; SUB; JNZ` chain in the order they are checked (which is d7, d6, d5, d4, d3, d2, d1, d0 because of how `PICK 7` walks up as differences accumulate on top):

```
r(d7, 15) == 706975780
r(d6, 19) == 1972114847 (signed)
r(d5, 7)  == 1170424423 (signed)
r(d4, 18) == 574761715  (signed)
r(d3, 12) == 213630203  (signed)
r(d2, 20) == 1193747491
r(d1, 14) == 353885596
r(d0, 7)  == 1237732311 (signed)
```

## Solving it

The whole thing inverts in a dozen lines of Python. For each dword, rotate the expected constant the other way by the same shift, split into four little endian bytes, drop them into the right slots of a 32 byte buffer.

```python
def rotr32(v, n):
    v &= 0xFFFFFFFF
    return ((v >> n) | (v << (32  n))) & 0xFFFFFFFF

targets = {
    7: (15,  706975780),
    6: (19,  1972114847 & 0xFFFFFFFF),
    5: (7,   1170424423 & 0xFFFFFFFF),
    4: (18,   574761715 & 0xFFFFFFFF),
    3: (12,   213630203 & 0xFFFFFFFF),
    2: (20, 1193747491),
    1: (14,  353885596),
    0: (7,  1237732311 & 0xFFFFFFFF),
}

packs = [
    (0, (24, 14, 27, 15)),
    (1, (11,  7, 12,  4)),
    (2, ( 6,  9,  2, 18)),
    (3, (19, 13, 20, 26)),
    (4, (28, 16, 23,  8)),
    (5, ( 3, 30, 21, 22)),
    (6, (25,  5, 10, 31)),
    (7, (29,  1,  0, 17)),
]

flag = bytearray(32)
for k, (shift, c) in targets.items():
    d = rotr32(c, shift)
    for i, idx in enumerate(packs[k][1]):
        flag[idx] = (d >> (8 * i)) & 0xFF

print(flag.decode())
```

Output:

```
HTB{v1rTu4L_p4sSw0rD_t3ChN0loGy}
```

## Verification

I popped the binary into a Docker ubuntu container, piped the candidate flag in, and got back the one word I wanted to see:

```
=======================
vvm v0.0.3
=======================
What is the password: Correct!
```

Done.

## Closing thoughts

A few things I liked about this one:

* The VM is genuinely small. Every handler fits on one screen, no hidden state, no weird globals. It rewards just reading the code.
* The author put the first opcode into the PC variable itself, so the very first dispatch reads `dword_5540` and then operands from `0x5544`. Minor, but a nice way to blur the boundary between "registers" and "bytecode".
* The arithmetic spaghetti at the start of the bytecode is great misdirection. If you try to symbolically execute the whole program you will drown. If you skim for `READ`, `CALL`, `JNZ` you see the real structure in about thirty seconds.
* The check itself is linear in the input. No branching, no key schedule that depends on prior bytes. So once you have the packing permutation and the rotation constants, the inversion is immediate.

Fun little box. On to the next one.
