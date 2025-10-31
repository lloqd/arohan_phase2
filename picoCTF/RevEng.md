# 1: GDB baby step 1
> Can you figure out what is in the eax register at the end of the main function? Put your answer in the picoCTF flag format: picoCTF{n} where n is the contents of the eax register in the decimal number base. If the answer was 0x11 your flag would be picoCTF{17}. Disassemble [this](assets_reveng/debugger0_a).
## Solution:

![alt text](assets_reveng/gdbterm.png)

- We are told to look in the `eax` register at the end of the `main` function, and the challenge's name also points towards using `gdb`, so we give the user executable permissions for the file using `chmod +x` and open it in `gdb`.
- Next, we get a dump of all the functions present in the executable using `info functions` and disassemble the `main` function with `disas main`.
- Looking in the disassembly, we can see that `0x86342` was moved into the `eax` register near the end of `main`, which we convert to decimal and get the flag.

## Flag:
`picoCTF{549698}`

## Notes:
- Pretty straightforward challenge, only hitch came while learning `gdb` syntax.
### Resources:
- https://gist.github.com/jarun/ea47cc31f1b482d5586138472139d090
***
# 2: Vault Door 3
