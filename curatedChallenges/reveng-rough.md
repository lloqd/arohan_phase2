# 1. worthy.knight
## Solution:
1) the input must be exactly 10 characters
2) the input is parsed as 5 pairs of 2 characters each which must satisfy:
  - both must be alphabetic
  - both must be of different cases
3) each pair also has specific conditions to satisfy:
  1) (0,1) -> char1 ^ char0 == 0x24 and char1 = 0x6a (j)
  2) (2,3) -> char2 ^ char3 == 0x38 and char3 = 0x53 (S)
  3) (4,5) -> bytes swapped then MD5 hashed -> hash must equal given hash
  4) (6,7) -> char6 ^ char7 == 0x38 and char7 = 0x61 (a)
  5) (8,9) -> char9 ^ char8 == 0x20 and char9 = 0x69 (i)
4) we brute force pair 3 with a script + we perform all the XOR's and get the flag
***
# 2. time
## Solution:
1) read decomp -> srand() is current time
2) make one C script to srand with time -> pipe it into the binary
3) ez
***
# 3. VerdisQuo
## Solution:
1) opening the app, we see "Too Slow!" -> located in `MainActivity.java` in 
2) same file, `util.cleanUp()` is called -> `Utilities.java` has `cleanUp()` -> ts has `R.id.flagPart...`
3) we find ts in `R.java` + `activity_main.xml` in `res/layout` has them mapped to their characters with the margins with which they appear on screen
4) we somehow need to render ts
5) flag: `byuctf{android_piece_0f_c4ke}`
***
# 4. Dusty
This challenge contains 3 binaries, `dust_noob`, `dust_intermediate`, and `dust_pro`. Going in order:
# Dusty
