undefined4 FUN_001010d0(void){
  byte bVar1;
  ushort uVar2;
  ushort uVar3;
  int iVar4;
  char *pcVar5;
  size_t sVar6;
  ushort **ppuVar7;
  byte *pbVar8;
  undefined4 uVar9;
  char *pcVar10;
  long in_FS_OFFSET;
  ushort local_10c;
  undefined1 local_10a;
  byte local_108 [16];
  char local_f8 [32];
  char local_d8 [16];
  undefined1 local_c8 [16];
  undefined1 local_b8 [16];
  undefined1 local_a8 [16];
  undefined1 local_98 [16];
  undefined1 local_88 [16];
  undefined1 local_78 [16];
  undefined1 local_68 [16];
  undefined1 local_58 [16];
  long local_40;

  local_40 = *(long *)(in_FS_OFFSET + 0x28);
  puts(
      "                       (Knight\'s Adventure)                \n\n         O                                              \n        <M>            .---.                            \n        /W\\           ( -.- )--------.                  \n   ^    \\|/            \\_o_/         )    ^             \n  /|\\    |     *      ~~~~~~~       /    /|\\            \n  / \\   / \\  /|\\                    /    / \\            \n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\nWelcome, traveler. A mighty dragon blocks the gate.\nSpeak the secret incantation (10 runic letters) to continue.\n"
      );
  local_c8 = (undefined1  [16])0x0;
  local_b8 = (undefined1  [16])0x0;
  local_a8 = (undefined1  [16])0x0;
  local_98 = (undefined1  [16])0x0;
  local_88 = (undefined1  [16])0x0;
  local_78 = (undefined1  [16])0x0;
  local_68 = (undefined1  [16])0x0;
  local_58 = (undefined1  [16])0x0;
  printf("Enter your incantation: ");
  pcVar5 = fgets(local_c8,0x80,stdin);
  if (pcVar5 == (char *)0x0) {
    puts("\nSomething went awry. Fare thee well...");
  }
  else {
    sVar6 = strcspn(local_c8,"\n");
    local_c8[sVar6] = 0;
    sVar6 = strlen(local_c8);
    if (sVar6 == 10) {
      ppuVar7 = __ctype_b_loc();
      pbVar8 = local_c8;
      do {
        uVar2 = (*ppuVar7)[*pbVar8];
        if (((uVar2 & 0x400) == 0) || (uVar3 = (*ppuVar7)[pbVar8[1]], (uVar3 & 0x400) == 0)) {
          puts("\nThe runes fail to align. The incantation is impure.");
          puts(&DAT_001022b8);
          goto LAB_0010124c;
        }
        if ((((uVar2 & 0x100) != 0) && ((uVar3 & 0x100) != 0)) ||
           (((uVar2 & 0x200) != 0 && ((uVar3 & 0x200) != 0)))) {
          puts("\nThe ancient seals do not resonate with your runes.");
          puts(&DAT_001022b8);
          goto LAB_0010124c;
        }
        pbVar8 = pbVar8 + 2;
      } while (pbVar8 != local_c8 + 10);
      if ((byte)(local_c8[1] ^ local_c8[0]) == 0x24) {
        if (local_c8[1] == 0x6a) {
          if ((local_c8[2] ^ local_c8[3]) == 0x38) {
            if (local_c8[3] == 0x53) {
              local_10a = 0;
              pbVar8 = local_108;
              local_10c = local_c8._4_2_ << 8 | (ushort)local_c8._4_2_ >> 8;
              sVar6 = strlen((char *)&local_10c);
              MD5((uchar *)&local_10c,sVar6,pbVar8);
              pcVar5 = local_f8;
              do {
                bVar1 = *pbVar8;
                pcVar10 = pcVar5 + 2;
                pbVar8 = pbVar8 + 1;
                sprintf(pcVar5,"%02x",(ulong)bVar1);
                pcVar5 = pcVar10;
              } while (local_d8 != pcVar10);
              local_d8[0] = '\0';
              iVar4 = strcmp(local_f8,"33a3192ba92b5a4803c9a9ed70ea5a9c");
              if (iVar4 == 0) {
                if ((local_c8[6] ^ local_c8[7]) == 0x38) {
                  if (local_c8[7] == 0x61) {
                    if ((byte)(local_c8[9] ^ local_c8[8]) == 0x20) {
                      if (local_c8[9] == 0x69) {
                        printf("\n%s\n",
                               "   The kingdom\'s gates open, revealing the hidden realm...    \n                         ( (                                 \n                          \\ \\                                \n                     .--.  ) ) .--.                         \n                    (    )/_/ (    )                        \n                     \'--\'      \'--\'                         \n    \"Huzzah! Thy incantation is true. Onward, brave knight!\" \n"
                              );
                        printf("The final scroll reveals your reward: KCTF{%s}\n\n",local_c8);
                        uVar9 = 0;
                        goto LAB_00101251;
                      }
                      puts("\nThe wards reject your Pair 5 second char.");
                      puts(&DAT_001022b8);
                    }
                    else {
                      puts("\nThe wards reject your Pair 5.");
                      puts(&DAT_001022b8);
                    }
                  }
                  else {
                    puts("\nThe wards reject your Pair 4 second char.");
                    puts(&DAT_001022b8);
                  }
                }
                else {
                  puts("\nThe wards reject your Pair 4.");
                  puts(&DAT_001022b8);
                }
              }
              else {
                puts("\nThe dragon\'s eyes glow red... The final seal remains locked.");
                puts(&DAT_001022b8);
              }
            }
            else {
              puts("\nThe wards reject your Pair 2 second char.");
              puts(&DAT_001022b8);
            }
          }
          else {
            puts("\nThe wards reject your Pair 2.");
            puts(&DAT_001022b8);
          }
        }
        else {
          puts("\nThe wards reject your Pair 1 second char.");
          puts(&DAT_001022b8);
        }
      }
      else {
        puts("\nThe wards reject your Pair 1.");
        puts(&DAT_001022b8);
      }
    }
    else {
      puts("\nScribe\'s note: The incantation must be exactly 10 runic symbols.");
      puts(&DAT_001022b8);
    }
  }
LAB_0010124c:
  uVar9 = 1;
LAB_00101251:
  if (local_40 == *(long *)(in_FS_OFFSET + 0x28)) {
    return uVar9;
  }
                    // WARNING: Subroutine does not return
  __stack_chk_fail();
}
