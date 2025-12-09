
/* shinyclean2::a */

void __rustcall
shinyclean2::a(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4)

{
  code *pcVar1;
  byte bVar2;
  int iVar3;
  ulong uVar4;
  char extraout_DL;
  undefined1 extraout_DL_00;
  undefined8 local_148;
  undefined8 local_140;
  undefined8 local_138;
  undefined8 local_130;
  byte local_121;
  int local_120;
  byte local_11c;
  char local_11b;
  byte local_11a;
  undefined1 local_119;
  undefined1 local_118 [279];
  char local_1;
  
  local_121 = 0x75;
  local_120 = 0;
  local_148 = param_1;
  local_140 = param_2;
  local_138 = param_3;
  local_130 = param_4;
  do {
                    /* try { // try from 0010d268 to 0010d271 has its CatchHandler @ 0010d28b */
    local_11c = std::sync::mpsc::Receiver<T>::recv(&local_148);
    local_11c = local_11c & 1;
    local_11b = extraout_DL;
    if (local_11c != 0) {
LAB_0010d2d8:
                    /* try { // try from 0010d2d8 to 0010d2f0 has its CatchHandler @ 0010d3d8 */
      core::ptr::drop_in_place<>(&local_138);
      core::ptr::drop_in_place<>(&local_148);
      return;
    }
    bVar2 = local_11a;
    local_1 = extraout_DL;
    if (extraout_DL == '\0') break;
                    /* try { // try from 0010d2f6 to 0010d306 has its CatchHandler @ 0010d28b */
    _<>::add_assign(&local_121,extraout_DL);
    memcpy(local_118,&DAT_00161298,0x100);
    uVar4 = (ulong)local_121;
    if (0xff < uVar4) {
                    /* WARNING: Subroutine does not return */
      core::panicking::panic_bounds_check(uVar4,0x100,&PTR_DAT_00175ab8);
    }
                    /* try { // try from 0010d33b to 0010d3c9 has its CatchHandler @ 0010d28b */
    local_11a = std::sync::mpsc::Sender<T>::send(&local_138,local_118[uVar4]);
    local_11a = local_11a & 1;
    local_119 = extraout_DL_00;
    if (local_11a != 0) goto LAB_0010d2d8;
    iVar3 = local_120 + 1;
    if (SCARRY4(local_120,1)) {
      core::panicking::panic_const::panic_const_add_overflow(&PTR_DAT_00175ad0);
                    /* WARNING: Does not return */
      pcVar1 = (code *)invalidInstructionException();
      (*pcVar1)();
    }
    local_120 = iVar3;
    bVar2 = 0;
  } while (iVar3 != 0x15);
  local_11a = bVar2;
  core::ptr::drop_in_place<>(&local_138);
  core::ptr::drop_in_place<>(&local_148);
  return;
}

