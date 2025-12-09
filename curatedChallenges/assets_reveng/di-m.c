
/* shinyclean2::main */

void __rustcall shinyclean2::main(void)

{
  char cVar1;
  undefined8 uVar2;
  char *pcVar3;
  undefined1 extraout_DL;
  undefined1 extraout_DL_00;
  ulong uVar4;
  undefined1 auVar5 [16];
  undefined8 local_238;
  undefined8 local_230;
  undefined8 local_228;
  undefined8 local_220;
  undefined8 local_218;
  undefined8 local_210;
  undefined8 local_208;
  undefined8 local_200;
  undefined8 local_1f8;
  undefined8 local_1f0;
  undefined8 local_1e8;
  undefined8 local_1e0;
  undefined8 local_1d8;
  undefined8 local_1d0;
  undefined8 local_1c8;
  undefined8 local_1c0;
  undefined1 local_1b8 [24];
  undefined1 local_1a0 [48];
  undefined8 local_170;
  undefined4 local_168;
  undefined4 uStack_164;
  undefined4 uStack_160;
  undefined4 uStack_15c;
  undefined8 local_158;
  undefined8 local_150;
  undefined8 local_148;
  undefined8 local_140;
  undefined8 local_138;
  undefined1 local_130 [16];
  byte local_11a;
  undefined1 local_119;
  undefined1 local_118 [16];
  undefined4 local_108;
  undefined4 uStack_104;
  undefined4 uStack_100;
  undefined4 uStack_fc;
  undefined8 local_f8;
  undefined1 local_e8 [29];
  byte local_cb;
  undefined1 local_ca;
  byte local_c9;
  undefined1 local_c8 [16];
  undefined1 local_b8 [16];
  char local_a5 [69];
  undefined1 local_60 [53];
  undefined1 local_2b;
  undefined1 local_2a;
  undefined1 local_29;
  undefined1 local_11;
  ulong local_10;
  undefined1 local_1;
  
  local_29 = 0;
  local_2a = 0;
  local_2b = 0;
  std::sync::mpsc::channel(&local_218);
  local_238 = local_218;
  local_230 = local_210;
  local_29 = 1;
  local_228 = local_208;
  local_220 = local_200;
                    /* try { // try from 0010d4a4 to 0010d4b0 has its CatchHandler @ 0010d4c6 */
  std::sync::mpsc::channel(&local_1d8);
  local_2a = 1;
  local_1f8 = local_1d8;
  local_1f0 = local_1d0;
  local_1e8 = local_1c8;
  local_1e0 = local_1c0;
                    /* try { // try from 0010d524 to 0010d530 has its CatchHandler @ 0010d545 */
  alloc::string::String::new(local_1b8);
                    /* try { // try from 0010d55b to 0010d56e has its CatchHandler @ 0010d580 */
  core::fmt::Arguments::new_const(local_1a0,&PTR_DAT_00175ae8);
                    /* try { // try from 0010d596 to 0010d685 has its CatchHandler @ 0010d580 */
  std::io::stdio::_print(local_1a0);
  local_170 = std::io::stdio::stdin();
  auVar5 = std::io::stdio::Stdin::read_line(&local_170,local_1b8);
  core::result::Result<T,E>::expect(auVar5._0_8_,auVar5._8_8_,&DAT_001613c7,0x13,&PTR_DAT_00175af8);
  local_29 = 0;
  local_2a = 0;
  local_150 = local_228;
  local_148 = local_220;
  local_140 = local_1f8;
  local_138 = local_1f0;
  std::thread::spawn(&local_168,&local_150);
  local_2b = 1;
                    /* try { // try from 0010d690 to 0010d821 has its CatchHandler @ 0010d6c2 */
  auVar5 = _<>::deref(local_1b8);
  auVar5 = core::str::_<impl_str>::bytes(auVar5._0_8_,auVar5._8_8_);
  local_130 = _<>::into_iter(auVar5._0_8_,auVar5._8_8_);
  while( true ) {
    local_11a = _<>::next(local_130);
    local_11a = local_11a & 1;
    local_119 = extraout_DL;
    if (local_11a == 0) break;
    local_1 = extraout_DL;
    std::sync::mpsc::Sender<T>::send(&local_238);
  }
  std::sync::mpsc::Sender<T>::send(&local_238,0);
  local_2b = 0;
  local_f8 = local_158;
  local_108 = local_168;
  uStack_104 = uStack_164;
  uStack_100 = uStack_160;
  uStack_fc = uStack_15c;
  local_118 = std::thread::JoinHandle<T>::join(&local_108);
  core::ptr::drop_in_place<>(local_118);
  alloc::vec::Vec<T>::new(local_e8);
  while( true ) {
                    /* try { // try from 0010d826 to 0010d832 has its CatchHandler @ 0010d84f */
    local_cb = std::sync::mpsc::Receiver<T>::recv(&local_1e8);
    local_cb = local_cb & 1;
    local_ca = extraout_DL_00;
    if (local_cb != 0) break;
                    /* try { // try from 0010d8a2 to 0010da64 has its CatchHandler @ 0010d84f */
    local_11 = extraout_DL_00;
    alloc::vec::Vec<T,A>::push(local_e8);
  }
  local_c9 = 1;
  uVar2 = alloc::vec::Vec<T,A>::len(local_e8);
  local_c8 = _<>::into_iter(0,uVar2);
  do {
    auVar5 = core::iter::range::_<>::next(local_c8);
    uVar4 = auVar5._8_8_;
    if (auVar5._0_8_ == 0) goto LAB_0010d944;
    local_10 = uVar4;
    if (0x15 < uVar4) {
      local_c9 = 0;
      goto LAB_0010d944;
    }
    local_a5[0] = -0x16;
    local_a5[1] = -0x27;
    local_a5[2] = '1';
    local_a5[3] = '\"';
    local_a5[4] = -0x2d;
    local_a5[5] = -0x1a;
    local_a5[6] = -0x69;
    local_a5[7] = 'p';
    local_a5[8] = '\x16';
    local_a5[9] = -0x5e;
    local_a5[10] = -0x58;
    local_a5[0xb] = '\x1b';
    local_a5[0xc] = 'a';
    local_a5[0xd] = -4;
    local_a5[0xe] = 'v';
    local_a5[0xf] = 'h';
    local_a5[0x10] = '{';
    local_a5[0x11] = -0x55;
    local_a5[0x12] = -0x48;
    local_a5[0x13] = '\'';
    local_a5[0x14] = 0x96;
    local_b8 = auVar5;
    if (0x14 < uVar4) {
                    /* WARNING: Subroutine does not return */
      core::panicking::panic_bounds_check(uVar4,0x15,&PTR_DAT_00175b10);
    }
    cVar1 = local_a5[uVar4];
    pcVar3 = (char *)_<>::index(local_e8,uVar4,&PTR_DAT_00175b28);
  } while (cVar1 == *pcVar3);
  local_c9 = 0;
  auVar5 = local_b8;
LAB_0010d944:
  local_b8 = auVar5;
  if ((local_c9 & 1) == 0) {
    core::fmt::Arguments::new_const(local_60,&PTR_s_Loser!_Try_again?_00175b40);
    std::io::stdio::_print(local_60);
  }
  else {
    core::fmt::Arguments::new_const
              (local_a5 + 0x15,&PTR_s_You_win!_May_you_be_Rust_clean_f_00175b50);
                    /* try { // try from 0010da78 to 0010da88 has its CatchHandler @ 0010d84f */
    std::io::stdio::_print(local_a5 + 0x15);
  }
                    /* try { // try from 0010da69 to 0010da75 has its CatchHandler @ 0010d6c2 */
  core::ptr::drop_in_place<>(local_e8);
  local_2b = 0;
                    /* try { // try from 0010da95 to 0010daa1 has its CatchHandler @ 0010d545 */
  core::ptr::drop_in_place<>(local_1b8);
                    /* try { // try from 0010daa4 to 0010dab0 has its CatchHandler @ 0010dac2 */
  core::ptr::drop_in_place<>(&local_1e8);
  local_2a = 0;
  local_29 = 0;
  core::ptr::drop_in_place<>(&local_238);
  return;
}

