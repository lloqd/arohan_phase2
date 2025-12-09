
/* shinyclean2::main */

void __rustcall shinyclean2::main(void)

{
  byte bVar1;
  undefined4 uVar2;
  ulong uVar3;
  ulong uVar4;
  undefined1 auVar5 [16];
  undefined *local_1c8;
  undefined8 local_1c0;
  byte local_1b1 [73];
  undefined1 local_168 [24];
  undefined8 local_150;
  undefined4 local_144;
  undefined8 local_140;
  undefined1 local_138 [16];
  undefined1 local_128 [16];
  undefined1 local_118 [24];
  undefined1 local_100 [16];
  undefined1 local_f0 [24];
  undefined1 local_d8 [48];
  undefined8 local_a8;
  undefined4 uStack_a0;
  undefined4 uStack_9c;
  undefined1 *local_98;
  code *pcStack_90;
  undefined1 local_88 [64];
  undefined8 local_48;
  undefined8 local_40;
  undefined4 local_34;
  ulong local_30;
  undefined1 *local_28;
  code *local_20;
  undefined1 *local_18;
  code *local_10;
  undefined1 *local_8;
  
  local_1c8 = &DAT_0015b134;
  local_1c0 = 0x40;
  local_1b1[0] = 0xcf;
  local_1b1[1] = 9;
  local_1b1[2] = 0x1e;
  local_1b1[3] = 0xb3;
  local_1b1[4] = 200;
  local_1b1[5] = 0x3c;
  local_1b1[6] = 0x2f;
  local_1b1[7] = 0xaf;
  local_1b1[8] = 0xbf;
  local_1b1[9] = 0x24;
  local_1b1[10] = 0x25;
  local_1b1[0xb] = 0x8b;
  local_1b1[0xc] = 0xd9;
  local_1b1[0xd] = 0x3d;
  local_1b1[0xe] = 0x5c;
  local_1b1[0xf] = 0xe3;
  local_1b1[0x10] = 0xd4;
  local_1b1[0x11] = 0x26;
  local_1b1[0x12] = 0x59;
  local_1b1[0x13] = 0x8b;
  local_1b1[0x14] = 200;
  local_1b1[0x15] = 0x5c;
  local_1b1[0x16] = 0x3b;
  local_1b1[0x17] = 0xf5;
  local_1b1[0x18] = 0xf6;
  core::fmt::Arguments::new_const(local_1b1 + 0x19,&PTR_DAT_0016e870);
  std::io::stdio::_print(local_1b1 + 0x19);
  alloc::string::String::new(local_168);
                    /* try { // try from 00109728 to 00109730 has its CatchHandler @ 00109751 */
  local_150 = std::io::stdio::stdin();
                    /* try { // try from 00109777 to 0010991f has its CatchHandler @ 00109751 */
  auVar5 = std::io::stdio::Stdin::read_line(&local_150,local_168);
  core::result::Result<T,E>::expect
            (auVar5._0_8_,auVar5._8_8_,"Failed to read line",0x13,&PTR_s_src/main.rs_0016e880);
  auVar5 = _<>::deref(local_168);
  auVar5 = core::str::_<impl_str>::trim(auVar5._0_8_,auVar5._8_8_);
  local_140 = core::str::_<impl_str>::parse(auVar5._0_8_,auVar5._8_8_);
  local_48 = local_140;
  local_40 = local_140;
  uVar2 = core::result::Result<T,E>::expect
                    (local_140,"Invalid int!",0xc,&PTR_s_src/main.rs_0016e898);
  local_144 = core::num::_<impl_u32>::to_ne_bytes(uVar2);
  local_34 = local_144;
  local_138 = _<>::into_iter(0,0x19);
  while( true ) {
    auVar5 = core::iter::range::_<>::next(local_138);
    uVar4 = auVar5._8_8_;
    local_128 = auVar5;
    if (auVar5._0_8_ == 0) {
      sha256::digest(local_118,local_1b1);
                    /* try { // try from 0010993c to 00109950 has its CatchHandler @ 0010996d */
      bVar1 = _<>::eq(local_118,&local_1c8);
      if ((bVar1 & 1) == 0) {
                    /* try { // try from 0010998d to 001099d7 has its CatchHandler @ 0010996d */
        core::fmt::Arguments::new_const(local_88,&PTR_s_Sorry,_better_luck_next_time!_0016e8b0);
        std::io::stdio::_print(local_88);
      }
      else {
        core::str::converts::from_utf8(local_f0,local_1b1,0x19);
                    /* try { // try from 001099f2 to 00109ae8 has its CatchHandler @ 0010996d */
        local_100 = core::result::Result<T,E>::expect
                              (local_f0,"Failed to Parse",0xf,&PTR_s_src/main.rs_0016e8c0);
        local_18 = local_100;
        local_10 = _<>::fmt;
        local_8 = local_100;
        local_98 = local_100;
        local_20 = _<>::fmt;
        pcStack_90 = _<>::fmt;
        uStack_a0 = 0x109e20;
        uStack_9c = 0;
        local_28 = local_98;
        local_a8 = local_98;
        core::fmt::Arguments::new_v1(local_d8,&PTR_s_Congratulations!_You_win_a_0016e8d8,&local_a8);
        std::io::stdio::_print(local_d8);
      }
                    /* try { // try from 001099dc to 001099ec has its CatchHandler @ 00109751 */
      core::ptr::drop_in_place<>(local_118);
      core::ptr::drop_in_place<>(local_168);
      return;
    }
    local_30 = uVar4;
    uVar3 = uVar4 & 3;
    if (3 < uVar3) break;
    if (0x18 < uVar4) {
                    /* WARNING: Subroutine does not return */
      core::panicking::panic_bounds_check(uVar4,0x19,&PTR_s_src/main.rs_0016e910);
    }
    local_1b1[uVar4] = *(byte *)((long)&local_144 + uVar3) ^ local_1b1[uVar4];
  }
                    /* try { // try from 00109b40 to 00109b93 has its CatchHandler @ 00109751 */
                    /* WARNING: Subroutine does not return */
  core::panicking::panic_bounds_check(uVar3,4,&PTR_s_src/main.rs_0016e8f8);
}

