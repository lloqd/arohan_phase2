
{
  int iVar1;
  bool bVar2;
  __uid_t _Var3;
  long *plVar4;
  ostream *poVar5;
  long in_FS_OFFSET;
  int local_5d4;
  int local_5d0;
  int i;
  string local_5c8 [32];
  istringstream local_5a8 [384];
  int arr [258];
  long local_20;

  local_20 = *(long *)(in_FS_OFFSET + 0x28);
  local_5d0 = 0;
  std::__cxx11::string::string(local_5c8);
                    /* try { // try from 001024a2 to 001024c4 has its CatchHandler @ 00102698 */
  std::getline<>((istream *)std::cin,local_5c8);
  std::__cxx11::istringstream::istringstream(local_5a8,local_5c8,8);
  while( true ) {
    plVar4 = (long *)std::istream::operator>>((istream *)local_5a8,&local_5d4);
    bVar2 = std::ios::operator.cast.to.bool((ios *)((long)plVar4 + *(long *)(*plVar4 + -0x18)));
    if ((bVar2) && (local_5d0 < 0x100)) {
      bVar2 = true;
    }
    else {
      bVar2 = false;
    }
    if (!bVar2) break;
    if ((local_5d4 < 1) || (3 < local_5d4)) {
                    /* try { // try from 001024f0 to 00102625 has its CatchHandler @ 00102684 */
      poVar5 = std::operator<<((ostream *)std::cout,"Ignoring invalid option: ");
      poVar5 = (ostream *)std::ostream::operator<<(poVar5,local_5d4);
      std::ostream::operator<<(poVar5,std::endl<>);
    }
    else {
      arr[local_5d0] = local_5d4;
      local_5d0 = local_5d0 + 1;
    }
  }
  if ((arr[0] == 2) && (_Var3 = geteuid(), _Var3 != 0)) {
    bVar2 = true;
  }
  else {
    bVar2 = false;
  }
  if (bVar2) {
    poVar5 = std::operator<<((ostream *)std::cout,"Error: Option 2 requires root privileges HAHA");
    std::ostream::operator<<(poVar5,std::endl<>);
  }
  else {
    for (i = 0; i < local_5d0; i = i + 1) {
      iVar1 = arr[i];
      if (iVar1 == 3) {
        login();
      }
      else if (iVar1 < 4) {
        if (iVar1 == 1) {
          sayHello();
        }
        else if (iVar1 == 2) {
          printFlag();
        }
      }
    }
  }
  std::__cxx11::istringstream::~istringstream(local_5a8);
  std::__cxx11::string::~string(local_5c8);
  if (local_20 == *(long *)(in_FS_OFFSET + 0x28)) {
    return;
  }
                    /* WARNING: Subroutine does not return */
  __stack_chk_fail();
}
