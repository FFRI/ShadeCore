/*
 * (c) FFRI Security, Inc., 2026 / Author: FFRI Security, Inc.
 */

//
// Check if hypervisor is present and prints message
//
VOID
EFIAPI
CheckHypervisor(
    )
{
  UINT32 Eax, Ebx, Ecx, Edx;
  AsmCpuid(1, &Eax, &Ebx, &Ecx, &Edx);
  BOOLEAN IsHvPresent = (BOOLEAN)((Ecx&BIT31)!=0);
  Print(L"Hypervisor is %s\n", IsHvPresent ? L"present" : L"NOT present");
}


// 
// Just a function to calc checksum
//
UINT8
EFIAPI
CalcChecksum8 (
  IN VOID   *Buffer,
  IN UINTN  Size
  )
{
  UINT8 Sum = 0;
  UINT8 *p  = (UINT8 *)Buffer;
  for (UINTN i = 0; i < Size; ++i) {
    Sum = (UINT8)(Sum + p[i]);
  }
  return (UINT8)(0 - Sum);
}



