# Shade Core
Shade Core is a BIOS malware attack technique that bypasses Hypervisor-Based Security (HBS) enforced by arbitrary hypervisors.
This technique bypasses HBS by creating a CPU core that escapes hypervisor control on the target system, without tampering with or hooking any components such as the hypervisor or bootloader.

This work is presented at [CODE BLUE 2026](https://codeblue.jp/en/program/time-table/day2-t1-01-shade-core/), and please refer the slides for explanation of the inner workings.
This repository contains the stripped PoC code of Shade Core for security purpose.
If you require the full source code, please contact us via email (research-feedback@ffri.jp). Once your identity is verified, we will send it to you directly.


## Components
- ShadeCoreDxe (DXE driver): Main DXE module which implements Shade Core
- ShadeCoreLoaderApp (UEFI app): This is for ESP infection. Loads ShadeCoreDxe and executes bootmgfw.efi/grubx64.efi afterwards


## Installation & Build
1. Prepare EDK2
1. Copy ShadeCorePkg to `edk2/`
1. Setup `edk2/Conf/target.txt`
    1. `ACTIVE_PLATFORM = ShadeCorePkg/ShadeCorePkg.dsc`
    1. `TARGET_ARCH = X64`
    1. `TOOL_CHAIN_TAG = GCC5`
        1. VS cannot use inline assembly so only GCC is supported
1. Modify source code for your test environment
    1. Fill `SHADE_CORE_PROCESSOR_ID` and `SHADE_CORE_APIC_ID`
1. `source edksetup.sh` & `build` => ShadeCoreDxe.efi & ShadeCoreLoaderApp.efi is created
1. Run this DXE module (Flash it in SPI flash, include in OROM, infect ESP...)

**Note: When executing ShadeCoreDxe.efi before MAT construction (prior to EndOfDxe), the MAT tampering (`ModifyMAT()`) must be removed from the source code**  
**Note: The sections of ShadeCoreDxe.efi must be aligned on 0x1000-byte boundaries. In addition, the current implementation assumes that only .text and .data sections are present**


## Usage
There are several ways to execute ShadeCore.efi. For research purposes, the following usage using USB stick is recommended.

1. Get [UEFI Shell](https://github.com/pbatard/UEFI-Shell) binary, rename it to `bootx64.efi`, and place it in `EFI/BOOT/bootx64.efi` in USB stick
1. Copy ShadeCoreDxe.efi & ShadeCoreLoaderApp.efi to USB root
1. Create a folder named `EFILOAD/` in USB root because ShadeCoreLoaderApp.efi locates USB partition using this folder name
1. Insert the USB stick into the PC on which you want to execute Shade Core, boot the system, and open the boot options menu
    1. Since the boot key differs depending on the system, please look up the correct boot key for the target machine
1. Selecting the USB stick as the boot target will start the UEFI Shell
    1. Specifically, `/EFI/BOOT/bootx64.efi` on the USB stick is executed, and since a UEFI Shell binary is placed there in this case, the shell is launched
1. In the UEFI Shell, move to the filesystem where ShadeCoreDxe.efi and related files are located, and execute it with `.\ShadeCoreLoaderApp.efi`
    1. You can switch filesystems using commands such as `fs0:\`, and by running `ls` to list the files in the root, you can identify which filesystem corresponds to the USB stick
1. ShadeCoreLoaderApp.efi will load ShadeCoreDxe.efi and executes bootmgfw.efi/grubx64.efi afterwards


Shade Core can be activated in one of the following two ways:

1. By writing a specific value, `WAKEUP_SHADE_CORE_SIGNAL`, to a specific memory address, `gShadeCoreStartupSignalBuffer`, from a runtime DXE driver or a kernel driver
2. By operating autonomously without external triggers, where Shade Core performs malicious behavior on its own—for example, assuming that the OS has booted after 3 minutes post-boot and autonomously read/writing to physical memory

In order to execute the runtime DXE module after OS boot, ShadeCoreDxe.efi hooks the UEFI runtime service `gRT->SetVariable()`, triggering Shade Core–specific tasks only when a write targets the specific variable name `MAGIC_VAR_NAME`.
Writing to the UEFI variable can be done from userland executable (require admin priv) calling such OS apis like [SetFirmwareEnvironmentVariableExA](https://learn.microsoft.com/ja-jp/windows/win32/api/winbase/nf-winbase-setfirmwareenvironmentvariableexa).



## How it works
If you refer to the presentation materials, you can find a detailed explanation of the mechanism.
Here, I will introduce the key events that occur in chronological order to assist you with debugging or reading source code.
Operations executed by Shade Core are prefixed with **[SC]**, while those executed on other cores are left unmarked.
Important legitimate operations affected by the processing of ShadeCoreDxe.efi are marked with **[L]** (for "Legitimate"), although they are not part of the ShadeCoreDxe.efi processing itself.
While Shade Core is not limited to Windows VBS, the following example focuses on the Windows VBS case for clarity.

#### Boot phase
1. DriverEntry
    1. Check mutex to ensure ShadeCoreDxe.efi is executed only once
    1. Create identity map page tables to use in Shade Core
    1. Create SetVirtualAddressMap event which most runtime DXE modules do
    1. Hook `gBS->GetMemoryMap`, `gRT->SetVariable`, `gBS->ExitBootServices`
    1. Initialize ACPI PM Timer (because we want to use a timer equivalent to `gBS->Stall()` also during runtime) 
    1. Initialize communication buffer between VTL0 and Shade Core
    1. **Modify MADT to hide Shade Core from OS loader**
        1. Find MADT table by `AcpiSdtProtocol->GetAcpiTable`
        1. Remove the entry of core with the specified processor ID from MADT
        1. Install the modified MADT table
    1. **Modify MAT to add ShadeCoreDxe.efi memory attribute information (avoiding EPT violation BSOD)**
        1. Get .text and .data section base address and size for ShadeCoreDxe.efi by LoadedImageProtocol
        1. Register .text with the attributes `RUNTIME | RO` and .data with `RUNTIME | XP` in the MAT
            1. Since MAT entries must be sorted in ascending order of `PhysicalStart`, the descriptor encompassing the entire ShadeCoreDxe.efi is divided, and separate descriptors for the .text and .data memory regions are inserted between them
1. ExitBootServices Hook (called by `winload.efi!OslFwpKernelSetupPhase1`)
    1. Prepare a "scan map" that represents the memory regions of non-BIOS components (OS, hypervisors, ...), which Shade Core uses when read/writing physical memory
    1. Create SIPI vector and locate it at physical address `gVector`
    1. Call original ExitBootServices (Most BIOS will reset APs at this point)
    1. **Send INIT-SIPI-SIPI to Shade Core and let it execute the SIPI vector**
        1. [SC] Start executing the SIPI vector (sipi-vector.nasm) in real mode (16-bit)
        1. [SC] Load GDT and transition to protected mode (32-bit)
        1. [SC] Enable paging and transition to long mode (64-bit)
        1. [SC] Jump to SipiEntry function in Processor.h
        1. [SC] Set IDT used in the boot time and run *either of* the followings
            1. [SC] Poll for gShadeCoreStartupSignalBuffer to have `WAKEUP_SHADE_CORE_SIGNAL` as value
            1. [SC] Wait for about 3 minutes until the OS boots up
1. GetMemoryMap Hook (called multiple times by `winload.efi`)
    1. Modify the attributes of EFI memory map entry which includes ShadeCoreDxe.efi to `EFI_MEMORY_RUNTIME`
1. SetVirtualAddressMapEvent (called by `winload.efi`)
    1. Convert global pointers that contains physical addresses to virtual address
        1. gShadeCoreStartupSignalBufferVirAddr (VTL0 GPA) corresponds to gShadeCoreStartupSignalBuffer (HPA)
1. [L] winload!OslFwMapRuntimeRanges
    1. [L] Compare EFI memory map and MAT, and trigger BSOD if the memory type for the same memory region does not match
    1. [L] OR the attributes from both and save the resulting memory map
1. [L] hvix64.exe
    1. [L] Enters VMX operation by VMXON
    1. [L] Runtime DXE modules including ShadeCoreDxe.efi are now mapped to VTL0
    1. [L] Parses the "resulting memory map" created by winload and construct EPT
    1. [L] vmlaunch ntoskrnl.exe in VTL0

#### Runtime phase (No VTL0 cooperation)
1. ntoskrnl.exe executes as usual, but runs with one fewer CPU core
1. [SC] About 3 minutes after ExitBootServices, ShadeCore starts executing `ShadeCoreMain()`
    1. [SC] Scan physical memory by referencing the scan map of non-BIOS component memory regions prepared by PrepareScanMap()
    1. [SC] Locate binaries such as securekernel.exe and tamper with them to arbitrarily modify memory belonging to VTL1 or hypervisors

#### Runtime phase (Yes VTL0 cooperation)
1. Execute an .exe file with admin privileges that calls `SetFirmwareEnvironmentVariableExA` with `MAGIC_VAR_NAME`
1. ntoskrnl.exe will call `gRT->SetVariable()`
1. SetVariableHook
    1. Write `WAKEUP_SHADE_CORE_SIGNAL` to gShadeCoreStartupSignalBufferVirAddr
    1. [SC] ShadeCore starts executing `ShadeCoreMain()`
        1. [SC] Scan physical memory by referencing the scan map of non-BIOS component memory regions prepared by PrepareScanMap()
        1. [SC] Locate binaries such as securekernel.exe and tamper with them to arbitrarily modify memory belonging to VTL1 or hypervisors


## Author
Kazuki Matsuo. © FFRI Security, Inc. 2026

## License
Apache version 2.0
