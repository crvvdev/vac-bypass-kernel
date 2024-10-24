# VAC kernel-mode bypass

Fully working VAC kernel-mode bypass, it makes use of either SSDT hooks or Infinityhook to intercept VAC syscalls and ultimately spoof the results in order to bypass the memory integrity checks.
Using this bypass you're able to load unsigned DLL into the game memory space and perform patches on the game modules as desired, it also makes sure the DLL will never be scanned by their signature/heuristic checks.


# How it works

VAC is loaded in *SteamService.exe* process (*Steam.exe* will be the process loading it if being ran as administrator instead). 

Basically the anti-cheat is fully external, meaning that it makes use of syscalls like **NtReadVirtualMemory** in order to read game memory and perform some checks. 
Because it's designed like that we can simply intercept those syscalls in a higher level (ring-0) and spoof whatever is being checked/scanned.

*Steam.exe*, *SteamService.exe* and *cs2.exe* are placed into a thread-safe list, this list is used for reference in hooks so we know which process is calling the syscall and which process is requested to be queried from.

Any allocation done by the manual map is also stored in a thread-safe list which is used as reference in hooks in order to spoof any query from **NtReadVirtualMemory** or **NtQueryVirtualMemory**, thus breaking any signature/heuristic check possible.

I place a hook in  **NtMapViewOfSection** so i can intercept any module being loaded as soon as possible, meaning i can create a copy of the module, relocate it and later on i can spoof any VAC query using the copy.

```
static wchar_t *g_BackupModulesList[] = {L"\\bin\\win64\\client.dll",           L"\\bin\\win64\\engine.dll",
                                         L"\\bin\\win64\\materialsystem2.dll",  L"\\bin\\win64\\inputsystem.dll",
                                         L"\\bin\\win64\\rendersystemdx11.dll", L"\\bin\\win64\\rendersystemvulkan.dll",
                                         L"\\bin\\win64\\inputsystem.dll",      L"\\bin\\win64\\scenesystem.dll"};
```

The list is currently hardcoded, there's no need to copy every single loaded module from the game, only the ones you're going to patch.

Because Steam and VAC also makes some system queries like checking if system is in Test or Debug mode we also intercept **NtQuerySystemInformation**, ultimately defeating anything that can lower the trust-factor system.

*In Debug mode there are CRC32 checks used to ensure the spoofed results are consistent, that basically means we're ensuring VAC is really getting what it "expected".*

## Usage

```
Usage: test-driver.exe <operation> <...>
Operations:
    
    test        -   Run bypass test
    bypass      -   Control bypass status
    inject-dll  -   Inject DLL in game


Options:

    inject-dll  <dll-path>

        No additional params.

    bypass
        
        /disable  Disable bypass
        /enable   Enable bypass
```

The description is straightforward, i provide this simple executable which can be used to control the bypass or to inject a DLL in game (using manual map).

### Load kernel driver

Compile the project and install the kernel-driver, i suggest setting Windows in Test mode so the driver can be loaded without having to sign it, but you can sign it youself with your certificate if you want.

It's worth mentioning that SSDT hook method is not PG compatible, thus using something like [EfiGuard](https://github.com/Mattiwatti/EfiGuard) is encouraged, since it disables PG completely and also lets you load any driver by disabling DSE.

For Infinityhook method nothing has to be done for PG, just load driver and it's ready to go.

## WPP Tracing

This project makes use of WPP tracing for debug tracing, if you wish to see debug output you have to setup a tracing session on your machine.

```
tracelog.exe -addautologger VAC -sessionguid #{SESSION_GUID} -flag 0xFF -level 6 -guid #{BBB7063B-B267-4728-A95D-304A8E4E6A89} -kd
```

## Final regards

This project is not meant to be used for newbies, i assume you have at least some knowledge about anti-cheats and malware in general to understand how it works, it's more of a proof-of-concept and a personal project to show my skills.
You're more than welcome to take a look at the source code and contribute to this project!

## Credits

https://github.com/Oxygen1a1/InfinityHookClass
https://github.com/everdox/InfinityHook
