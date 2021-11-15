# VeraCryptPasswordSniffer
Hooks the MultiByteToWideChar win api using inline hooking, will dump password used to mount drives to a file on disk.


The VCSniffer program will compile to a dll that is injected into the VeraCrypt program by VCMigrate (Originally, the project was supposed to be injected into 32-bit version of ondrive however, i only has the 64-bit version so the heaven's gate technique 32-bit -> 64-bit injection is not used).
The VCSniffer program uses import address table hooking, which patches the location of the MultiByteToWideChar imported function address to our custom function address.
This function is used by VeraCrypt to change the password input by the user to a unicode format.


The program catches the call to the targeted function, views the parameters, and then outputs the password to a file on disk.

Once the user compiles the VCSniffer program, sRDI is used to create a binary file containing the loader function which calls DllMain (exported by VCSniffer) and the VCSNiffer image itself. Next, aes.py is used to encrypted the image so it can be stored in the next binary on disk without fear of it being scanned by an AV solution.


VCMigrate is used to inject the VeraCrypt process. The program will search every 5 seconds for a running VeraCrypt process and try to inject into it. If successfully injected the loop breaks. Standard process injection technique is used. Same process using sRDI and aes.py to create the payload that is stored in VCPersist.

VCPersist is an interesting program. It contains the DLL for VCMigrate which will inject the DLL of VCSniffer into the veraCrypt Program. It will also inject VCMigrate into OneDrive. This is for stealth & persistence purposes. Since OneDrive is almost always running on windows machines and makes regular network / system activity, it should fly relatively under the radar. VCPersist also performs many unique actions such as dynamically resolving malicious functions such as WriteProcessMemory, VirtualAllocEx, RtlCreateUserThread, so the image does not have it listed in its import tables. Additionally, a custom implemenation of GetProcAddress and GetModuleHandle are used for those dynamic look ups. All static strings such as NTDLL, Kernel32.DLL, etc. are obfuscated in base64 strings. All functions could be dynamically resolved in this manner, however, since this is a PoC and not an actual implant I did not see the need to go that far.
