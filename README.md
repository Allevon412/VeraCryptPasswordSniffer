# VeraCryptPasswordSniffer
Hooks the MultiByteToWideChar win api using inline hooking, will dump password used to mount drives to a file on disk.


The VCSniffer program will compile to a dll that is injected into the VeraCrypt program by VCMigrate (Originally, the project was supposed to be injected into 32-bit version of ondrive however, i only has the 64-bit version so the heaven's gate technique 32-bit -> 64-bit injection is not used).
The VCSniffer program uses import address table hooking, which patches the location of the MultiByteToWideChar imported function address to our custom function address.
This function is used by VeraCrypt to change the password input by the user to a unicode format.
