# SharpRDPThief
SharpRDPThief is a C# implementation of RDPThief. It uses EasyHook to inject a DLL into mstsc.exe, which will then hook the CryptProtectMemory api call. The hook will grab the password from the address passed to CryptProtectMemory and then send it to the main process through EasyHook's IPC server.

Currently this is only a proof of concept implementation and requires RDPHook.dll to be in the same directory as SharpRDPThief.exe. The immediate plan is to allow for completely in memory execution, for use with tools like Cobalt Strike's execute-assembly. 

You can read more about the original research from @0x09AL here: https://www.mdsec.co.uk/2019/11/rdpthief-extracting-clear-text-credentials-from-remote-desktop-clients/

![Proof of concept screenshot](https://pbs.twimg.com/media/EgUZZQVXYAEGMAw?format=png&name=large)

## TODO
Completely in-memory execution

Better parsing of memory for username/password

[Done] ~~Search for mstsc.exe processes and inject into them automatically.~~

## References
RDPThief: https://github.com/0x09AL/RdpThief

EasyHook FileMonitor: https://github.com/EasyHook/EasyHook-Tutorials/tree/master/Managed/RemoteFileMonitor

EasyHook remote process hook tutorial: https://easyhook.github.io/tutorials/remotefilemonitor.html
