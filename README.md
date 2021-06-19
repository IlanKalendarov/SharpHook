# SharpHook 

SharpHook is inspired by the [SharpRDPThief project](https://github.com/passthehashbrowns/SharpRDPThief), It uses various API hooks in order to give us the desired credentials. 

In the background it uses the [EasyHook](http://easyhook.github.io/) project, Once the desired process is up and running SharpHook will automatically inject its dependencies into the target process and then, It will send us the credentials through EasyHook's IPC server.

# Supported Processes

|        Process        |             API Call              |                         Description                          |                           Progress                           |
| :-------------------: | :-------------------------------: | :----------------------------------------------------------: | :----------------------------------------------------------: |
|         mstsc         | `CredUnPackAuthenticationBufferW` | This will hook into mstsc and should give you Username, Password and the remote ip |                             DONE                             |
|         runas         |     `CreateProcessWithLogonW`     | This will hook into runas and should give you Username, Password and the domain name |                             DONE                             |
|      powershell       |     `CreateProcessWithLogonW`     | This will hook into powershell and should give you output for commands for when the user enters a different credentials |                             DONE                             |
|          cmd          |     `RtlInitUnicodeStringEx`      | This should hook into cmd and then would be able to filter keywords like: PsExec,password etc.. |              In Progress - Crashes cmd idk why               |
|       MobaXterm       |         `CharUpperBuffA`          | This will hook into MobaXterm and should give you credentials for SSH and RDP logins | In Progress - Problems with this being a 32bit process and [Fody](https://github.com/Fody/Costura) not working. **As a workaround you can compile the project as x86 and it'll work just fine** |
| explorer (UAC Prompt) | `CredUnPackAuthenticationBufferW` | This will hook into explorer and should give you Username, Password and the Domain name from the UAC Prompt | In Progress - UAC says access denied probably integrity levels problems |


# Demo
![](https://github.com/IlanKalendarov/SharpHook/blob/main/Images/Helpscreen.PNG)
![](https://github.com/IlanKalendarov/SharpHook/blob/main/Images/Demo.gif)

# Contribution

Please feel free to contribute as I'm having some issues with some processes. You can find me on [Twitter](https://twitter.com/IKalendarov) or open a Pull Request. 

