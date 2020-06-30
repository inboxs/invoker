# Invoker

Penetration testing utility.

The goal is to use this tool when access to some Windows OS features through GUI is restricted.

Some features require administrative privileges.

Capabilities:

* invoke the Command Prompt and PowerShell,
* download a file,
* add a registry key,
* schedule a task,
* connect to a remote host,
* terminate a running process,
* run a new process,
* inject a bytecode into a running process,
* inject a DLL into a running process,
* list DLLs of a running process,
* enable access token privileges,
* duplicate an access token of a running process,
* list unquoted service paths and restart a running service,
* replace Sticky Keys,
* install a hook procedure.

Built with Dev-C++ IDE v5.11 (64-bit), compiled with TDM-GCC v4.9.2 (32-bit and 64-bit) and tested on Windows 10 Enterprise OS (64-bit). Download Dev-C++ from [here](https://sourceforge.net/projects/orwelldevcpp/files/Portable%20Releases/).

Made for educational purposes. I hope it will help!

Future plans:

* ~~DLL Hijacking~~,
* DLL Proxying,
* COM Hijacking.

## Invoker Library

Check all the capabilities [here](https://github.com/ivan-sincek/invoker/blob/master/src/Invoker/lib/invoker/invoker.cpp). Feel free to use the library.

## How to Run

Run ['\\exec\\Invoker_x86.exe'](https://github.com/ivan-sincek/invoker/tree/master/exec) (32-bit) or ['\\exec\\Invoker_x64.exe'](https://github.com/ivan-sincek/invoker/tree/master/exec) (64-bit).

32-bit Invoker can only:

* inject a 32-bit bytecode into a 32-bit process,
* inject a 32-bit DLL into a 32-bit process,
* list DLLs of a 32-bit process,
* install a hook procedure from a 32-bit DLL.

64-bit Invoker can only:

* inject a 32-bit bytecode into a 32-bit process,
* inject a 64-bit bytecode into a 64-bit process,
* ~~inject a 32-bit DLL into a 32-bit process~~,
* inject a 64-bit DLL into a 64-bit process,
* ~~list DLLs of a 32-bit process~~,
* list DLLs of a 64-bit process.
* ~~install a hook procedure from a 32-bit DLL~~,
* install a hook procedure from a 64-bit DLL.

## Bytecode Injection

Elevate privileges by injecting bytecode into a higher-privileged process.

This tool can parse an HTTP response and extract the payload from a custom element, i.e. from `<img class="bc" src="data:image/gif;base64,payload" alt="bc" hidden="hidden">` where `payload` is a binary code/file encoded in Base64.

This might be useful if antivirus is constantly deleting your local payloads.

You can also specify your own custom element but you will have to modify the program source code and recompile it.

Check an example at [pastebin.com/raw/Nd1tCBv6](https://pastebin.com/raw/Nd1tCBv6).

**Bytecode provided will most certainly not work for you.**

Too see if a process is 32-bit or 64-bit open up Task Manager -> click on `More details` -> go to `Details` tab -> right click on any of the columns -> click on `Select columns` -> check the `Platform` checkbox.

Additionally, to see if a process is running with administrative privileges check the `Elevated` checkbox.

## Generate a Reverse Shell Payload

Find out how to generate a reverse shell payload from my other [project](https://github.com/ivan-sincek/penetration-testing-cheat-sheet#generate-a-reverse-shell-payload).

## PowerShell Scripts

Check all the PowerShell scripts used in the main C++ program [here](https://github.com/ivan-sincek/invoker/tree/master/ps).

## Make a DLL With a Hook Procedure

Find out how to make a DLL with a hook procedure [here](https://github.com/ivan-sincek/invoker/blob/master/src/InvokerHook/dllmain.cpp).

Hook procedure from will invoke a message box on each window close.

Check out a keyboard hook procedure from my other [project](https://github.com/ivan-sincek/keylogger/blob/master/src/keylogger.cpp).

## Get the LocalSystem Account (NT AUTHORITY\SYSTEM)

Run the Invoker as administrator.

Enable all access token privileges.

Duplicate the access token from e.g. Windows Logon Application (winlogon.exe) and run a new instance of Invoker.

Within the new Invoker instance, open the Command Prompt and run `whoami`, you should now see `nt authority\system`.

Enable all access token privileges once again.

Close the old Invoker instance.

P.S. You get more access token privileges from Local Security Authority Subsystem Service (lsass.exe).

## Images

<p align="center"><img src="https://github.com/ivan-sincek/invoker/blob/master/img/invoker.jpg" alt="Invoker"></p>

<p align="center">Figure 1 - Invoker</p>

<p align="center"><img src="https://github.com/ivan-sincek/invoker/blob/master/img/registry.jpg" alt="Add/Edit Registry Key"></p>

<p align="center">Figure 2 - Add/Edit Registry Key</p>

<p align="center"><img src="https://github.com/ivan-sincek/invoker/blob/master/img/bytecode_injection.jpg" alt="Bytecode Injection"></p>

<p align="center">Figure 3 - Bytecode Injection</p>

<p align="center"><img src="https://github.com/ivan-sincek/invoker/blob/master/img/elevated_privileges.jpg" alt="Elevated Privileges"></p>

<p align="center">Figure 4 - Elevated Privileges</p>
