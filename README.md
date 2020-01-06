# Mimir
A C++ POC for process injection using NtCreateSectrion, NtMapViewOfSection and RtlCreateUserThread.

# Description

A C++ POC for process injection using NtCreateSectrion, NtMapViewOfSection and RtlCreateUserThread. Currently it only works for 32bit processes.

# Usage
```
Mimir.exe process notepad.exe
```
or 
```
Mimir.exe PID 1000
```
# Example

```
Mimir.exe PID 248
[>] NtCreateSection is at: 0x77002210.
[>] NtMapViewOfSection is at: 0x77001FF0.
[>] RtlCreateUserThread is at: 0x76FFF7D0.
[>] Section local BaseAddress: 0x000F0000.
[>] Target process PID found: 248.
[>] Trying to open a handle to the target process...
[>] Section remote BaseAddress: 0x010B0000.
[>] Trying to copy the shellcode to the new section of the current process...
[>] Trying to pop calc...
[>] Done
```

# Todo
- [ ] 64bit process injection

# Bugs
For any bugs give me a shout on Twitter [@den_n1s](https://twitter.com/den_n1s) or open an issue. 
