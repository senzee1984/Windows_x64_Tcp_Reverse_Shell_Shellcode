## Windows/x64 - PIC Null-Free TCP Reverse Shell Shellcode (478 Bytes)

### Shellcode Author:    Senzee
##### OS Architecture:   Windows x64
##### Tested On:         Windows 11 Home 10.0.22621, Windows Server 2022 Standard 10.0.20348, Windows Server 2019 Datacenter 10.0.17763
##### Shellcode Size:    478 bytes
##### Null-Free:         True

![image](/screenshot/reverse_tcp_shell.jpg)


## Shellcode Description
Null-Free, PIC, and extremely small-size (25 bytes smaller than MSF's) Windows x64 shellcode that implements Windows TCP reverse shell. The shellcode works by dynamically resolving the base address of `kernel32.dll` via `PEB` and `ExportTable` method. 

To resolve the base address of `kernel32.dll`, the steps are as follows:

1. Locate the address of `TEB` in the Intel `GS` register
2. Locate the address of `PEB` in the TEB structure
3. Locate `_PEB_LDR_DATA` structure in PEB structure
4. Get the head of doubly-linked list `InMemoryOrderModuleList`
5. The 3rd entry of doubly-linked list InMemoryOrderModuleList: `program.exe(shellcode loading program) -> ntdll.dll -> kernel32.dll`
6. Find DllBase of the current module in `_LDR_DATA_TABLE_ENTRY structure`

After getting the base address of kernel32.dll, parse kernel32.dll and locate `LoadLibraryA` function. The steps are as follows:

1. Locate the `Export Directory`
2. Get the `number of function names` and use it as an index
3. Locate the `Export Name Pointer Table`.
4. Use function name hashing approach to avoid the use of function name
5. Compare the WinExec's hash with the current function's hash in the loop
6. Get the address of LoadLibraryA, supply proper arguments, and call it.

Use LoadLibraryA to get the base address of `ws2_32.dll` module, and locate `WSAStartup`, `WSASocketA`, and `WSAConnect` functions. Supply with proper arguments and call them respectively.

Argument `vVersionRequired` should be `0x202`, argument `lpWSAData` should point to the start address of the reserved space. 
```c++
int WSAStartup(
        WORD      wVersionRequired,
  [out] LPWSADATA lpWSAData
);
```

Argument `af` should be `2`, argument `type` should be `1`, and argument `protocol` should be `6`. The left 3 arguments should be `0`.
```c++
SOCKET WSAAPI WSASocketA(
  [in] int                 af,
  [in] int                 type,
  [in] int                 protocol,
  [in] LPWSAPROTOCOL_INFOA lpProtocolInfo,
  [in] GROUP               g,
  [in] DWORD               dwFlags
);
```

Argument `s` should be the return value of `WSASocketA`, argument `name` should point to the address of structure `sockaddr_in`, and argument `namelen` should be `0x16`. The left 4 arguments should be `0`.
```c++
int WSAAPI WSAConnect(
  [in]  SOCKET         s,
  [in]  const sockaddr *name,
  [in]  int            namelen,
  [in]  LPWSABUF       lpCallerData,
  [out] LPWSABUF       lpCalleeData,
  [in]  LPQOS          lpSQOS,
  [in]  LPQOS          lpGQOS
);
```

Member `sin_family` should be `2`, member `sin_port` should be the listening port,  member `sin_addr` should be the IP address, sin_zero should be `0`.
```c++
struct sockaddr_in {
        short   sin_family;
        u_short sin_port;
        struct  in_addr sin_addr;
        char    sin_zero[8];
};
```


Locate `CreateProcessA` function in kernel32.dll, call it.

Argument `lpCommandLine` is `"cmd.exe"`, argument `bInheritHandles` is `1`, argument `lpStartupInfo` is the address of structure `LPSTARTUPINFOA`, argument `lpProcessInformation` points to the start address of the reserved space. Other arguments are `0`.
```c++
BOOL CreateProcessA(
  [in, optional]      LPCSTR                lpApplicationName,
  [in, out, optional] LPSTR                 lpCommandLine,
  [in, optional]      LPSECURITY_ATTRIBUTES lpProcessAttributes,
  [in, optional]      LPSECURITY_ATTRIBUTES lpThreadAttributes,
  [in]                BOOL                  bInheritHandles,
  [in]                DWORD                 dwCreationFlags,
  [in, optional]      LPVOID                lpEnvironment,
  [in, optional]      LPCSTR                lpCurrentDirectory,
  [in]                LPSTARTUPINFOA        lpStartupInfo,
  [out]               LPPROCESS_INFORMATION lpProcessInformation
);
```

Member `cb` is `0x68`, member `dwFlags` is `0x100`, members `hStdInput`, `hStdOutput`, and `hStdError` are the return value of function WSASocketA. Other members are `0`.
```c++
typedef struct _STARTUPINFOA {
  DWORD  cb;
  LPSTR  lpReserved;
  LPSTR  lpDesktop;
  LPSTR  lpTitle;
  DWORD  dwX;
  DWORD  dwY;
  DWORD  dwXSize;
  DWORD  dwYSize;
  DWORD  dwXCountChars;
  DWORD  dwYCountChars;
  DWORD  dwFillAttribute;
  DWORD  dwFlags;
  WORD   wShowWindow;
  WORD   cbReserved2;
  LPBYTE lpReserved2;
  HANDLE hStdInput;
  HANDLE hStdOutput;
  HANDLE hStdError;
} STARTUPINFOA, *LPSTARTUPINFOA;
```

## Change IP and Port
To change the IP address, modify `line 162` of `reverse_shell.py`. The IP address is reversed and NEGed. 

```WinDBG
0:000> ? 0n45
Evaluate expression: 45 = 00000000`0000002d
0:000> ? 0n0
Evaluate expression: 0 = 00000000`00000000
0:000> ? 0n168
Evaluate expression: 168 = 00000000`000000a8
0:000> ? 0n192
Evaluate expression: 192 = 00000000`000000c0
0:000> ? -2d00a8c0
Evaluate expression: -755017920 = ffffffff`d2ff5740
```

According to the value of the IP address, in rare cases (`255` is part of the address), 0x00 could exist. However, in most cases (none of the 4 parts of the IP address is `0`), we can directly set the IP address without the need to neg it.

To change the listening port, modify `line 160` of `reverse-shell.py`. According to the value of the listening port, in rare cases, 0x00 could exist.




