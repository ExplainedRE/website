---
title: "Flare-On 7 — 09 crackinstaller"
date: 2020-10-23T21:29:42+03:00
draft: false
author: "explained.re"
tags: ["flare-on"]
categories: ["write-up", "ctf"]

lightgallery: true


toc:
  enable: false

---

{{< admonition info "Challenge Description" >}}

What kind of crackme doesn't even ask for the password? We need to work on our COMmunication skills.
{{< /admonition >}}

In this challenge we get a 64 bit Windows executable, off to a good start.

{{< image src="images/image.png" >}}

The challenge description has a clue for the possible usage of COM objects here, so we'll make a mental note of that.

Simply executing the binary doesn't seem to do much, so we'll fire up a debugger and start looking at the code. IDA Pro identified `main` for us, so we can simply put a breakpoint at the start of this function and execute the file. Doing that, the process seems to start but immediately exit, without hitting our breakpoint. This tells us that there is probably some interesting code that executes before `main`.  A good place to start looking for this kind of code is the entry point. `Ctrl+E` in IDA will get us there.

```cpp
__int64 start()
{
  _security_init_cookie();
  return __scrt_common_main_seh();
}
```

We'll examine `__scrt_common_main_seh` (from which `main` is supposed to be invoked). This function seems pretty standard when it comes to C runtime code, so the next place to look for something interesting will be in the function array that is passed to `initterm`. `initterm` is an internal CRT function that simply walks a function pointer array and initializes every function there.

```cpp
.rdata:000000014000F2B0 ; const _PVFV First
.rdata:000000014000F2B0 First           dq 0                    ; DATA XREF: __scrt_common_main_seh(void)+75↑o
.rdata:000000014000F2B8                 dq offset ?pre_cpp_initialization@@YAXXZ ; pre_cpp_initialization(void)
.rdata:000000014000F2C0                 dq offset sub_140001000
.rdata:000000014000F2C8 ; const _PVFV Last
.rdata:000000014000F2C8 Last            dq 0
```

Looking at this function pointer array, we see two functions - one that IDA identified as `pre_cpp_initialization` and another one which has no matching signature. We probably have nothing to look for in the function IDA has identified, so let's go to `sub_140001000` and see what it does. This is just a wrapper for `sub_140002530` so we'll focus on this one.

```cpp
__int64 sub_140002530()
{
  v0 = -1i64;
  v1 = 0;
  hObject = (HANDLE)-1i64;
  v2 = 0i64;
  if ( (unsigned int)sub_140001CD8() )
  {
    v3 = sub_140002370(&unk_1400363B0, 8069i64, 10576i64);
    if ( v3 )
    {
      v2 = (void *)sub_140002370(&unk_140034080, 8882i64, 22528i64);
      if ( v2 )
      {
        v4 = sub_140001C34(&unk_140019988, 28i64, 0i64);
        v1 = sub_140002ED8(v4, v3);
        if ( v1 )
        {
          v12 = *(_QWORD *)sub_140001C34(&unk_140019900, 4i64, 0i64);
          v5 = sub_140001C34(&unk_140019988, 28i64, 0i64);
          v17 = *(_OWORD *)v5;
          v18 = *(_OWORD *)(v5 + 16);
          v19 = *(_OWORD *)(v5 + 32);
          v20 = *(_QWORD *)(v5 + 48);
          v6 = sub_140001C34(&unk_1400199C0, 15i64, 0i64);
          v13 = *(_OWORD *)v6;
          v14 = *(_QWORD *)(v6 + 16);
          v15 = *(_DWORD *)(v6 + 24);
          v16 = *(_WORD *)(v6 + 28);
          v7 = sub_140001FB4(&v12, &v17, &v13, &hObject);
          v0 = (__int64)hObject;
          v1 = v7;
          if ( v7 )
          {
            LODWORD(v12) = 0;
            *(_QWORD *)&v18 = 0i64;
            v17 = 0i64;
            DWORD2(v18) = 0;
            *(_QWORD *)&v13 = 0i64;
            DWORD2(v13) = 0;
            WORD6(v13) = 0;
            BYTE14(v13) = 0;
            v1 = sub_140002C44(hObject);
            if ( v1 )
            {
              v8 = sub_140001C34(&unk_140019900, 4i64, 0i64);
              v1 = sub_140001EB4(v8) != 0;
            }
          }
        }
      }
    }
  }
  v9 = (const WCHAR *)sub_140001C34(&unk_140019988, 28i64, 0i64);
  v10 = CreateFileW(v9, 0x10000000u, 0, 0i64, 3u, 0x4000000u, 0i64);
  if ( v10 != (HANDLE)-1i64 )
    CloseHandle(v10);
  if ( v0 != -1 )
    CloseHandle((HANDLE)v0);
  if ( v2 )
  {
    memset(v2, 0, 0x5800ui64);
    free(v2);
  }
  if ( !v1 )
    exit(0);
  return 0i64;
```

Let's rename this to be our `init_function` so it'll be easy to refer to it. Right before this function returns, we see an if statement the can potentially terminate the process. This aligns with what we saw before, where the process exited even before our breakpoint in `main`, so looks like we're in the right direction. We'll continue by looking at the first function call here which is to `sub_140001CD8`.

```cpp
 __int64 sub_140001CD8()
{
  v0 = (const CHAR *)sub_140001B54(&unk_140019A40, 13i64);
  v1 = LoadLibraryA(v0);
  v2 = (const CHAR *)sub_140001B54(&unk_1400199D0, 13i64);
  v3 = LoadLibraryA(v2);
  v4 = 0;
  v5 = v3;
  if ( v1 )
  {
    if ( v3 )
    {
      v6 = (const CHAR *)sub_140001B54(&unk_140019918, 15i64);
      qword_1400395F8 = (__int64)GetProcAddress(v1, v6);
      if ( qword_1400395F8 )
      {
        v7 = (const CHAR *)sub_140001B54(&unk_140019A70, 13i64);
        qword_1400395C8 = (__int64)GetProcAddress(v1, v7);
        if ( qword_1400395C8 )
        {
          v8 = (const CHAR *)sub_140001B54(&unk_140019928, 19i64);
          qword_1400395F0 = (__int64)GetProcAddress(v1, v8);
          if ( qword_1400395F0 )
          {
            v9 = (const CHAR *)sub_140001B54(&unk_140019A50, 14i64);
            qword_1400395D8 = (__int64)GetProcAddress(v1, v9);
            if ( qword_1400395D8 )
            {
              v10 = (const CHAR *)sub_140001B54(&unk_1400199F0, 15i64);
              qword_1400395E0 = (__int64)GetProcAddress(v1, v10);
              if ( qword_1400395E0 )
              {
                v11 = (const CHAR *)sub_140001B54(&unk_140019940, 14i64);
                qword_1400395D0 = (__int64)GetProcAddress(v1, v11);
                if ( qword_1400395D0 )
                {
                  v12 = (const CHAR *)sub_140001B54(&unk_140019908, 15i64);
                  qword_1400395E8 = (__int64)GetProcAddress(v1, v12);
                  if ( qword_1400395E8 )
                  {
                    v13 = (const CHAR *)sub_140001B54(&unk_1400199E0, 12i64);
                    qword_140039600 = (__int64)GetProcAddress(v5, v13);
                    if ( qword_140039600 )
                      v4 = 1;
                  }
                }
              }
            }
          }
        }
      }
    }
  }
  return v4;
```

This seems like a rather simple function that loads a couple of DLLs using `LoadLibraryA` and then locates a few functions from those DLLs using `GetProcAddress`. As you see, before every function call to load a library or to locate a function, we have a call to `sub_140001B54`, passing a location and a number to it. Experienced reverse engineers may already guess that this is a string decryption routine, that accepts the encoded string, and its size. Since we only have a handful of functions being resolved here, you can either execute this and then examine dynamically which functions have been resolved, or you can write a quick script to perform the decoding of the function names for you. If you've chosen to decode the strings yourself, you'll need to look at the decoding function.

```cpp
char *__fastcall sub_140001B54(__int64 a1, unsigned int a2, int a3)
{
  dword_1400395B0 += a3;
  v3 = 0;
  if ( a2 )
  {
    v4 = Source;
    v5 = a2;
    do
    {
      *v4 = v4[a1 - (_QWORD)Source] ^ aGIt[v3];
      ++v4;
      v3 = (v3 + 1) % 7;
      --v5;
    }
    while ( v5 );
  }
  return Source;
}
```

This looks like a simple XOR decryption routine, that uses `'<g~{<it'` as the key. Not too bad. We can decode and rename the encrypted strings as we go. We'll rename the function names and the resolved function pointers and continue our analysis. After decoding and renaming the pointers, we get this.

```cpp
__int64 __stdcall ResolvAPIs()
{
  v0 = decode_string((__int64)&enc_advapi, 0xDu, 0);
  v1 = LoadLibraryA(v0);
  v2 = decode_string((__int64)&en_kernel32_dll, 0xDu, 0);
  v3 = LoadLibraryA(v2);
  v4 = 0;
  v5 = v3;
  if ( v1 )
  {
    if ( v3 )
    {
      v6 = decode_string((__int64)&enc_CreateServiceW, 0xFu, 0);
      CreateServiceW = (__int64 (__fastcall *)(_QWORD, _QWORD, _QWORD, _QWORD, _DWORD, _DWORD, _DWORD, _QWORD, _QWORD, _QWORD, _QWORD, _QWORD, _QWORD))GetProcAddress(v1, v6);
      if ( CreateServiceW )
      {
        v7 = decode_string((__int64)&enc_OpenServiceW, 0xDu, 0);
        OpenServiceW = (__int64 (__fastcall *)(_QWORD, _QWORD, _QWORD))GetProcAddress(v1, v7);
        if ( OpenServiceW )
        {
          v8 = decode_string((__int64)&enc_CloseServiceHandle, 0x13u, 0);
          CloseServiceHandle = (__int64 (__fastcall *)(_QWORD))GetProcAddress(v1, v8);
          if ( CloseServiceHandle )
          {
            v9 = decode_string((__int64)&enc_StartServiceW, 0xEu, 0);
            StartServiceW = (__int64 (__fastcall *)(_QWORD, _QWORD, _QWORD))GetProcAddress(v1, v9);
            if ( StartServiceW )
            {
              v10 = decode_string((__int64)&enc_ControlService, 0xFu, 0);
              ControlService = (__int64 (__fastcall *)(_QWORD, _QWORD, _QWORD))GetProcAddress(v1, v10);
              if ( ControlService )
              {
                v11 = decode_string((__int64)&enc_DeleteService, 0xEu, 0);
                DeleteService = (__int64 (__fastcall *)(_QWORD))GetProcAddress(v1, v11);
                if ( DeleteService )
                {
                  v12 = decode_string((__int64)&enc_OpenSCManagerW, 0xFu, 0);
                  OpenSCManagerW = (__int64 (__fastcall *)(_QWORD, _QWORD, _QWORD))GetProcAddress(v1, v12);
                  if ( OpenSCManagerW )
                  {
                    v13 = decode_string((__int64)&enc_CreateFileW, 0xCu, 0);
                    CreateFileW_0 = (__int64 (__fastcall *)(_QWORD, _QWORD, _QWORD, _QWORD, _DWORD, _DWORD, _QWORD))GetProcAddress(v5, v13);
                    if ( CreateFileW_0 )
                      v4 = 1;
                  }
                }
              }
            }
          }
        }
```

Now that we have resolved the API functions the binary is going to use, we can continue analyzing our `init_function`. In it, we see another function (`sub_140002370`) that calls `decode_string`, but this time it converts it to a Unicode string before it returns it, let's rename it `decode_string_unicode`. And then, we can also rename the encoded strings that are passed to this function as well, as we did before. Now we can continue to see what functions our `initi_functions` invokes:

1. `sub_140002370` - decodes and returns an executable file (PE format)
2. `sub_140002ED8` - seem to be writing the data from the second argument to a file, it writes the data it got from the previous function to `C:\Windows\System32\cfs.dll`.
3. `sub_140001FB4` - accepts a service name and a binary path, then creates a service and starts it. At this point, we understand that the `cfs.dll` the binary dumps is actually a driver. After running the service the function stores a handle to the `\\.\Htsysm72FB` device in the fourth argument. Some of you may already know what this device is, but even if you don't a quick search will tell you immediately. This is the famous vulnerable Capcom driver, which basically allows an unprivileged user to execute code in the kernel.

    The sole purpose of this Capcom driver here is to accept an IOCTL, then disable SMEP (prevents the kernel to execute user code), execute code from the user and reenable SMEP again. If you'd like to read a full analysis of this vulnerable driver, we recommend reading the following:
    - [https://github.com/notscimmy/libcapcom](https://github.com/notscimmy/libcapcom)
    - [https://www.fuzzysecurity.com/tutorials/28.html](https://www.fuzzysecurity.com/tutorials/28.html)

4. `sub_140002C44` - accepts the handle to the device and a pointer to the second PE file decoded by `sub_140002370`. It then locates the export `DriverBootstrap` from our driver and ultimately calls `DeviceIOControl`, with IOCTL code `0xAA013044` and a buffer pointing to code that contains the address of `DriverBootstrap`.

Since we already know this driver is Capcom, we know this IOCTL will make the driver disable SMEP, and then jumping to the user-supplied code in the input buffer of the `DeviceIoControl`. The easiest way to continue is to debug this and have a look at the code the kernel will be executing. But before we start *WinDbg*, we need to figure out where we'd like to break. A quick way is to locate where the dumped `cfs.dll` driver handles our IOCTL. We open up IDA and hit `Ctrl+I` to search an immediate value, which brings us to the dispatch function that handles `IRP_MJ_DEVICE_CONTROL` requests - `sub_10590`. Here we see that this IOCTL will ultimately bring to the invocation of `sub_10524` which accepts a pointer, disables SMEP, and jumps to it. This is where we'd like to break to we take the `call` address and subtract is from the module base to get its offset in the driver.

```python
Python>0x00010573 - idaapi.get_imagebase()
0x573
```

Next, we can connect a kernel debugger to our VM, and set an unresolved breakpoint on our desired address.

```bash
kd> bu cfs+573
*** Bp expression 'cfs+573' contains symbols not qualified with module name.
```

Now can hit `g` and execute `crackinstaller.exe`.

```markup
kd> g
Breakpoint 0 hit
cfs+0x573:
fffff806`6c270573 ff542428        call    qword ptr [rsp+28h]
kd> t
00000201`c7d00008 fb              sti
kd> u
00000201`c7d00008 fb              sti
00000201`c7d00009 48bae0dac1c701020000 mov rdx,201C7C1DAE0h
00000201`c7d00013 41b800580000    mov     r8d,5800h
00000201`c7d00019 41b970310000    mov     r9d,3170h
00000201`c7d0001f ff2500000000    jmp     qword ptr [00000201`c7d00025]
```

Now we're executing the code from the user. Let's try to run until the first dynamic function call to see what it is.

```cpp
00007ff7`6d482c26 ff542448        call    qword ptr [rsp+48h] ss:0018:ffffd201`06aca678={nt!**PsCreateSystemThread** (fffff803`5409f5a0)}
```

This code creates a new system thread, which starts at the routine pointed to by the 6th argument.

```markup
kd> dq rsp+5*8 l1
fffffc81`ca74f658  ffffa589`fc006170 
kd> bp ffffa589`fc006170 
kd> u ffffa589`fc006170 
ffffa589`fc006170 48894c2408      mov     qword ptr [rsp+8],rcx
ffffa589`fc006175 56              push    rsi
ffffa589`fc006176 57              push    rdi
ffffa589`fc006177 4881ec88000000  sub     rsp,88h
ffffa589`fc00617e 488d442448      lea     rax,[rsp+48h]
ffffa589`fc006183 488bf8          mov     rdi,rax
ffffa589`fc006186 33c0            xor     eax,eax
ffffa589`fc006188 b930000000      mov     ecx,30h
```

You may recognize this function as `DriverBootstrap`! We'll set a breakpoint on it and `g`.

When you get to code you recognize in *WinDbg* (`DriverBootstrap`) it's a good idea to rebase the driver in IDA so that addresses match (*Edit→Segments→Rebse program...*

`DriverBootstrap` main purpose is to call the undocumented function `[IoCreateDriver](http://www.codewarrior.cn/ntdoc/win2k/io/IoCreateDriver.htm)` with our driver's `DriverEntry` as the *InitializationFunction.* Thus, our analysis will continue to this function.

```cpp
NTSTATUS __stdcall DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
  _security_init_cookie();
  return driver_main_function(DriverObject);
}
```

Since it only passes the driver object, we'll continue to the next function.

```cpp
__int64 __fastcall driver_main_function(struct _DRIVER_OBJECT *a1)
{
  DeviceObject = 0i64;
  memset(&Altitude, 0, sizeof(Altitude));
  memset(v6, 0, 0x100ui64);
  Altitude.Buffer = (PWSTR)v6;
  callCallXORDecrypt((__int64)&enc_360000, 7u, (__int64)&Altitude);
  a1->DriverUnload = (PDRIVER_UNLOAD)driver_unload;
  v2 = IoCreateDevice(a1, 0x60u, 0i64, 0x22u, 0x100u, 0, &DeviceObject);
  if ( v2 >= 0 )
  {
    v3 = (char *)DeviceObject->DeviceExtension;
    ExInitializeFastMutex((PFAST_MUTEX)(v3 + 8));
    KeInitializeEvent((PRKEVENT)(v3 + 64), NotificationEvent, 0);
    *(_DWORD *)v3 = 0;
    v3[88] = 0;
    v2 = CmRegisterCallbackEx((PEX_CALLBACK_FUNCTION)CallbackFunction, &Altitude, a1, a1, &Cookie, 0i64);
  }
  if ( v2 < 0 && DeviceObject )
    IoDeleteDevice(DeviceObject);
  return (unsigned int)v2;
}
```

Most of the code is pretty standard for a Windows driver, stuff like creating a device, populating a driver unload function. In addition to that, we also have a call to [CmRegisterCallbackEx](https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-cmregistercallbackex) which registers a callback function for the configuration manager (registry). The most important parameter for us here is the first one, which is a pointer to the [RegistryCallback](https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-cmregistercallbackex) routine to register. Now our driver has a function that ntoskrnl will invoke that is able to monitor, block, or modify registry operations. Let's dive into it and see what is its purpose. A good place to start is to understand what this callback function should get as its arguments. From the [RegistryCallback](https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-cmregistercallbackex) documentation, we can see that the second and third parameters that it accepts are the type of registry operation (REG_NOTIFY_CLASS) and an optional pointer to a structure, containing information specific to the type of operation. These will be passed by the OS kernel, based on the type of operation that the function gets a callback for. The first argument, however, is called *CallbackContext*, and it's whatever the driver passed as the *Context* parameter when it registered this callback function. In our case, it was `a1` which is simply the driver object.

```cpp
v2 = CmRegisterCallbackEx((PEX_CALLBACK_FUNCTION)CallbackFunction, &Altitude, a1, a1, &Cookie, 0i64);
```

We'll set the appropriate type in IDA for easier analysis, and start examining the callback function itself. For analyzing `CallbackFunction` we will set the first parameter's type to `_DRIVER_OBJECT` and the second parameter's type to `_REG_CREATE_KEY_INFORMATION`. 

First this function will check if the notification is of type `RegNtPreCreateKeyEx`

```cpp
if ( NotifyClass && OperationInformation && CallbackContext && (_DWORD)NotifyClass == RegNtPreCreateKeyEx )
```

Then it will check if the registry path of this operation it got a callback from is a relative path, and if it is, it will construct the complete path. After that, this function will decrypt a buffer using `sub_140004DC0`, and use `wcsstr` to check if the decrypted buffer is contained in the full path of the current registry operation. Simply debugging until this `wcsstr` call, we see that the path is checked for the presence of `{CEEACC6E-CCB2-4C4F-BCF6-D2176037A9A7}\Config`.

```cpp
kd> du rdx
fffffc81`c8eb6ff0  "{CEEACC6E-CCB2-4C4F-BCF6-D217603"
fffffc81`c8eb7030  "7A9A7}\Config"
```

 If this registry operation is the one that this comparison is looking for, it will decrypt another buffer, construct an `_OBJECT_ATTRIBUTES` structure, and then call `ZwCreateKey`. There are two parameters that are interesting for us here, and we'll debug the function until this call in order to see what's being passed to it.

- 3rd argument - this is the target key `_OBJECT_ATTRIBUTES`. It contains the path of the key, which set to be the full path of the key being accessed in the current registry operation to which we get the callback. So, it should be `\HKEY_CLASSES_ROOT\CLSID\{CEEACC6E-CCB2-4C4F-BCF6-D2176037A9A7}\Config`

    ```cpp
    kd> r r8
    r8=fffffc81c81e71a8
    kd> dt nt!_OBJECT_ATTRIBUTES fffffc81c81e71a8
       +0x000 Length           : 0x30
       +0x008 RootDirectory    : (null) 
       +0x010 ObjectName       : 0xffffbd00`9366e2e0 _UNICODE_STRING "\REGISTRY\MACHINE\SOFTWARE\Classes\CLSID\{CEEACC6E-CCB2-4C4F-BCF6-D2176037A9A7}\Config"
       +0x018 Attributes       : 0x240
       +0x020 SecurityDescriptor : (null) 
       +0x028 SecurityQualityOfService : (null) 
    ```

- 5th argument - this argument is the result of the previous decryption process our `CallbackFunction` performed. According to the [documentation](https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-zwcreatekey) of `ZwCreateKey`, this is the `Class` parameter, that should point to a Unicode string that contains the key's object class (this information should be used by the configuration manager). We have to say that its purpose is not entirely clear from the documentation, but a few articles online mentioned that this should be a Unicode value that will be written to the registry key in some form ([here](https://wenku.baidu.com/view/574d392458fb770bf78a5501.html) for example). Debugging this, we see the value is `H@n $h0t FiRst!`.

    ```cpp
    kd> dq rsp+4*8 l1
    fffffc81`c81e70e0  fffffc81`c81e7168
    kd> dt nt!_UNICODE_STRING fffffc81`c81e7168
     "H@n $h0t FiRst!"
       +0x000 Length           : 0x1e
       +0x002 MaximumLength    : 0x20
       +0x008 Buffer           : 0xfffffc81`c81e7330  "H@n $h0t FiRst!"
    ```

Finally, the `CallbackFunction` will simply create a new system thread, that'll unload the driver.

```cpp
v7 = PsCreateSystemThread(
                 &ThreadHandle,
                 0x10000000u,
                 &ThreadObjectAttributes,
                 0i64,
                 0i64,
                 (PKSTART_ROUTINE)CallbackContext->DriverUnload,
                 CallbackContext);
```

Due to this fact, it's probably a good idea to leave the driver and return to the binary we started from.

So, let us come back to `crackinstaller` to see what's going on in its `main`. Having the ability to easily debug this function, we can focus on the API functions that `main` uses for its functionality.

```cpp
SHGetKnownFolderPath(&rfid, 0, 0i64, &ppszPath) )
v13 = CreateFileW(FileName, 0xC0000000, 3u, 0i64, 2u, 0, 0i64);
WriteFile(v13, v4, 0x1A600u, (LPDWORD)&NumberOfBytesWritten, 0i64)
v22 = LoadLibraryW(LibFileName);
v23 = (const CHAR *)sub_140001BC8(&unk_140019970, 18i64);
v24 = (void (*)(void))GetProcAddress(v22, v23);
v24();
```

We stripped the function down to the bare minimum so the functionality will be better visible.

1. Looking at the value of `rfid` and based on the known folder id [documentation](https://docs.microsoft.com/en-us/windows/win32/shell/knownfolderid), we understand that the challenge gets the path of `System32`
2. Next, the binary will create and write to a file in this folder. Now actual need to understand where the data comes from since we can simply execute is and grab the file it drops. We will look at `sub_140001C6C` which simply decrypts a string at `unk_140019A18` like we saw before and converts it to a wide string.

    ```python
    from malduck import unhex, xor
    key = b"<g~{<it"
    data = unhex("602A17184E060753010A277F1B115802100F5508184F3B1D09590D3C590B0E1E4E4710500B7E")
    xor(key, data)

    # Result
    # b'\\Microsoft\\Credentials\\credHelper.dll\x00'
    ```

    You can also use a monitoring tool like `procmon` to see immediately what is the dumped file.

3. Finally, the binary will decrypt another string from `unk_140019970`, will get the address of a function with that name from our `credHelper.dll`, and invoke it.

    ```python
    xor(key, unhex("780B1229590E1D4F131B096F0C064A020C7B"))
    # Result
    # b'DllRegisterServer\x00'
    ```

Sound like we're going into yet another binary!

### credHelper.dll

This DLL has quite a lot of code in it, but no need to think about it, we're heading straight to `DllRegisterServer`.

```python
HRESULT __stdcall DllRegisterServer()
{
  sub_180003220(Filename, 0i64, 512i64);
  sub_180003220(sz, 0i64, 258i64);
  sub_180003220(v17, 0i64, 498i64);
  v8 = 7471205;
  *(_OWORD *)Data = xmmword_180017790;
  v9 = 0;
  v11 = 116;
  *(_OWORD *)v10 = xmmword_1800177A8;
  v19 = 0;
  GetModuleFileNameW(hModule, Filename, 0xFFu);
  v0 = -1i64;
  do
    ++v0;
  while ( Filename[v0] );
  v1 = 2 * v0 + 2;
  StringFromGUID2(&rguid, sz, 129);
  v2 = &v13;
  v15 = 6029380;
  v16 = 0;
  *(_QWORD *)SubKey = 0x490053004C0043i64;
  do
    ++v2;
  while ( *v2 );
  v3 = 0i64;
  do
  {
    v4 = sz[v3];
    v2[v3++] = v4;
  }
  while ( v4 );
  v5 = RegCreateKeyExW(HKEY_CLASSES_ROOT, SubKey, 0, 0i64, 0, 0xF003Fu, 0i64, &hKey, 0i64);
  if ( v5
    || (v5 = RegSetValueExW(hKey, 0i64, 0, 1u, Data, 0x16u)) != 0
    || (v5 = RegCreateKeyExW(hKey, L"InProcServer32", 0, 0i64, 0, 0xF003Fu, 0i64, &phkResult, 0i64)) != 0
    || (v5 = RegCreateKeyExW(hKey, L"Config", 0, 0i64, 0, 0xF003Fu, 0i64, &v22, 0i64)) != 0
    || (v5 = RegSetValueExW(phkResult, 0i64, 0, 1u, (const BYTE *)Filename, v1)) != 0
    || (v5 = RegSetValueExW(phkResult, L"ThreadingModel", 0, 1u, v10, 0x14u)) != 0 )
  {
    result = (unsigned __int16)v5 | 0x80070000;
    if ( v5 <= 0 )
      result = v5;
  }
  else
  {
    RegSetValueExW(v22, L"Password", 0, 1u, (const BYTE *)&v19, 2u);
    RegSetValueExW(v22, L"Flag", 0, 1u, (const BYTE *)&v19, 2u);
    result = 0;
  }
  return result;
}
```

This function does what a lot of `DllRegisterServer` function do; creating a key under the classes root in the register, defining their configuration and their server type and threading model. But after that, we have something that seems very interesting. `credHelper` creates more registry keys there - `Password` and `Flag`. Let's try to see if this COM server does operate on those keys somewhere in the code.

{{< image src="images/image_1.png" >}}

{{< image src="images/image_2.png" >}}

We indeed see more functions that use those strings. Let's examine those. Our assumption now is that we can set an appropriate password, and then the COM server will decrypt the flag using the password and set it flag for us. Let's rename `sub_18000153C` to `GetPassword` and `sub_1800016D8` to `SetFlag`. We have a few options to approach this. One is to simply execute the functions and let them do their thing, which will get us the flag. This can be done using IDA's [Appcall](https://www.hex-rays.com/blog/practical-appcall-examples/), or even by writing a simple C program that gets the function pointers based on their offset in the DLL and invokes them.

Another option, which we chose here, is to understand what those two functions are doing and decrypt the flag using the known password

### Understanding `GetPassword` and `SetFlag`

```cpp
__int64 __fastcall GetPassword(__int64 a1, _WORD *a2)
{
  sub_180003220(pvData, 0i64, 1040i64);
  sub_180003220(SubKey, 0i64, 512i64);
  sub_180003220(sz, 0i64, 258i64);
  StringFromGUID2(&rguid, sz, 129);
  wsprintfW(SubKey, L"%s\\%s\\%s", L"CLSID", sz, L"Config");
  v3 = 0;
  if ( RegGetValueW(HKEY_CLASSES_ROOT, SubKey, L"Password", 2u, 0i64, pvData, &pcbData) )
    return 0x80004005;
  if ( pcbData <= 2 )
    return 0x80004005;
  v4 = sub_180005A2C(v20, pvData, 260i64);
  if ( v4 == 260 || v4 == -1 )
    return 0x80004005;
  v5 = (char *)(a2 + 1);
  *a2 = 0;
  v6 = a2 + 1;
  LOBYTE(v7) = 0;
  v8 = 0;
  v9 = 0;
  v10 = 0x100i64;
  do
    *v6++ = v9++;
  while ( v9 < 0x100 );
  v11 = v4;
  v12 = 0i64;
  v13 = v5;
  do
  {
    v14 = *v13;
    v15 = v12 + 1;
    v16 = v20[v12];
    v12 = 0i64;
    v7 = (unsigned __int8)(v7 + *v13 + v16);
    *v13++ = v5[v7];
    v5[v7] = v14;
    v17 = v8 + 1;
    v8 = 0;
    if ( v15 < v11 )
      v8 = v17;
    if ( v15 < v11 )
      v12 = v15;
    --v10;
  }
  while ( v10 );
  return v3;
}
```

When trying to identify an encryption/decryption algorithm, it's always a good idea to search for known crypto constants. A great way to do that is using the IDA plugin - *[FindCrypt](https://github.com/polymorf/findcrypt-yara).* Having said that, in this case, there are no such constants. What we do see in this function is, first of all, the usage of `RegGetValueW` to read our password from the registry. Secondly, we see two loops that iterate `0x100` times each. At this point, we should immediately suspect that RC4 is involved. If you didn't realize that, we encourage you to read this [article](https://blog.talosintelligence.com/2014/06/an-introduction-to-recognizing-and.html) published by Talos on how to identify RC4 in malware. It explains quite thoroughly how this encryption method works and what to look for while reverse engineering. The part we see here looks like the creation of the substitution box for the decryption.

```cpp
__int64 __fastcall SetFlag(__int64 a1, unsigned __int8 *a2)
{
  v3 = -2147467259;
  sub_180003220(SubKey, 0i64, 512i64);
  sub_180003220(sz, 0i64, 258i64);
  v14 = 0i64;
  v15 = 0;
  v16 = 0;
  *(_OWORD *)Source = 0i64;
  v13 = 0i64;
  sub_180003220(Data, 0i64, 180i64);
  v4 = *a2;
  v5 = 0i64;
  v6 = a2[1];
  do
  {
    v7 = a2[++v4 + 2];
    v6 += v7;
    v8 = a2[v6 + 2];
    a2[v4 + 2] = v8;
    a2[v6 + 2] = v7;
    Source[v5] = byte_18001A9F0[v5] ^ a2[(unsigned __int8)(v7 + v8) + 2];
    ++v5;
  }
  while ( v5 < 0x2C );
  *a2 = v4;
  a2[1] = v6;
  v9 = mbstowcs(Data, Source, 0x2Dui64);
  v10 = v9;
  if ( v9 != -1 && v9 != 45 )
  {
    StringFromGUID2(&rguid, sz, 129);
    wsprintfW(SubKey, L"%s\\%s\\%s", L"CLSID", sz, L"Config");
    if ( !RegOpenKeyExW(HKEY_CLASSES_ROOT, SubKey, 0, 0x20006u, &hKey) )
    {
      RegSetValueExW(hKey, L"Flag", 0, 1u, (const BYTE *)Data, 2 * v10);
      v3 = 0;
    }
  }
  return v3;
}
```

In `SetFlag`, we see a loop that uses constant bytes from `byte_18001A9F0`. After the loop, the result of this decryption is written to our `Flag` registry key, using `RegSetValueEx`. This must be our encrypted flag!

Let's apply RC4 decryption to these bytes and see if we identified the algorithm correctly.

```python
from malduck import rc4, unhex

flag = unhex("1656BC869EE1D10265C1699F100AACC1F6E9FDB4CD224A359C1273BD2B1054B943D2139A8465ADB0BF5A811000000000")
key = b"H@n $h0t FiRst!"
rc4(key, flag)

# Result
# b'S0_m@ny_cl@sse$_in_th3_Reg1stry@flare-on.com\xe8\x9d\x92A'
```

Got it! The flag is `S0_m@ny_cl@sse$_in_th3_Reg1stry@flare-on.com`.