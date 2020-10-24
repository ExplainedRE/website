---
title: "Flare-On7 — 02 Garbage"
date: 2020-10-23T21:29:42+03:00
draft: false
author: "explained.re"
tags: ["flare-on"]
categories: ["write-up", "ctf"]

lightgallery: true

---
{{< admonition info "Challenge Description" >}}

One of our team members developed a Flare-On challenge but accidentally deleted it. We recovered it using extreme digital forensic techniques but it seems to be corrupted. We would fix it but we are too busy solving today's most important information security threats affecting our global economy. You should be able to get it working again, reverse engineer it, and acquire the flag.
{{< /admonition >}}

## Triage

In the second challenge of Flare-On7 we are given a small binary file with the `.exe` extension. As usual, let's start by a quick triaging and execute the `file` command on `garbage.exe` to get more information about it.

```bash
$ file garbage.exe 
garbage.exe: PE32 executable (console) Intel 80386, for MS Windows, UPX compress
```

The `file` commands tell us that we have a 32-bit Windows executable that is compressed with the popular [UPX](https://en.wikipedia.org/wiki/UPX) packer.

## Unpacking the program using UPX

Luckily, whenever we have a UPX  packed executable, we can simply use the official `upx` program to unpack it.

```bash
$ upx -d garbage.exe -o garbage_unpacked.exe
                       Ultimate Packer for eXecutables
                          Copyright (C) 1996 - 2020
UPX git-d7ba31+ Markus Oberhumer, Laszlo Molnar & John Reiser   Jan 23rd 2020

        File size         Ratio      Format      Name
   --------------------   ------   -----------   -----------
upx: garbage.exe: OverlayException: invalid overlay size; file is possibly corrupt

Unpacked 1 file: 0 ok, 1 error.
```

Oh no, UPX threw an error at us: "OverlayException: invalid overlay size; file is possibly corrupt". Since the output did not provide a lot of meaningful data, let's check online and see what causes this error.  Thankfully, UPX is open source so we can check the [original source code](https://github.com/upx/upx/blob/d7ba31cab8ce8d95d2c10e88d2ec787ac52005ef/src/packer.cpp#L574-L583) and check why this error is showed.

```cpp
void Packer::checkOverlay(unsigned overlay)
{
    if ((int)overlay < 0 || (off_t)overlay > file_size)
        throw OverlayException("invalid overlay size; file is possibly corrupt");
    ...
```

Looks pretty simple. From reading the code we can understand that the calculated overlay size is bigger than the file size. The overlay size is calculated by reading the PE headers in the executable, while the file size is the actual file on disk. Thus, we can either fix the headers or simply increase the file size and feed it with appended null bytes. Hopefully, with enough null bytes we will be able to satisfy UPX so it will unpack the file for us.

```bash
# Copy the binary
$ cp garbage.exe modified_garbage.exe

# Append 1000 null-bytes to its end
$ python -c "print('\x00'*1000)" >> modified_garbage.exe

# Unpack it using UPX
$ upx -d modified_garbage.exe -o garbage_unpacked.exe
                       Ultimate Packer for eXecutables
                          Copyright (C) 1996 - 2020
UPX git-d7ba31+ Markus Oberhumer, Laszlo Molnar & John Reiser   Jan 23rd 2020

        File size         Ratio      Format      Name
   --------------------   ------   -----------   -----------
     79629 <-     41741   52.42%    win32/pe     garbage_unpacked.exe

Unpacked 1 file.
```

## Quick analysis in Cutter

Great! So UPX was able to unpack the file now, and we can begin its analysis. Let's open this file in  [Cutter](https://cutter.re/) and see what is waiting for us.

{{< image src="images/image.png" >}}

Now that the binary is opened, we can go to the `main` function which is the place we usually start our analysis from. The `main` function is very small and contains 3 blocks.

{{< image src="images/image_1.png" >}}

When looking at the function, we see that it builds two arrays on the stack, and then xor each of them with a different key. The results will be written to a file.

Luckily, the code is very simple so we can implement it manually in python. But why should we work hard? We already have this Windows executable opened in Cutter on Linux, so instead of understanding the instructions, we can use Cutter's emulation feature to emulate them, and just inspect the stack\registers and wait for the results. As simple as that? Yes. Well, almost - there is one thing we need to care for, Cutter can't emulate API calls to system libraries, so we need to `NOP` the call to `CreateFileA` at `0x00401166`.

## Emulating the binary on Cutter for Linux

In Cutter disassembly view, click on the top address of the main function and choose Debug→Start emulation from the Debug menu.

{{< image src="images/image_2.png" >}}

Then, go to the call to `CreateFileA` at `0x00401166` and right-click. From the context menu choose "Edit → NOP Instruction".

{{< image src="images/image_3.png" >}}

In the dialog that opened, choose "Enable Cache Mode". This will make sure that the file on disk stays the same, and only the memory loaded to Cutter will be changed.

Now it should look like this:

```bash
0x00401160      push    dword [lpFileName] ; LPCSTR lpFileName
0x00401166      nop
0x00401167      nop
0x00401168      nop
0x00401169      nop
0x0040116a      nop
0x0040116b      nop
0x0040116c      lea     ecx, [lpFileName]
```

Now, let's open the Register References view (Debug → View → Register References). This view will show us some interesting values that are referenced by the registers. Now we can use step over the instruction in Main, until we find what is the content that will be written to the flag.

The following gif shows how we emulate each instruction until the flag appears in both the stack and the registers. We can also learn that the file to be written is a vbs script `sink_the_tanker.vbs`.

{{< image src="images/get_flag.gif" >}}

```bash
MsgBox("Congrats! Your key is: C0rruptGarbag3@flare-on.com")
```

## The Python solution

For those of you who prefer the Python way, we have a code ready for you:

```bash
from malduck import xor

buf1 = b"8\x0E\x02;\x19;\x1B4\x1B\f#>3\b\x11B9\x12\x1Es"
key1 = b"KglPFOsQDxBPXmclOpmsdLDEPMRWbMDzwhDGOyqAkVMRvnBeIkpZIhFznwVylfjrkqprBPAdPuaiVoVugQAlyOQQtxBNsTdPZgDH "
print(xor(key1, buf1))

buf2 = b"##3,\x0E?dI\n\x1E\n\x04#\x16\x02\x1ADf\b$2\x11t,*-B\x0F>Pd\r]\x04\x1B\x17\x166\x03\x054 \t\bc!$\x0E\x15\x144X\x1A)y:\x00\x00"     
key2 = b"nPTnaGLkIqdcQwvieFQKGcTGOTbfMjDNmvibfBDdFBhoPaBbtfQuuGWYomtqTFqvBSKdUMmciqKSGZaosWCSoZlcIlyQpOwkcAgw "       
print(xor(key2, buf2))

# Results:
# b'sink_the_tanker.vbs\x00'
# b'MsgBox("Congrats! Your key is: C0rruptGarbag3@flare-on.com'
```