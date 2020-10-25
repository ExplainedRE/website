---
title: "Flare-On 7 — 08 Aardvark"
date: 2020-10-23T21:29:48+03:00
draft: false
author: "explained.re"
tags: ["flare-on"]
categories: ["write-up", "ctf"]

lightgallery: true

---

{{< admonition info "Challenge Description" >}}
Expect difficulty running this one. I suggest investigating why each error is occurring. Or not, whatever. You do you.
{{< /admonition >}}

## Getting Started

The eighth challenge this year was surprisingly easy, a good rest before the hardest challenges in the final. In it, we get `ttt2.exe` which is a 64-bit Windows binary.

```visual-basic
$ file ttt2.exe 
ttt2.exe: PE32+ executable (GUI) x86-64, for MS Windows
```

When opening the file in IDA, the flow is pretty straight forward. The `WinMain` function verifies that the environment is suitable for executing the challenge. First, it gets a path to a temporary folder and checks whether it can bind to a file named `%TEMP%/496b9b4b.ed5`.

```c
if ( GetTempPathA(0x105u, temp_path) )
    SetCurrentDirectoryA(temp_path);
  if ( WSAStartup(WINSOCK_VERSION, &WSAData) )
  {
    MessageBoxA(0i64, "Error initializing Winsock", "Error", 0x10u);
    goto LABEL_17;
  }
  ... [ snip ] ...
  wsprintfA(&name[2], "%s", "496b9b4b.ed5");
  DeleteFileA("496b9b4b.ed5");
  v8 = socket(1, 1, 0);
  v6 = v8;
  if ( v8 == -1i64 )
  {
    MessageBoxA(0i64, "socket failed", "Error", 0x10u);
    v9 = "Error creating Unix domain socket";
LABEL_16:
    MessageBoxA(0i64, v9, "Error", 0x10u);
    goto LABEL_17;
  }
  if ( bind(v8, (const struct sockaddr *)name, 110) == -1 )
  {
    v10 = "bind failed";
  }
```

The flow is then creating a COM object and call a function named `sub_1400012B0`. This function begins with creating a new `.tmp` file in the %TEMP% directory. Then reads a resource name "300" from its resource section, and writes it to the temp file.

```c
if ( !GetTempFileNameA(".", prefix, 0, FileName) )
  {
    v2 = "GetTempFileName failed";
    goto LABEL_7;
  }
  wsprintfA(Str, "%s", FileName);
  *strchr(Str, '\\') = '/';
  hTempFile = (__int64)CreateFileA(FileName, 0x40000000u, 0, 0i64, 3u, 0x80u, 0i64);
  if ( !hTempFile )
  {
    v2 = "CreateFile failed";
    goto LABEL_7;
  }
  hResource = FindResourceA(0i64, (LPCSTR)300, (LPCSTR)0x100);
  c_hResource = hResource;
  if ( !hResource )
  {
    v2 = "FindResource failed";
LABEL_7:
    MessageBoxA(0i64, v2, "Error", 0x10u);
    c_hrsrc = *(void **)NumberOfBytesWritten;
    if ( !*(_QWORD *)NumberOfBytesWritten )
      goto LABEL_16;
    goto LABEL_15;
  }
  size = SizeofResource(0i64, hResource);
  hrsrc = LoadResource(0i64, c_hResource);
  c_hrsrc = hrsrc;
  if ( !hrsrc )
  {
    MessageBoxA(0i64, "LockResource failed", "Error", 0x10u);
    goto LABEL_16;
  }
  buf = LockResource(hrsrc);
  if ( WriteFile((HANDLE)hTempFile, buf, size, NumberOfBytesWritten, 0i64) && NumberOfBytesWritten[0] == size )
  {
```

## Dumping the resource

What is this resource that was saved? We can check it using different PE Resource editors. We chose to use radare2 for this.

First, open the binary in radare2 and use the `iR` command to list its resources.

```c
$ r2 ttt2.exe 

[0x1400027bc]> iR
Resource 0
  name: BOARD
  timestamp: Tue Jan  1 00:00:00 1980
  vaddr: 0x140023100
  size: 328
  type: DIALOG
  language: LANG_ENGLISH
Resource 1
  name: 1
  timestamp: Tue Jan  1 00:00:00 1980
  vaddr: 0x140025a48
  size: 585
  type: MANIFEST
  language: LANG_ENGLISH
Resource 2
  name: 300
  timestamp: Tue Jan  1 00:00:00 1980
  vaddr: 0x140023248
  size: 10K
  type: UNKNOWN (256)
  language: LANG_ENGLISH

```

We see that there are 3 resource files, interesting! The first one called "BOARD" (a DIALOG), the second is named "1" (a MANIFEST) and the third is our target resource — "300". Let's print some bytes from the resource "300" and see what's in there.

```c
[0x1400027bc]> px @ 0x140023248
- offset -    0 1  2 3  4 5  6 7  8 9  A B  C D  E F  0123456789ABCDEF
0x140023248  7f45 4c46 0201 0100 0000 0000 0000 0000  .ELF............
0x140023258  0300 3e00 0100 0000 a013 0000 0000 0000  ..>.............
0x140023268  4000 0000 0000 0000 4021 0000 0000 0000  @.......@!......
0x140023278  0000 0000 4000 3800 0900 4000 1b00 1a00  ....@.8...@.....
0x140023288  0600 0000 0400 0000 4000 0000 0000 0000  ........@.......
0x140023298  4000 0000 0000 0000 4000 0000 0000 0000  @.......@.......
0x1400232a8  f801 0000 0000 0000 f801 0000 0000 0000  ................
```

Interesting! It seems like the program is dropping a Linux ELF file to the file. And it doesn't look like it was applied with any kind of encryption on it. How does a Windows executable run this Linux ELF binary? This made us curious.

Let's dump this ELF to a file so we can look at it later. Using radare2's `wtf` (Write To File) command we can specify the resource length and dump it.

```c
[0x1400027bc]> wtf rsrc_300.elf 10240 @ 0x140023248
Dumped 10240 bytes from 0x140023248 into rsrc_300.elf
```

## Game board UI

Back to our analysis. After saving the ELF file to a temporary file, the program calls `sub_140001930`. In this function, we can see checks for our OS version. Each version has a different function to handle it. These handler functions will use `CreateLxProcecs` COM method to execute the Linux binary is WSL, the Windows Subsystem for Linux. According to one of the error messages, we can see that we need to have WSL version 1 installed. Luckily, we do.

When the program is executing the ELF file using COM, we are back to the `WinMain` function and continue the execution of the program. First, it looks like a connection was established, using the `accept` function and then a call to create a dialog using the `BOARD` resource we saw earlier.

```c
s = accept(c_hsock, 0i64, 0i64);
hModule = GetModuleHandleA(0i64);
hWnd_ = CreateDialogParamA(hModule, "BOARD", 0i64, (DLGPROC)DialogFunc, 0i64);
```

When looking at the `DialogFunc` function, it looks like a board game that is handling commands from a server (`send`, `recv`). It seems like the board is built out of 9 space characters (0x20).

```c
14000123A  mov     rax, 2020202020202020h
140001244  xor     r9d, r9d        ; flags
140001247  mov     cs:board, rax
```

A closer looks at the function suggests that it is a "front end" GUI for a game, but that the processing itself done in the Linux ELF. When a user clicks different buttons, the operations are sent to the ELF binary through sockets, and then it replies with results. Since the ELF seems to contain valuable information, it's time to open it. But before it, let's open the game and see how it looks like when running it.

{{< image src="images/image.png" >}}

It looks like a simple Tic-Tac-Toc game. The spaces we saw earlier must be the annotation for an empty cell. The program always takes the first turn and put an X in the middle cell. It looks like we need to win the game by placing "O" in it. Game on.

## Checking the ELF server file

The Linux ELF file is a very simple game back end. After establishing a connection to the server it builds an empty game and sends it to the client (the EXE file). The EXE is showing the game, and the Server is processing the current state of the board. If it's the turn of the "O", it uses the `recv` function to get the coordinates of where the user placed "O". When it's X's turn, the server looks for the best cell to place X in, and send an updated board to the Windows process. After each turn, the server validates if there is a winner. As our goal is to win, we wanted to check how can we bypass the different checks.

At the very beginning of the program, we saw that the board is initialized with empty spaces:

```c
0B67  lea     rbx, g_board
...
0B98  mov     rax, 2020202020202020h
0BA2  mov     [rbx], rax
0BA5  mov     cs:g_board+8, 20h
```

It caught us by surprise to see that there is no enforcing of an empty board in both the server and the Windows application. In fact, we wondered if we can patch the default empty board of nine spaces — empty cells — and replace it with a board with 'O'. If we will able to do this, the server will try to check if there is a winner and will see that "O" wins. Let's try to do this.

### Patching the ELF resource

What we want to do is to take the instruction at `0xb98` and patch it with O chars — `0x4f`. We need to remember that we can't just patch the dumped file, because it should reside in the resources of the Windows executable. Luckily, the resource wasn't encrypted in any way so we can simply patch the bytes in the resource section itself.

First, let's copy `ttt2.exe` to a new file that we can patch, and open it in radare2 in write mode enabled (`-w`).

```c
$ cp ttt2.exe ttt2_patched.exe 
$ r2 -w ttt2_patched.exe
```

Then, we can navigate to the "300" resource and from there, we can go `0xb98` bytes forward, to the `mov` instruction. Radare2 named the resource for us as "resource.2".

```c
[0x1400027bc]> s resource.2 + 0xb98
[0x140023de0]> pd 1
0x140023de0      48b82020202020202020   movabs rax, 0x2020202020202020 ; '        '
```

Good, we are in the right place. All we need is two "O"s so it will be easy for us to click the third one and complete a row. Let's patch the bytes of this instruction from `48b82020`to `48b84f4f` using the `wx` command.

```c
[0x140023de0]> wx 48b84f4f
[0x140023de0]> pd 1
0x140023de0      48b84f4f202020202020   movabs rax, 0x2020202020204f4f ; 'OO      '
```

Alright, let's close radare2 and start our patched process. Running the program, we can see that the first two cells are filled with "O". These are the cells that we patched, so far so good.

{{< image src="images/image_1.png" >}}

This is our turn now, and thus we click on the cell at the top right corner to fill it with "O". The message box with the flag will immediately appear on the screen:

{{< image src="images/image_2.png" >}}

**Flag:** `c1ArF/P2CjiDXQIZ@flare-on.com`

---