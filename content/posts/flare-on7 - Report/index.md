---
title: "Flare-On 7 - 04 Report"
date: 2020-10-23T21:29:42+03:00
draft: false
author: "explained.re"
tags: ["flare-on"]
categories: ["write-up", "ctf"]

lightgallery: true

---

{{< admonition info "Challenge Description" >}}
Nobody likes analysing infected documents, but it pays the bills. Reverse this macro thrill-ride to discover how to get it to show you the key.
{{< /admonition >}}

## Getting Started

In the 4th challenge of Flare-On7, we are given a single Excel file named "report.xls". As in every challenge, let's run the `file` command on it and verify that the extension makes sense.

```bash
$ file report.xls 
report.xls: Composite Document File V2 Document, Little Endian, Os: Windows, Version 10.0, Code page: 1252, 0x17: 1048576CDFV2 Microsoft Excel
```

When opening this file in LibreOffice Calc, we see the following message box. It tells us that the document has macro insides and that we should be careful while handling them as they might contain a virus — scary!

{{< image src="images/image.png" >}}

## Extracting the Macros

Thankfully, we can use `olevba` from [oletools](http://www.decalage.info/python/oletools) to extract macros from the file. When running `olevba` on our file, we get a huge output that contains: Extracted macros, huge hexadecimal blobs, disassembled p-codes, and more. Usually, we would want to focus our attention on the end of the output as it contains a summary.

```bash
$ olevba report.xls
FILE: report.xls
Type: OLE

...
... [truncated for readibilty] ...
...

+----------+--------------------+---------------------------------------------+
|Type      |Keyword             |Description                                  |
+----------+--------------------+---------------------------------------------+
|AutoExec  |Auto_Open           |Runs when the Excel Workbook is opened       |
|AutoExec  |Workbook_Open       |Runs when the Excel Workbook is opened       |
|Suspicious|GetObject           |May get an OLE object with a running instance|
|Suspicious|CreateObject        |May create an OLE object                     |
|Suspicious|Environ             |May read system environment variables        |
|Suspicious|Open                |May open a file                              |
|Suspicious|Write               |May write to a file (if combined with Open)  |
|Suspicious|Put                 |May write to a file (if combined with Open)  |
|Suspicious|Lib                 |May run code from a DLL                      |
|Suspicious|Chr                 |May attempt to obfuscate specific strings    |
|          |                    |(use option --deobf to deobfuscate)          |
|Suspicious|Xor                 |May attempt to obfuscate specific strings    |
|          |                    |(use option --deobf to deobfuscate)          |
|Suspicious|Binary              |May read or write a binary file (if combined |
|          |                    |with Open)                                   |
|Suspicious|Hex Strings         |Hex-encoded strings were detected, may be    |
|          |                    |used to obfuscate strings (option --decode to|
|          |                    |see all)                                     |
|IOC       |wininet.dll         |Executable file name                         |
|IOC       |winmm.dll           |Executable file name                         |
|Suspicious|VBA Stomping        |VBA Stomping was detected: the VBA source    |
|          |                    |code and P-code are different, this may have |
|          |                    |been used to hide malicious code             |
+----------+--------------------+---------------------------------------------+

```

The summary table gives us a very nice summary of what the file does. The things that caught our attention are:

1. Writing the file using `Open` and `Write`
2. Usage of `Xor`
3. Handling of binary data
4. Hard-coded hex strings (well, it was not easy to miss these)
5. VBA Stomping

These behaviors are common in malware and CTF challenges, so we were not surprised. That said, `olevba` told us that it detected the VBA Stomping technique in this file. This means that the content it printed on the screen isn't enough, as the real VBA code might be different than shown.

To read more about VBA stomping we recommend visiting [https://vbastomp.com/](https://vbastomp.com/)

The output of `olevba` was very important to us, and now we know that we need to use another tool, one that deals better with stomped macros — [pcode2code](https://github.com/Big5-sec/pcode2code).

```bash
$ pcode2code report.xls -o macros.vba
```

## Analyzing the Macros

From a quick look at the output, it seems like it is slightly obfuscated, nothing we won't be able to handle. Let's slowly go through the functions in the macro and try to understand them.

First, we see that the function to be executed when the document is opened called `folderol`.

```vb
Sub Workbook_Open()
  Sheet1.folderol
End Sub

Sub Auto_Open()
  Sheet1.folderol
End Sub
```

Naturally, this will be the function we will start to analyzed. It begins with variable declaration, and then `Split` a string named `F.L` by a dot delimiter. The split array is assigned to a variable named `onzo.`

```vb
Function folderol(id_FFFE As Variant)
        Dim wabbit As Byte
        Dim fn As Integer: fn = FreeFile
        Dim onzo As String
        Dim mf As String
        Dim xertz As Variant
        Dim buff(0 To 7) As Byte
        
        onzo = Split(F.L, ".")
```

Where did this `F.L` came from? When searching for `F.L` in the output of the program we ran, we find nothing. We did find `F` though, and it is the name of a form. Looking at LibreOffice Calc again, we can see what `F.L` is. It is a label in a form.

{{< image src="images/image_1.png" >}}

Actually, the content of this label is also shown in the results of `olevba` under `F/o`. The value of this label is shown below. As you can see it is separated by dots.

```bash
9655B040B64667238524D15D6201.B95D4E01C55CC562C7557405A532D768C55FA12DD074DC697A06E172992CAF3F8A5C7306B7476B38.C555AC40A7469C234424.853FA85C470699477D3851249A4B9C4E.A855AF40B84695239D24895D2101D05CCA62BE5578055232D568C05F902DDC74D2697406D7724C2CA83FCF5C2606B547A73898246B4BC14E941F9121D464D263B947EB77D36E7F1B8254.853FA85C470699477D3851249A4B9C4E.9A55B240B84692239624.CC55A940B44690238B24CA5D7501CF5C9C62B15561056032C468D15F9C2DE374DD696206B572752C8C3FB25C3806.A8558540924668236724B15D2101AA5CC362C2556A055232AE68B15F7C2DC17489695D06DB729A2C723F8E5C65069747AA389324AE4BB34E921F9421.CB55A240B5469B23.AC559340A94695238D24CD5D75018A5CB062BA557905A932D768D15F982D.D074B6696F06D5729E2CAE3FCF5C7506AD47AC388024C14B7C4E8F1F8F21CB64
```

Then, the function checks for internet connection and shows an alert if no internet connection was found. The program continues and assign to a variable named `fudgel` the value of `GetObject(rigmarole(onzo(7)))`. This means, that we need to analyze `rigmarole` in order to understand what it does with the 8th item in the `onzo` array.

```vb
      Function rigmarole(es As String, id_FFFE As String) As String
        Dim furphy As String
        Dim c As Integer
        Dim s As String
        Dim cc As Integer
        furphy = ""
        For i = 1 To Len(es) Step 4
          c = CDec("&H" & Mid(es, i, 2))
          s = CDec("&H" & Mid(es, i + 2, 2))
          cc = c - s
          furphy = furphy + Chr(cc)
        Next i
        rigmarole = furphy
      End Function
```

 

`rigmarole` is a very simple function. Basically, it iterates the array and takes two pairs of chars. Each pair is considered hexadecimal and converted to a decimal value. The second pair is then subtracted from the first pair. The result is converted to a char using `Chr` and added to a string  of chars. Finally, the string is returned. Easy, right? We can see that this function is used quite a bit in the VBA code, so we can start by executing it on every item in `onzo`. Let's use Python for this

```python
from malduck import chunks

onzo = "9655B040B64667238524D15D6201.B95D4E01C55CC562C7557405A532D768C55FA12DD074DC697A06E172992CAF3F8A5C7306B7476B38.C555AC40A7469C234424.853FA85C470699477D3851249A4B9C4E.A855AF40B84695239D24895D2101D05CCA62BE5578055232D568C05F902DDC74D2697406D7724C2CA83FCF5C2606B547A73898246B4BC14E941F9121D464D263B947EB77D36E7F1B8254.853FA85C470699477D3851249A4B9C4E.9A55B240B84692239624.CC55A940B44690238B24CA5D7501CF5C9C62B15561056032C468D15F9C2DE374DD696206B572752C8C3FB25C3806.A8558540924668236724B15D2101AA5CC362C2556A055232AE68B15F7C2DC17489695D06DB729A2C723F8E5C65069747AA389324AE4BB34E921F9421.CB55A240B5469B23.AC559340A94695238D24CD5D75018A5CB062BA557905A932D768D15F982D.D074B6696F06D5729E2CAE3FCF5C7506AD47AC388024C14B7C4E8F1F8F21CB64"

onzo = onzo.split('.')

onzo_decoded = []

for o in onzo:
    # Split each item to a pair of two characters
    es = chunks(o, 2) 
    output = ""
    # A for loop will be more readable than a list comprehension 
    for i in range(0, len(es), 2):
        first = int(es[i],16)
        second = int(es[i+1], 16)
        output += chr(first - second)
    onzo_decoded.append(output) 

print(onzo_decoded)
```

The decoded array looks like this:

```python
['AppData',
 '\\Microsoft\\stomp.mp3',
 'play ',
 'FLARE-ON',
 'Sorry, this machine is not supported.',
 'FLARE-ON',
 'Error',
 'winmgmts:\\\\.\\root\\CIMV2',
 'SELECT Name FROM Win32_Process',
 'vbox',
 'WScript.Network',
 '\\Microsoft\\v.png']
```

Looking at these strings we can see a hint for VBA stomping (`stomp.mp3`), we can assume it iterates through the processes using `WMI` and probably checks the for VM existence (`vbox`). We can also see `v.png` that will probably be used as an output file, and of course — we see a couple of `FLARE-ON`. A very nice trick to do in such cases is to replace every instance of `rigmarole(onzo(number))` with the value of the string itself. Let's do it:

```python
content = '' 
with open("macros.vba", "r") as f: 
    content = f.read() 

for idx, v in enumerate(onzo_decoded): 
    content = content.replace(f"rigmarole(onzo({idx}))", f"\"{v}\"")    

with open("macros.vba", "w") as f: 
    f.write(content)
```

Now it is much easier to read the content of the macros.

Moving forward, we see that the script is checking all the processes for the existence of VM related process names:

```vb
      Set fudgel = GetObject("winmgmts:\\.\root\CIMV2")
        Set twattling = fudgel.ExecQuery("SELECT Name FROM Win32_Process", , 48)
        For Each p In twattling
          Dim pos As Integer
          pos = Instr(LCase(p.Name), "vmw") + Instr(LCase(p.Name), "vmt") + Instr(LCase(p.Name), "vbox")
          If pos > 0 Then
            MsgBox "Sorry, this machine is not supported.", vbCritical, "Error"
            End
          End If
        Next
```

The code is then creating a `Network` object and checks if our UserDomain name is `FLARE-ON`. If it is not, the script is raising an error and a message box. Most likely, by renaming our UserDomain to "FLARE-ON" we can solve, or at least make a big progress towards solving, the challenge. But we are on Linux, so let's work harder.

```vb
        Set groke = CreateObject("WScript.Network")
        firkin = groke.UserDomain
        If firkin <> "FLARE-ON" Then
          MsgBox "Sorry, this machine is not supported.", vbCritical, "Error"
          End
        End If
```

After this check, the program takes the `firkin` variable that contains "FLARE-ON", and reverse the order of characters to `NO-ERALF` and assign it to a buffer named `buff`. Then the program is calling a function named `canoodle` with the value of another label in the form `F`, `buff` and two other arguments.

```vb
        n = Len(firkin)
        For i = 1 To n
          buff(n - i) = Asc(Mid$(firkin, i, 1))
        Next
        
        wabbit = canoodle(F.T.Text, 2, 285729, buff)
```

Let's have a look at the `canoodle` function now. We renamed the variables to make the analysis easier. First, the function begins with a regular variable definition.

```vb
Function canoodle(f_label As String, decimal_2 As Integer, size As Long, NO_ERALF_array As Variant) As Append
  Dim quean As Long
  Dim index As Long
  Dim kerfuffle As Byte
  ReDim kerfuffle(size)
  quean = 0
```

Then, we have a very simple xor decryption. The script is iterating through the huge buffer from the `F` form, starting from the second byte and skipping two bytes at a time. The bytes are being XORd with `NO-ERALF`.

```vb
     For index = 1 To Len(f_label) Step 4
          kerfuffle(quean) = CByte("&H" & Mid(f_label, index + decimal_2, 2)) Xor NO_ERALF_array(quean Mod (UBound(NO_ERALF_array) + 1))
          quean = quean + 1
          If quean = UBound(kerfuffle) Then
            Exit For
          End If
      Next index
```

Let's dump this huge hex blob to a file and script the solution for this loop in python.

```python
from malduck import unhex, xor

# Read the huge blob of hex bytes from a file
data = unhex(open("encrypted.hex", "r").read())
# Create a byte string with every other byte starting from offset 1
second_stage = bytes([data[i] for i in range(1, len(data), 2)])
# XOR the bytes string with the key
xord = xor(b"NO-ERALF", second_stage)

# Save the results to a file
open('out.bin', 'wb').write(xord)

```

Let's run the program and check the value of `out.bin`:

```vb
$ file out.bin
out.bin: PNG image data, 600 x 310, 8-bit/color RGBA, non-interlaced
```

The `file` command told us it is a valid PNG file, let's open it in an image viewer and check it out:

{{< image src="images/image_2.png" >}}

We got the flag! Cool one.

Flag: `thi5_cou1d_h4v3_b33n_b4d@flare-on.com`

## VBA Stomping References

[https://vbastomp.com/](https://vbastomp.com/)

[https://github.com/Big5-sec/pcode2code](https://github.com/Big5-sec/pcode2code)