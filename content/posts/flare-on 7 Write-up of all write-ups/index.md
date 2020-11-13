---
title: "Flare-On 7 - Write-up of all write-ups"
date: 2020-11-01T19:09:19+02:00
draft: false
author: "explained.re"
tags: ["flare-on"]
categories: ["write-up", "ctf"]

lightgallery: true

toc:
  enable: false

---


# Intro

This is the write-up of all Flare-On 7 challenge write-ups. We assembled this list of the write-ups we found for the different challenges and wrote down the methods each challenge can be solved in. 

Found a write-up that we did not mention? Wrote a write-up and can't find it here? Send us a [Pull-Request](https://github.com/explainedre/website) on Github.

*This list will keep getting updates*

# Challenges

## 1 - fidler 🐍

1. Static
    1. Call `decode_flag` with the correct number - [explained.re](https://explained.re/posts/flare-on7-fidler/), [a](https://explained.re/posts/flare-on7-fidler/)[uthor✏️](https://www.fireeye.com/content/dam/fireeye-www/blog/pdfs/flareon7-challenge1-solution.pdf), [asuna amawaka](https://medium.com/insomniacs/journal-flareon7-part-1-ca675815f204), [@NotCoderL](https://github.com/LeoCodes21/ctf-writeups/tree/main/Flare-On%202020/01-fidler), [@arnaugamez](https://arnaugamez.com/blog/2020/10/23/writeup-flareon7-challenge1/)
    2. Guess correct input for `decode_flag` - [@demonslay335](https://www.youtube.com/watch?v=OpBXDZxc2DQ) (video)
2. Dynamic
    1. Cheat Engine
        1. Increase speed - [@bbaskin](https://twitter.com/bbaskin/status/1320028970528759809?s=20)
    2. Modify program
        1. `current_coins` > 100 billion - [@_graypanda](https://github.com/gray-panda/grayrepo/tree/master/2020_flareon/01_fidler), [@0xdf_](https://0xdf.gitlab.io/flare-on-2020/fidler), [@pawel_lukasik](https://www.youtube.com/watch?v=6I3P_2dcOcM)
        2. Cat click increase in 100 billion - [@xEHLE_](https://blog.p1.gs/#fidler), [@L3cr0f](https://github.com/L3cr0f/flare-on_2020/blob/master/1_Fidler/1_Fidler.md), [@AleeAmini](https://github.com/aleeamini/Flareon7-2020/tree/main/1)
    3. Play and win - [@g3rzi](https://eviatargerzi.medium.com/flare-on-7-2020-challenge-1-fidler-1db63d227b4f)

## 2 - garbage 🚮

1. Repair headers and manifest
    1. Execute -  [author✏️](https://www.fireeye.com/content/dam/fireeye-www/blog/pdfs/flareon7-challenge2-solution.pdf), [@74wny0wl](https://whitehatlab.eu/en/blog/writeup/flareon/2020/002-garbage/), [@xEHLE_](https://blog.p1.gs/#garbage), [@0xdf_](https://0xdf.gitlab.io/flare-on-2020/garbage)
2. Add junk and unpack
    1. Static
        1. XOR the strings - [explained.re](https://explained.re/posts/flare-on7-garbage/), [author✏️](https://www.fireeye.com/content/dam/fireeye-www/blog/pdfs/flareon7-challenge2-solution.pdf), [@_graypanda](https://github.com/gray-panda/grayrepo/tree/master/2020_flareon/02_garbage), [@0xdf_](https://0xdf.gitlab.io/flare-on-2020/garbage), [@NotCoderL](https://github.com/LeoCodes21/ctf-writeups/tree/main/Flare-On%202020/02-garbage), [@g3rzi](https://eviatargerzi.medium.com/flare-on-7-2020-challenge-2-garbage-c7f573df696a), [asuna amawaka](https://medium.com/insomniacs/journal-flareon7-part-1-ca675815f204), [@demonslay335](https://www.youtube.com/watch?v=wN4ZK-Ickpc) (video), [@L3cr0f](https://github.com/L3cr0f/flare-on_2020/blob/master/2_Garbage/2_Garbage.md)
        2. floss XORPlugin - [0xswitch](https://0xswitch.fr/CTF/flare-on-2020-how-not-to-solve-an-easy-reverse-challenge)
    2. Emulation
        1. Cutter - [explained.re](https://explained.re/posts/flare-on7-garbage/#emulating-the-binary-on-cutter-for-linux)
        2. Unicorn Engine - [0xswitch](https://0xswitch.fr/CTF/flare-on-2020-how-not-to-solve-an-easy-reverse-challenge)
        3. radare2's ESIL - [@arnaugamez](https://arnaugamez.com/blog/2020/10/24/writeup-flareon7-challenge2/)
3. Manual unpack - [@AleeAmini](https://github.com/aleeamini/Flareon7-2020/tree/main/2)

## 3 - wednesday 🐸

1. Dynamic
    1. Patch collision - [explained.re](https://explained.re/posts/flare-on7-wednesday/), [author✏️](https://www.fireeye.com/content/dam/fireeye-www/blog/pdfs/flareon7-challenge3-solution.pdf), [@74wny0wl](https://whitehatlab.eu/en/blog/writeup/flareon/2020/003-wednesday/), [@0xdf_](https://0xdf.gitlab.io/flare-on-2020/wednesday), [@AleeAmini](https://github.com/aleeamini/Flareon7-2020/tree/main/3), [@g3rzi](https://eviatargerzi.medium.com/flare-on-7-2020-challenge-3-wednesday-132e60858a0b), [@arnaugamez](https://arnaugamez.com/blog/2020/11/07/writeup-flareon7-challenge3/)
    2. Cheat Engine - [@xEHLE_](https://blog.p1.gs/#wednesday), [@demonslay335](https://www.youtube.com/watch?v=F3AEkaHs29c) (video), [@arnaugamez](https://arnaugamez.com/blog/2020/11/07/writeup-flareon7-challenge3/)
    3. Play and win - [@NotCoderL](https://github.com/LeoCodes21/ctf-writeups/tree/main/Flare-On%202020/03-wednesday)
    4. Patch required score - [asuna amawaka](https://medium.com/insomniacs/journal-flareon7-part-1-ca675815f204)
2. Static
    1. Decode binary flag from obstacles array - [author✏️](https://www.fireeye.com/content/dam/fireeye-www/blog/pdfs/flareon7-challenge3-solution.pdf), [@_graypanda](https://github.com/gray-panda/grayrepo/tree/master/2020_flareon/03_wednesday), [@L3cr0f](https://github.com/L3cr0f/flare-on_2020/blob/master/3_Wednesday/3_Wednesday.md), [@arnaugamez](https://arnaugamez.com/blog/2020/11/07/writeup-flareon7-challenge3/)

## 4 - Report 📄

1. Static
    1. pcode2code - [explained.re](https://explained.re/posts/flare-on7-report/), [author✏️](https://www.fireeye.com/content/dam/fireeye-www/blog/pdfs/flareon7-challenge4-solution.pdf), [@74wny0wl](https://whitehatlab.eu/en/blog/writeup/flareon/2020/004-report/), [@0xdf_](https://0xdf.gitlab.io/flare-on-2020/report), [@NotCoderL](https://github.com/LeoCodes21/ctf-writeups/tree/main/Flare-On%202020/04-report), [@_graypanda](https://github.com/gray-panda/grayrepo/tree/master/2020_flareon/04_report)
    2. pcodedmp - [@xEHLE_](https://blog.p1.gs/#report), [@g3rzi](https://eviatargerzi.medium.com/flare-on-7-2020-challenge-4-report-5f701d3a5968), [@L3cr0f](https://github.com/L3cr0f/flare-on_2020/blob/master/4_Report/4_Report.md)
    3. Educated guess and XOR with PNG header - [asuna amawaka](https://medium.com/insomniacs/journal-flareon7-part-1-ca675815f204), [@AleeAmini](https://github.com/aleeamini/Flareon7-2020/tree/main/4)

## 5 - TKApp 🐯

1. Run the flag getting routine with all the right inputs
    1. Python - [explained.re](https://explained.re/posts/flare-on7-tkapp/), [author✏️](https://www.fireeye.com/content/dam/fireeye-www/blog/pdfs/flareon7-challenge5-solution.pdf), [@NotCoderL](https://github.com/LeoCodes21/ctf-writeups/tree/main/Flare-On%202020/05-TKApp), [asuna amawaka](https://medium.com/insomniacs/journal-flareon7-part-1-ca675815f204), [@L3cr0f](https://github.com/L3cr0f/flare-on_2020/blob/master/5_TKApp/5_TKApp.md)
    2. C# - [@_graypanda](https://github.com/gray-panda/grayrepo/tree/master/2020_flareon/05_tkapp), [@74wny0wl](https://whitehatlab.eu/en/blog/writeup/flareon/2020/005-tkapp/), [@xEHLE_](https://blog.p1.gs/#tkapp), [@AleeAmini](https://github.com/aleeamini/Flareon7-2020/tree/main/5), [@g3rzi](https://eviatargerzi.medium.com/flare-on-7-2020-challenge-5-tkapp-d5192cf011f7)
2. Emulate the watch OS with winning conditions - [@0xdf_](https://0xdf.gitlab.io/flare-on-2020/tkapp)

## 6 - codeit 👩🏽‍💻

1. Static - [explained.re](https://explained.re/posts/flare-on7-codeit/), [author✏️](https://www.fireeye.com/content/dam/fireeye-www/blog/pdfs/flareon7-challenge6a-solution.pdf), [@_graypanda](https://github.com/gray-panda/grayrepo/tree/master/2020_flareon/06_codeit), [asuna amawaka](https://medium.com/insomniacs/journal-flareon7-part-1-ca675815f204), [@xEHLE_](https://blog.p1.gs/#codeit), [@NotCoderL](https://github.com/LeoCodes21/ctf-writeups/tree/main/Flare-On%202020/06-codeit), [@L3cr0f](https://github.com/L3cr0f/flare-on_2020/blob/master/6_CodeIt/6_CodeIt.md), [@AleeAmini](https://github.com/aleeamini/Flareon7-2020/tree/main/6), [@g3rzi](https://eviatargerzi.medium.com/flare-on-7-2020-challenge-6-codeit-864dabda161)

## 7 - re-crowd 🦈

1. Analyze shellcode
    1. Static decode AlphanumUnicodeMixed - [explained.re](https://explained.re/posts/flare-on7-re-crowd), [author✏️](https://www.fireeye.com/content/dam/fireeye-www/blog/pdfs/flareon7-challenge7a-solution.pdf), [@_graypanda](https://github.com/gray-panda/grayrepo/tree/master/2020_flareon/07_recrowd), [@NotCoderL](https://github.com/LeoCodes21/ctf-writeups/tree/main/Flare-On%202020/07-re_crowd), [@xEHLE_](https://blog.p1.gs/#recrowd), [@L3cr0f](https://github.com/L3cr0f/flare-on_2020/blob/master/7_Re_crowd/7_Re_crowd.md)
    2. Dynamic analysis- [asuna amawaka](https://medium.com/insomniacs/journal-flareon7-part-2-88baa92ffc9b), [@AleeAmini](https://github.com/aleeamini/Flareon7-2020/tree/main/7), [@g3rzi](https://eviatargerzi.medium.com/flare-on-7-2020-challenge-7-re-crowd-e6c79511937)

## 8 - Aardvark 🐧

1. Static
    1. Patch board - [explained.re](https://explained.re/posts/flare-on7-aardvark/), [author✏️](https://www.fireeye.com/content/dam/fireeye-www/blog/pdfs/flareon7-challenge8-solution.pdf), [@_graypanda](https://github.com/gray-panda/grayrepo/tree/master/2020_flareon/08_aardvark), [@xEHLE_](https://blog.p1.gs/#aardvark), [@L3cr0f](https://github.com/L3cr0f/flare-on_2020/blob/master/8_Aardvark/8_Aardvark.md)
    2. Patch game check function - [asuna amawaka](https://medium.com/insomniacs/journal-flareon7-part-2-88baa92ffc9b), [@AleeAmini](https://github.com/aleeamini/Flareon7-2020/tree/main/8)
2. Dynamic
    1. Change board
    2. Change game check function return value

## 9 - crackinstaller 🔫

1. Dynamic
    1. Load driver and get the password
        1. Invoke `credHelper` functions
            1. COM - [author✏️](https://www.fireeye.com/content/dam/fireeye-www/blog/pdfs/flareon7-challenge9-solution.pdf)
            2. IDA Pro's Appcall
            3. Build an executable
        2. Decrypt with RC4 - [explained.re](https://explained.re/posts/flare-on7-crackinstaller/), [@_graypanda](https://github.com/gray-panda/grayrepo/tree/master/2020_flareon/09_crackinstaller), [@xEHLE_](https://blog.p1.gs/#crackinstaller), [asuna amawaka](https://medium.com/insomniacs/journal-flareon7-part-2-88baa92ffc9b), [@AleeAmini](https://github.com/aleeamini/Flareon7-2020/tree/main/9)
2. Static
    1. Decrypt password with Salsa
        1. Decrypt flag with RC4

## 10 - break 🌈

1. Stage 1
    1. Patch `memcmp` - [explained.re](https://explained.re/posts/flare-on-7-break/#patching-memcmp)
    2. Infinite loop and open proc mem - [author✏️](https://www.fireeye.com/content/dam/fireeye-www/blog/pdfs/flareon7-challenge10-solution.pdf)
    3. LD_PRELOAD - [@_graypanda](https://github.com/gray-panda/grayrepo/tree/master/2020_flareon/10_break), [@xEHLE_](https://blog.p1.gs/#Break), [asuna amawaka](https://medium.com/insomniacs/journal-flareon7-part3-e81536c14855)
2. Stage 2
    1. Debug - [explained.re](https://explained.re/posts/flare-on-7-break/#debugging-method), [@xEHLE_](https://blog.p1.gs/#Break)
    2. Static - [author✏️](https://www.fireeye.com/content/dam/fireeye-www/blog/pdfs/flareon7-challenge10-solution.pdf)
    3. LD_PRELOAD - [@_graypanda](https://github.com/gray-panda/grayrepo/tree/master/2020_flareon/10_break), [asuna amawaka](https://medium.com/insomniacs/journal-flareon7-part3-e81536c14855)
3. Stage 3
    1. Solve bignum equation
        1. Python - [explained.re](https://explained.re/posts/flare-on-7-break/#analyzing-the-shellcode), [@_graypanda](https://github.com/gray-panda/grayrepo/tree/master/2020_flareon/10_break), [@xEHLE_](https://blog.p1.gs/#Break)
        2. Wolfram Alpha - [author✏️](https://www.fireeye.com/content/dam/fireeye-www/blog/pdfs/flareon7-challenge10-solution.pdf)
        3. Java - [asuna amawaka](https://medium.com/insomniacs/journal-flareon7-part3-e81536c14855)

## 11 - rabbithole 🐰

1. Dynamic - [explained.re](https://explained.re/posts/flare-on-7-rabbithole/), [author✏️](https://www.fireeye.com/content/dam/fireeye-www/blog/pdfs/flareon7-challenge11-solution.pdf), [@_graypanda](https://github.com/gray-panda/grayrepo/blob/master/2020_flareon/11_rabbithole), [@xEHLE_](https://blog.p1.gs/#Rabbithole)


&nbsp;
&nbsp;

---



# Links to all available write-ups

- [https://www.fireeye.com/blog/threat-research/2020/10/flare-on-7-challenge-solutions.html](https://www.fireeye.com/blog/threat-research/2020/10/flare-on-7-challenge-solutions.html)
- [https://explained.re/posts/flare-on-7-opening-notes/](https://explained.re/posts/flare-on-7-opening-notes/)
- [https://github.com/gray-panda/grayrepo/tree/master/2020_flareon](https://github.com/gray-panda/grayrepo/tree/master/2020_flareon)
- [https://medium.com/insomniacs/journal-flareon7-part-1-ca675815f204](https://medium.com/insomniacs/journal-flareon7-part-1-ca675815f204)

    [https://medium.com/insomniacs/journal-flareon7-part-2-88baa92ffc9b](https://medium.com/insomniacs/journal-flareon7-part-2-88baa92ffc9b) 

    [https://medium.com/insomniacs/journal-flareon7-part3-e81536c14855](https://medium.com/insomniacs/journal-flareon7-part3-e81536c14855)

- [https://blog.p1.gs/ctf,/reverse/engineering/2020/10/24/FLARE-ON-7-writeup/](https://blog.p1.gs/ctf,/reverse/engineering/2020/10/24/FLARE-ON-7-writeup/)
- [https://krabsonsecurity.com/2020/09/13/write-ups-for-the-flare-on-2020-challenges/](https://krabsonsecurity.com/2020/09/13/write-ups-for-the-flare-on-2020-challenges/) (mostly notes)
- [https://github.com/LeoCodes21/ctf-writeups/tree/main/Flare-On 2020](https://github.com/LeoCodes21/ctf-writeups/tree/main/Flare-On%202020)
- [https://github.com/L3cr0f/flare-on_2020](https://github.com/L3cr0f/flare-on_2020)
- [https://github.com/aleeamini/Flareon7-2020](https://github.com/aleeamini/Flareon7-2020)
- [https://eviatargerzi.medium.com/flare-on-7-2020-write-ups-4342fb819039](https://eviatargerzi.medium.com/flare-on-7-2020-write-ups-4342fb819039)
- [https://www.youtube.com/user/Demonslay335/search?query=flareon7](https://www.youtube.com/user/Demonslay335/search?query=flareon7) (video)
- [https://whitehatlab.eu/en/tags/flareon/](https://whitehatlab.eu/en/tags/flareon/)
- [https://twitter.com/zvikam/status/1319910195326341120](https://twitter.com/zvikam/status/1319910195326341120) (short)
- [https://www.youtube.com/c/PawelLukasik/search?query="flare-on 2020"](https://www.youtube.com/c/PawelLukasik/search?query=%22flare-on%202020%22) (video)
