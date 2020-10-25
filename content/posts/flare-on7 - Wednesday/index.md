---
title: "Flare-On 7 — 03 Wednesday"
date: 2020-10-23T21:29:43+03:00
draft: false
author: "explained.re"
tags: ["flare-on"]
categories: ["write-up", "ctf"]

lightgallery: true

toc:
  enable: false

---

{{< admonition info "Challenge Description" >}}

Be the wednesday. Unlike challenge 1, you probably won't be able to beat this game the old fashioned way. Read the README.txt file, it is very important.
{{< /admonition >}}

Usually, when the challenge author tells you that the `README.txt` is very important, it's a great idea to start the challenge by reading it.

```python
██╗    ██╗███████╗██████╗ ███╗   ██╗███████╗███████╗██████╗  █████╗ ██╗   ██╗
██║    ██║██╔════╝██╔══██╗████╗  ██║██╔════╝██╔════╝██╔══██╗██╔══██╗╚██╗ ██╔╝
██║ █╗ ██║█████╗  ██║  ██║██╔██╗ ██║█████╗  ███████╗██║  ██║███████║ ╚████╔╝ 
██║███╗██║██╔══╝  ██║  ██║██║╚██╗██║██╔══╝  ╚════██║██║  ██║██╔══██║  ╚██╔╝  
╚███╔███╔╝███████╗██████╔╝██║ ╚████║███████╗███████║██████╔╝██║  ██║   ██║   
 ╚══╝╚══╝ ╚══════╝╚═════╝ ╚═╝  ╚═══╝╚══════╝╚══════╝╚═════╝ ╚═╝  ╚═╝   ╚═╝   

                        --- BE THE WEDNESDAY ---
                                   S
                                   M
                                   T
                                  DUDE
                                   T
                                   F
                                   S
                --- Enable accelerated graphics in VM ---
                  --- Attach sound card device to VM ---
                    --- Only reverse mydude.exe ---
                       --- Enjoy it my dudes ---
```

So we're told to "be the wednesday " which seems a bit vague, we see this "DUDE" in the middle of some letters, and some instructions on how to get the executable running on our machine. Lastly, we have an important instruction - only reverse `mydude.exe`. This is important since the challenge comes with a lot of files.

Next, we can execute the binary and see what's going in it. It looks like a pretty standard side-scroller game, where we control *dude* and need to avoid obstacles in order to score points. From playing around for a couple of minutes, we can notice that we should duck when approaching squares containing the letters S/M/T should be and jump when approaching T/F/S. Much like in the form we saw in the challenge's readme. Let's open this game up in a disassembler and see how we can get to the winning screen to get the flag. We'll start with our `main`.

```cpp
int __cdecl main(int argc, const char **argv, const char **envp)
{
  __main();
  cmdLine = (int)argv;
  cmdCount = argc;
  gEnv = (int)envp;
  NimMain();
  return nim_program_result;
}
```

Based on the fact we have a `NimMain` function, we can understand that this executable was developed in [Nim](https://nim-lang.org/). This is useful since as you can see in the binary, all the names from the original source code were saved and we can see those in the binary. This can help us quite a lot when trying to understand the logic of different functions. From `NimMain` we see a few function calls that eventually get us to the main functionality of the binary - `NimMain` → `NimMainInner` → `NimMainModule`. This function is responsible for initializing the game object and creating the game's main scene, then it finally runs the game and we'll get to the main game loop in `run__E9cSjWeb4G6NszYRcpo6sLA_2`.

Now we need to have a goal in mind before we continue our reversing process. The option we may come up with at this point are:

1. Find the flag statically / find where the flag is decode or decrypted upon a win, and do that statically
2. Patch the game in order to win. This can be done in many ways, here are two:
    1. Reduce a score threshold we need to get to in order to win - make the winning screen pop up after passing one obstacle for example.
    2. Patch the condition in which the game decide if we pass an obstacle or not, to make it always think we passed

For option 1, it can be useful to start and look for strings related to our score, so we can locate it in memory. In this case, we couldn't really find those strings the traditional way, so we'll do something else. In our main function `run__E9cSjWeb4G6NszYRcpo6sLA_2`, we see a lot of call for different update functions. They seem to be invoked in order to update certain elements of the game like location, status, and probably score as well. Stepping through those functions we see `update__Arw3f6ryHvqdibU49aaayOg` which seems to be creating some score-related strings. Stepping through that as well, we find a very interesting check that seems to show the `winScene`.

```cpp
if ( *v15 == 0x128 )
      sceneeq___HC7o4hYar8OQigU09cNyehg(game__7aozTrKmb7lwLeRmW9a9cs9cQ, winScene__eVaCVkG1QBiYVChMxpMGBQ);
  }
```

It tests whether our score is equal to `0x128`. Let's patch this so the winning score should be lower, and see if we get the flag. We'll go to *Edit→Patch program→Assemble...*

{{< image src="images/image.png" >}}

```asm
; Before the patch
.text:00433FAD                 cmp     dword ptr [eax], 128h
.text:00433FB3                 jnz     loc_433D3A

; After the patch
.text:00433FAD                 cmp     dword ptr [eax], 2
.text:00433FB0                 nop
.text:00433FB1                 nop
.text:00433FB2                 nop
.text:00433FB3                 jnz     loc_433D3A
```

Next, we will *Edit→Patch program→Apply patches to input file...* and we'll run our new game and pass 2 obstacles.

{{< image src="images/image_1.png" >}}

We won! But hang on, where's our flag? This probably means that the flag is somehow affected by the score, or obstacles avoided during the game, so we need to try a different method.

Our strategy will now be trying to change the condition that is responsible to tell the game if we passed an obstacle or not. The way to locate the code that does it can be by simply debugging the game or by checking the function names since in this case, we have the symbols. We find `checkCollisions__P9bTKWszU9b7sTpYI5ZXt5Ug` which seems like it checks every collision that dude has with an obstacle. Now we'll try to locate the condition after which we add 1 to our score or lose the game. `checkCollisions__P9bTKWszU9b7sTpYI5ZXt5Ug` doesn't seem to contain what we're after, but it does call another function that sounds related - `onCollide__BN6X9bI9aXYgG1H4BavWOusg`. 

```cpp
void __fastcall onCollide__BN6X9bI9aXYgG1H4BavWOusg(int **a1, int a2)
{
  int *v4; // eax

  chckNilDisp();
  if ( a1 )
  {
    v4 = *a1;
    if ( *a1 == &NTI__Izz1yqaplqIXEoEFpusDCA_ )
    {
      if ( !(unsigned __int8)isObj(&NTI__Izz1yqaplqIXEoEFpusDCA_, &NTI__Izz1yqaplqIXEoEFpusDCA_) )
        raiseObjectConversionError();
      **onCollide__9byAjE9cSmbSbow3F9cTFQfLg**((int)a1, a2);
    }
    else if ( v4 == &NTI__zAmpQ4W10DAkJqNC4t2weQ_
           || (int *)v4[2] == &NTI__zAmpQ4W10DAkJqNC4t2weQ_
           || v4 != (int *)Nim_OfCheck_CACHE20
           && (v4 == (int *)dword_443FAC
            || (unsigned __int8)isObjSlowPath__H8B7g6iFRPI5Em52KFoD6w(
                                  v4,
                                  &NTI__zAmpQ4W10DAkJqNC4t2weQ_,
                                  &Nim_OfCheck_CACHE20)) )
    {
      onCollide__LM9b9b09cstNz9cvDN3XPcQqVg(a1, a2);
    }
  }
}
```

Then we'll continue our analysis of the collision functions with `onCollide__9byAjE9cSmbSbow3F9cTFQfLg`, which does seem to alter the score.

```cpp
void __fastcall onCollide__9byAjE9cSmbSbow3F9cTFQfLg(int a1, int a2)
{
  v2 = *(unsigned int **)(a2 + 20);
  if ( v2 )
  {
    v22 = *v2;
    if ( (int)*v2 > 0 )
    {
      v4 = 0;
      v5 = 0;
      while ( 1 )
      {
        v6 = v2[v4 + 2];
        if ( v6 )
        {
          if ( *(_DWORD *)v6 == 3 && *(_WORD *)(v6 + 8) == 24932 && *(_BYTE *)(v6 + 10) == 121 )
            break;
        }
        v7 = __OFADD__(1, v5++);
        if ( v7 )
          ((void (*)(void))raiseOverflow)();
        if ( v22 == ++v4 )
          goto LABEL_12;
        if ( v22 <= v4 )
          raiseIndexError2(v4, *v2 - 1);
      }
      if ( v5 >= 0 )
      {
        v13 = sfxData__L0NEb9bbVaCJg09cSf9auviJQ;
        *(_BYTE *)(a1 + 249) = 1;
        v14 = (_DWORD *)X5BX5D___m13cHDTNyHJWI0nfsypQew(v13, &TM__E4euemHcWzC1bcQ69azK2pw_8);
        play__ekc9cEXgy7z9cRAqIYID39ccg(*v14, 0);
      }
LABEL_12:
      v8 = *(unsigned int **)(a2 + 20);
      if ( v8 )
      {
        v9 = *v8;
        v23 = v8 + 2;
        if ( (int)*v8 > 0 )
        {
          v10 = 0;
          v11 = 0;
          while ( 1 )
          {
            v12 = v23[v10];
            if ( v12 )
            {
              if ( *(_DWORD *)v12 == 5 && *(_DWORD *)(v12 + 8) == 'cehc' && *(_BYTE *)(v12 + 12) == 'k' )
                break;
            }
            v7 = __OFADD__(1, v11++);
            if ( v7 )
              ((void (*)(void))raiseOverflow)();
            if ( v9 == ++v10 )
              return;
            if ( v9 <= v10 )
              raiseIndexError2(v10, v9 - 1);
          }
          if ( v11 >= 0 )
          {
            if ( !(unsigned __int8)isObj(*(_DWORD *)a2, &NTI__bc9cIRpcNby7Dj3TH0kx9cWA_) )
              raiseObjectConversionError();
            v15 = score__h34o6jaI3AO6iOQqLKaqhw + 1;
            if ( __OFADD__(1, score__h34o6jaI3AO6iOQqLKaqhw) )
              ((void (*)(void))raiseOverflow)();
            *(_BYTE *)(a2 + 24) = 1;
            score__h34o6jaI3AO6iOQqLKaqhw = v15;
            if ( !(unsigned __int8)isObj(*(_DWORD *)a2, &NTI__bc9cIRpcNby7Dj3TH0kx9cWA_) )
              raiseObjectConversionError();
            v16 = incrSeqV3(*(_DWORD *)(a1 + 252), &NTI__pxbIse2JUQkJU0n9blV9bY5g_);
            v17 = (_DWORD *)v16;
            if ( v16 )
              *(_DWORD *)(v16 - 8) += 8;
            v18 = *(_DWORD *)(a1 + 252);
            if ( v18 )
            {
              v19 = *(_DWORD *)(v18 - 8);
              *(_DWORD *)(v18 - 8) = v19 - 8;
              if ( (unsigned int)(v19 - 8) <= 7 )
                addZCT__Y66tOYFjgwJ0k4aLz4bc0Q(&dword_44B54C, v18 - 8);
            }
            *(_DWORD *)(a1 + 252) = v17;
            v20 = (*v17)++;
            *(_BYTE *)(*(_DWORD *)(a1 + 252) + v20 + 8) = *(_BYTE *)(a2 + 248);
          }
        }
      }
    }
  }
}
```

We want this line of code to always be executed.

```cpp
v15 = score__h34o6jaI3AO6iOQqLKaqhw + 1;
```

So we patch the branch before that. This is how it looks like before:

{{< image src="images/image_2.png" >}}

And here's after:

{{< image src="images/image_3.png" >}}

When we run the patched game, it looks like we still need to duck to avoid all types of obstacles. Oh well, we'll put something heavy to press on our down arrow key, and after a few minutes we have this:

{{< image src="images/getFlag1.gif" >}}

We got the flag - `1t_i5_wEdn3sd4y_mY_Dud3s@flare-on.com`!