---
title: "Flare-On 7 — 01 Fidler"
date: 2020-10-23T21:29:41+03:00
draft: false
author: "explained.re"
tags: ["flare-on"]
categories: ["write-up", "ctf"]

lightgallery: true


toc:
  enable: false

---
{{< admonition info "Challenge Description" >}}
Welcome to the Seventh Flare-On Challenge!

This is a simple game. Win it by any means necessary and the victory screen will reveal the flag. Enter the flag here on this site to score and move on to the next level.

This challenge is written in Python and is distributed as a runnable EXE and matching source code for your convenience. You can run the source code directly on any Python platform with PyGame if you would prefer.
{{< /admonition >}}

In this first challenge, we get a Python program that was distributed as a Windows executable. The challenge author was kind enough to provide the executable alongside the source code that was used to create it. Running the executable we get this window.

{{< image src="images/image.png" >}}

This is a simple prompt for a password. Let's dig into the Python source code to try and get it. After looking at as little as 9 lines of code, we stumble across a function called `password_check`.

```python
def password_check(input):
    altered_key = 'hiptu'
    key = ''.join([chr(ord(x) - 1) for x in altered_key])
    return input == key
```

Looks like each character of `'hiptu'` is subtracted by 1, and then compared to our password. We'll execute this process to get the correct password.

```python
''.join([chr(ord(x) - 1) for x in 'hiptu'])

# Results:
# 'ghost'
```

After we insert the `ghost`, we see the following window (keeping up with the cats theme in the first challenge):

{{< image src="images/image_1.png" >}}

Seems like we need to earn 100 Billion coins to get the flag, but 100 Billion does sound like a lot. After all, we have 10 more challenges to solve, so we better try to find the flag in the source code.

Browsing through the code, we see a function called `decode_flag`. This must be important. Let's see where it is being used.

```python
def victory_screen(token):
	[ . . . ]
	flag_content_label.change_text(decode_flag(**token**))
	[ . . . ]
```

`decode_flag` is called in `victory_screen` and it gets an argument called `token`, which is the parameter of the `victory_screen` function. We have to go a step back and see how `victory_screen` is invoked.

```python
def game_screen():
	[ . . . ] 
	target_amount = (2**36) + (2**35)
	if current_coins > (target_amount - 2**20):
	    while current_coins >= (target_amount + 2**20):
	        current_coins -= 2**20
	    victory_screen(int(current_coins / 10**8))
	    return
```

We see that it is being invoked by `game_screen`, and that it gets the number of coins we have currently, divided by `10**8`(100 million). In the game screen itself, we saw that we need to have 100 Billion (`10**11`) coins in order to get the flag, so let's use this number as our amount of coins, and call `decode_flag` ourselves, outside of the context of the game and simulate winning conditions.

```python
current_coins = 10**12 # More than about 100 Billion target
target_amount = (2**36) + (2**35)
if current_coins > (target_amount - 2**20):
    while current_coins >= (target_amount + 2**20):
        current_coins -= 2**20
    print(int(current_coins / 10**8))
# Result:
# 1030
```

We got `1030`. Now let's use this as the token for the `decode_flag` function and see what we get.

```python
def decode_flag(frob):
    last_value = frob
    encoded_flag = [1135, 1038, 1126, 1028, 1117, 1071, 1094, 1077, 1121, 1087, 1110, 1092, 1072, 1095, 1090, 1027,
                    1127, 1040, 1137, 1030, 1127, 1099, 1062, 1101, 1123, 1027, 1136, 1054]
    decoded_flag = []

    for i in range(len(encoded_flag)):
        c = encoded_flag[i]
        val = (c - ((i%2)*1 + (i%3)*2)) ^ last_value
        decoded_flag.append(val)
        last_value = c

    return ''.join([chr(x) for x in decoded_flag])

print(decode_flag(1030))
# Result:
# idle_with_kitty@flare-on.com
```

We got the flag - [`idle_with_kitty@flare-on.com`](mailto:idle_with_kitty@flare-on.com).