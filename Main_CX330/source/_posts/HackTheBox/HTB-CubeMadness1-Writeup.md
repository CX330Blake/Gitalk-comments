---
title: "[HTB] CubeMadness1 Writeup"
cover: >-
    https://raw.githubusercontent.com/CX330Blake/MyBlogPhotos/main/image/help-you-at-solving-hackthebox-htb-challenges-machines.png
categories:
    - - HackTheBox
    - - CTF
tags:
    - HTB
    - HackTheBox
    - GamePwn
abbrlink: bd7b2870
date: 2024-10-07 10:50:06
---

# 0x00 Challenge Info

> Gotta collect them all.

# 0x01 Reconnaissance

We have a zip file, and after we unzip the file, we got an executable file called `HackTheBox CubeMadness1.exe`. First, we can run the file to see what's going on and what is this game about.

![Game View](https://raw.githubusercontent.com/CX330Blake/MyBlogPhotos/main/image/image-20241007105809337.png)

In this game, we can use left/right arrow to control the white cube (?) and use space to jump, and it also allows jumping in the air. The challenge description said that we should collect all the cubes, but when we try to get all of them by playing the game, we can found that there's **only 6 cubes in total**, so there's no way to collect all of them, which is 20 as shown in the top left corner.

So we can infer that the challenge want us to modify the data in the game to achieve the goal, then we can use the tool called [Cheat Engine](https://www.cheatengine.org/) to do this job.

First, we need to find out where is the location in memory that save the number of cubes we collected. To do that, we need to open Cheat Engine and the game so that Cheat Engine can scan the memory of the game. After doing so, click on the scan button on CE to open the process of the game.

![Scan Button on Top Left Corner](https://raw.githubusercontent.com/CX330Blake/MyBlogPhotos/main/image/image-20241007113456966.png)

Once we open it, we can operate the game character to get the first cube. After we got 1 cube, we can set the value to be 1 in CE, and then click on `First Scan` to scan the memory. It should be like this.

![First Scan](https://raw.githubusercontent.com/CX330Blake/MyBlogPhotos/main/image/image-20241007113832519.png)

And then, we go get the second cube and click on `Next Scan`, and the third, and the forth, and so on until we get all 6 cubes. After that, there should be only 4 addresses left, just like below.

![After Scanning](https://raw.githubusercontent.com/CX330Blake/MyBlogPhotos/main/image/image-20241007114232621.png)

# 0x02 Exploit

So, we found 4 addresses that may be the place to store the cubes we got. Let's modfy the data to be 20!

First, we double click on the first address in the left panel, which is `0x206FEA32A40` in previous picture, then we double click the value below and change it to 20.

![Modify The Data](https://raw.githubusercontent.com/CX330Blake/MyBlogPhotos/main/image/image-20241007115118419.png)

Go back to the game and you can see the flag! The flag is redacted below.

![Pwned](https://raw.githubusercontent.com/CX330Blake/MyBlogPhotos/main/image/image-20241007115423250.png)

# 0x03 Pwned

![Pwned](https://raw.githubusercontent.com/CX330Blake/MyBlogPhotos/main/image/image-20241007115837227.png)

This is a very easy challenge that can help me to get into game pwning! Interesting one.
