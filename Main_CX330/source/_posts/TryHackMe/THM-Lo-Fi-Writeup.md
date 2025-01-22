---
title: "[THM] Lo-Fi Writeup"
date: 2025-01-22 10:34:38
cover: https://raw.githubusercontent.com/CX330Blake/MyBlogPhotos/main/image/TryHackMe.jpg
categories: TryHackMe
tags: Web 
---

# 0x00 Challenge Info

Obviously, it's an LFI vuln. The web application can read the local file to response the different page.

# 0x01 Reconnaissance

We can found that the file can be read by such as `page=file:///etc/passwd`.

# 0x02 Exploit

Use the `file:///flag.txt` to read the `flag.txt` in the root path.

# 0x03 Pwned

![Pwned](https://raw.githubusercontent.com/CX330Blake/MyBlogPhotos/main/image/image-20250122104141201.png)

