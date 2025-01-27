---
title: Add a Seperator to Your Terminal!
date: 2025-01-27 16:51:14
cover: https://raw.githubusercontent.com/CX330Blake/MyBlogPhotos/main/image/TerminalSeperator.jpg
categories: DevCorner
tags:
---

# Why this?

Why? Just since it makes my terminal looks prettier and easier to understand. It devides every command into a BLOCK so that I can easily get to the point. 

# How it looks like?

 ![Demo](https://raw.githubusercontent.com/CX330Blake/MyBlogPhotos/main/image/image-20250127170649921.png)

The gray line in the graph is how it looks like. You can change the color later in your setup.  

# Setup

```sh
function print_separator() {
    local cols=$(tput cols)
    local color="\033[38;2;68;71;90m" # RGB(68, 71, 90), you can change the color here
    local reset="\033[0m"             
    printf "\n"
    printf "${color}%${cols}s${reset}\n" | tr " " "-"
    printf "\n"
}

# Inject seperator after commands
precmd() { print_separator }
```

You can simply copy and paste the script above to your shell source, such as `~/.zshrc` or `~/.bashrc`.
