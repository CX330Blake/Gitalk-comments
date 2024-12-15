---
title: Reversing.Kr Writeups
date: 2024-12-07 13:13:42
cover: https://raw.githubusercontent.com/CX330Blake/MyBlogPhotos/main/image/ReversingKr.jpg
categories: CTF
tags: RE
---

# Easy Crack

Open IDA and find the check password function (you can use a string to find it). I will put the decompiled function below.

```c
int __cdecl sub_401080(HWND hDlg)
{
    CHAR String[97]; // [esp+4h] [ebp-64h] BYREF
    __int16 v3; // [esp+65h] [ebp-3h]
    char v4; // [esp+67h] [ebp-1h]

    memset(String, 0, sizeof(String));
    v3 = 0;
    v4 = 0;
    GetDlgItemTextA(hDlg, 1000, String, 100);
    if ( String[1] != 'a' || strncmp(&String[2], Str2, 2u) || strcmp(&String[4], aR3versing) || String[0] != 'E' )
        return MessageBoxA(hDlg, aIncorrectPassw, Caption, 0x10u);
    MessageBoxA(hDlg, Text, Caption, 0x40u);
    return EndDialog(hDlg, 0);
}
```

`GetDlgItemTextA` on line 10 is the Windows API, which is used to obtain the text of the message box. The details are as follows.

```cpp
UINT GetDlgItemTextA(
  [in]  HWND  hDlg,
  [in]  int   nIDDlgItem,
  [out] LPSTR lpString,
  [in]  int   cchMax
);
```

As you can see from line 11, if the condition here is true, an Incorrect message box will pop up, so the judgment here should be False. In this way, `String[1]` is `a`, `String[2]` is `Str2`, whose content is `5y`, `String[4]` is `R3versing`, and finally `String[0]` is `E`. We can obtain the password `Ea5yR3versing` by ordering the sequence.

# Easy Keygen

```python
serial_str = "5B134977135E7D13"

serial_hex = [int(serial_str[i : i + 2], 16) for i in range(0, len(serial_str), 2)]


print(serial_hex)


nums = [16, 32, 48]

v3 = 0


name = ""

while v3 < len(serial_hex):
    name += chr(serial_hex[v3] ^ nums[v3 % 3])
    v3 += 1


print(name)
```

# Easy Unpack

# Easy ELF

# CSHOP
