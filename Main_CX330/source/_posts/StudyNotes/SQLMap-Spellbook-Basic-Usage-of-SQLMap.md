---
title: 'SQLMap Spellbook: Basic Usage of SQLMap'
cover: >-
  https://raw.githubusercontent.com/CX330Blake/MyBlogPhotos/main/image/Blog_cover%20(13)-min.jpg
categories: StudyNotes
tags:
  - SQLi
  - Web
abbrlink: '97052569'
date: 2024-08-12 18:23:02
---


# Prologue

This article is mainly intended to serve as my own cheat sheet and notes, but if it can also help you, that would be great. The content is summarized from the original document, so you can regard this article as an TL;DR version of the document per se.

I will consistently update the content if I find something missing or something worth to be noted. You can also contact me to update the content. 

# Types of SQL Injection

There're 5 types of SQLi vulnerability or 5 ways that SQLMap can test a website.

1. **Boolean-Based (Content-Based) Blind SQLi**

   - Attackers send some boolean expression that forces the application to return different result depending on the TRUE or FALSE condition.

   - By trying the payload multiple times, attackers can infer the secret data. 

2. **Time-Based Blind SQLi**

   - This attack method relied on sending a function or an SQL query to the database to force it to wait or delay for an amount of time before responding. The responding time can tell the attackers if the query is TRUE or FALSE.

3. **Error-Based SQLi**

   - By triggering the SQL error message from the database to obtain the data.

4. **Union-Based SQLi**

   - Use the UNION operator to merge the result of original query and the one from the malicious query.
   - The secret data will then be rendered by the browser directly.

5. **Stacked Queries (Piggybacking)**

   - Stacked queries injection allows multiple query in one SQL request.
   - It often uses the "**;**" sign as the seperator to concatenate several queries.

There's also another type of classification from HTB Academy.

![Types of SQLi](https://raw.githubusercontent.com/CX330Blake/MyBlogPhotos/main/image/types_of_sqli.jpg)

# Magic Spells

The following are some parameters commonly used in SQLMap.

## Options

| Flag         | Description                         |
| :----------- | :---------------------------------- |
| `-h, --help` | Show basic help message and exit    |
| `-hh`        | Show advanced help message and exit |
| `-v VERBOSE` | Verbosity level: 0-6 (default 1)    |

## Target

At least one of these options has to be provided to define the target(s).

| Flag                | Description                                           |
| :------------------ | :---------------------------------------------------- |
| `-u URL, --url=URL` | Target URL (e.g. "http://www.site.com/vuln.php?id=1") |

## Request

These options can be used to specify how to connect to the target URL.

| Flag              | Description                                           |
| :---------------- | :---------------------------------------------------- |
| `--data=DATA`     | Data string to be sent through POST (e.g. "id=1")     |
| `--cookie=COOKIE` | HTTP Cookie header value (e.g. "PHPSESSID=a8d127e..") |
| `--random-agent`  | Use randomly selected HTTP User-Agent header value    |
| `--proxy=PROXY`   | Use a proxy to connect to the target URL              |
| `--tor`           | Use Tor anonymity network                             |
| `--check-tor`     | Check to see if Tor is used properly                  |

## Injection

These options can be used to specify which parameters to test for, provide custom injection payloads and optional tampering scripts.

| Flag               | Description                                              |
| :----------------- | :------------------------------------------------------- |
| `-p TESTPARAMETER` | Testable parameter(s) (eg. -p username)                  |
| `--dbms=DBMS`      | Force back-end DBMS to provided value (eg. --dbms=mysql) |
| `--tamper=TAMPER`  | Use given script(s) for tampering injection data         |

## Detection

These options can be used to customize the detection phase.

| Flag            | Description                                |
| :-------------- | :----------------------------------------- |
| `--level=LEVEL` | Level of tests to perform (1-5, default 1) |
| `--risk=RISK`   | Risk of tests to perform (1-3, default 1)  |

## Enumeration

These options can be used to enumerate the back-end database management system information, structure and data contained in the tables.

| Flag             | Description                                |
| :--------------- | :----------------------------------------- |
| `-a, --all`      | Retrieve everything                        |
| `-b, --banner`   | Retrieve DBMS banner                       |
| `--current-user` | Retrieve DBMS current user                 |
| `--current-db`   | Retrieve DBMS current database             |
| `--passwords`    | Enumerate DBMS users password hashes       |
| `--dbs`          | Enumerate DBMS databases                   |
| `--tables`       | Enumerate DBMS database tables             |
| `--columns`      | Enumerate DBMS database table columns      |
| `--schema`       | Enumerate DBMS schema                      |
| `--sql-shell`    | Prompt for an interactive SQL shell        |
| `--dump`         | Dump DBMS database table entries           |
| `--dump-all`     | Dump all DBMS databases tables entries     |
| `-D DB`          | DBMS database to enumerate                 |
| `-T TBL`         | DBMS database table(s) to enumerate        |
| `-C COL`         | DBMS database table column(s) to enumerate |

## Operating system access

These options can be used to access the back-end database management system underlying operating system.

| Flag         | Description                                      |
| :----------- | :----------------------------------------------- |
| `--os-shell` | Prompt for an interactive operating system shell |
| `--os-pwn`   | Prompt for an OOB shell, Meterpreter or VNC      |
| `--priv-esc` | Database process user privilege escalation       |

## General

These options can be used to set some general working parameters.

| Flag                 | Description                                                  |
| :------------------- | :----------------------------------------------------------- |
| `--batch`            | Never ask for user input, use the default behavior           |
| `--crawl=CRAWLDEPTH` | Crawl the website starting from the target URL (usually use 2) |
| `--forms`            | Parse and test forms on target URL                           |
| `--flush-session`    | Flush session files for current target                       |

## Miscellaneous

| Flag       | Description                                |
| :--------- | :----------------------------------------- |
| `--wizard` | Simple wizard interface for beginner users |

# More About The Spells

If you want to know more about the magic spells of SQLMap, you can check out the official document. I will put some resources below JFYI.

1. [Chinese version of SQLMap docs.](https://octobug.gitbooks.io/sqlmap-wiki-zhcn/content/)
2. [Official SQLMap docs](https://github.com/sqlmapproject/sqlmap/wiki)

You can also use the `-hh` flag to see the manual page of sqlmap in your CLI. 
