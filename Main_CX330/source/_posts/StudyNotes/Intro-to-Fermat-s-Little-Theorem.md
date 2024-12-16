---
title: Intro to Fermat's Little Theorem
cover: >-
  https://raw.githubusercontent.com/CX330Blake/MyBlogPhotos/main/image/fermatlittle.jpg
categories: StudyNotes
abbrlink: e5109b78
date: 2024-10-08 18:32:24
tags:
---

# Prologue

Fermat's Little Theorem is quite often seen in the CTF contests, so let's dive in to this article to know more about it! Math is powerful!

# Required Knowledge

- $a\equiv{b}\pmod{k}\Leftrightarrow{k}\mid(a-b)$
- $a\equiv{b}\pmod{k}\quad\text{and}\quad c\equiv{d}\pmod{k}\Leftrightarrow a+c\equiv b+c\pmod{k}$
- $a\equiv{b}\pmod{k}\quad\text{and}\quad c\equiv{d}\pmod{k}\Leftrightarrow ac\equiv bd\pmod{k}$
  - $a\equiv b\pmod{k}\Leftrightarrow a^n\equiv b^n\pmod{k}$
  - $a\equiv b\pmod{k}\Leftrightarrow am\equiv bm\pmod{k}$

# Statement

If $p$ is a prime, and $a$ is an arbitrary integer which is coprime with $p$, then the following relationship is satisfied.
$$
a^{p-1}\equiv1\pmod{p}
$$
This means, if we devided $a^{p-1}$ by $p$, the remainder will be 1. Mathematically, if we repeatedly multiply an integer $a$, which is coprime to a prime $p$, until reaching $a^{p-1}$, the result will be congruent to 1 modulo $p$.

# Example

Suppose $p=7$, and $a=3$. Since $3$ and $7$ are coprime, so we can apply the Fermat's Little Theorem.
$$
3^{7-1}	=3^{6}=729
$$
Then calculate $729\mod{7}$
$$
729\div{7}=104\dots{1}
$$
The remainder is $1$ so,
$$
3^{6}\equiv1\pmod{7}
$$

# Generalization & Application

- Fast Exponentiation
  - Fermat's Little Theorem is often used to simplify modular exponention. For large exponents, applying this Theorem can significantly reduce the computational complexity.
  - For example, to compute $a^{1000}\mod{p}$, one can first reduce $1000$ modulo $p-1$, transforming it into a smaller exponent before calculating.
- RSA Encryption & Decryption
- Verifying Congruence Relations
  - Fermat's Little Theorem is also frequently used to verify specific congruence properties in modular arithmetic, making it an essential tool in number theory proofs.

# The Generalization of Euler's Theorem

Fermat's Little Theorem is a special case of Euler's Theorem. Euler's Theorem applies to all integers $a$ that are coprime with $n$, and its form is as follows.
$$
a^{\phi(n)}\equiv1\pmod{n}
$$
Where $\phi(n)$ is Euler's function, representing the numbers of positive integers less than $n$ that are coprime to $n$. When $n=p$ is a prime number, $\phi(p)=p-1$, and Eular's Theorem simplifies to Fermat's Little Theorem. 
