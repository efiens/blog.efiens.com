---
# Documentation: https://sourcethemes.com/academic/docs/managing-content/

title: "[MatesCTF2019 Round 4] Barry Allen, Fill the Bottle, web01 writeups"
subtitle: ""
summary: "Writeups for MatesCTF2019 Round 4 challenges"
authors: [midas]
tags: []
categories: []
date: 2019-04-27T20:22:17-07:00
lastmod: 2019-04-27T20:22:17-07:00
featured: false
draft: false

# Featured image
# To use, add an image named `featured.jpg/png` to your page's folder.
# Focal points: Smart, Center, TopLeft, Top, TopRight, Left, Right, BottomLeft, Bottom, BottomRight.
image:
  caption: ""
  focal_point: ""
  preview_only: false

# Projects (optional).
#   Associate this post with one or more of your projects.
#   Simply enter your project's folder or file name without extension.
#   E.g. `projects = ["internal-project"]` references `content/project/deep-learning/index.md`.
#   Otherwise, set `projects = []`.
projects: []
---

*All files for this writeups were lost, it's just to demonstrate techniques*

## BarryAllen (pwn)

### Analyzing
This challenge comes with a single binary file with a single function

The program is just simple: it calls srand with the difference of the 2 values of microsecond from `gettimeofday()` as the seed, and then it calls `rand()%1000000000` a hundred times. If our 99/100 inputs match those, we got the flag.

### Solution
I will not call it an exploitation in this challenge because it just don't feel like it, I will just call it a "solution".

The thing here is that the `srand()` and `rand()` function are just pseudo-random. It means that if you know what the seed is, you can predict the return values of `rand()`. Moreover, the program only asks you to guess 99/100 value correctly, and it does print out the correct value each time, so you can just use the first guess to find the seed, and then you can easily get all the `rand()`'s return value.

I was bored and lazy as hell with solving a challenge like this, so what I did was just to write a short C program to bruteforce the seed and then print out 99 `rand()%1000000000` values with that seed. Then all I needed to do was nc to the server, guess the 1st one, put the correct value into the C code and let it bruteforce the seed and print the other values into a file, then I just copied the content of that file and threw it into the server.

*To be completely honest, I don't like this challenge at all. I really think that this type of pwn is pretty lame, but of course it came with some points so I solved it anyway.*

`MatesCTF{JUST_A_RANDOM_FLAG_KJASDJASOIDQWMKODASOIDOASDQOPKWPEQWASDKASD}`

## Fill The Bottle (programming)

This was the only programming challenge of the contest. Actually, I am not a programming kind of guy but our team did solve all the pwn challenges (there are only 2 of them) so I proceeded to solve this one.

The task here is that you have 2 bottles that can hold x and y litres, what you can do with them is that you can fill one, empty one, or pour all of from one to the other (the syntax is shown above), what you have to do is to achieve z litres (x < z < y, they didn't show this, but with several runs I think it is true). You have to pass 5 rounds of this (each round the number goes higher and they are all random).

My solution to this is nothing fancy and it is not even close to be any good. In fact, in some case, it will go into an infinite loop, but I would just disconnect and run again then :v. Here is the solution: (1): empty 2 bottles and then fill the second one. (2): keep pouring from the second one to the first one and then empty the first one until the value in the second one is less than the first. (3): pour from the second one to the first one, fill the second one and pour from it to the first one again. (4): empty the first one. And then keep repeating (2) (3) (4) until we achieve z.

## Web1 (web)

This challenge were solved by me and `@mrsrc` and `@phieulang`.

This website has 2 places where we can input: the login page and the contact page.

First, I tried some payload and some random username + password into the login page but none of them seemed to work, so I switched to the contact page.

The contact page has the following URL: `http://35.225.65.132/matesctf-01/mail/contact.php`. First, I tried to connect to `http://35.225.65.132/matesctf-01/mail/` and recieved this:


This page gave me the information that the mailing function of this website is using PHPMailer, and by looking at the VERSION file, I learned that it was PHPMailer version 5.2.16. I then googled for some information about some possible vulnearablities in PHPMailer and found these CVEs: CVE-2016-10033 and CVE-2016-10045. These bugs are in PHPMailer < 5.2.18 and < 5.2.20, so I decided to follow this path, because I thought it was 99% the correct path. Then I showed this to @mrsrc and we proceeded with this path.

The exploitation requires the directory after the `-X` option to be a writable dir, so we had to find it. Using dirsearch, we found a file called README at `http://35.225.65.132/matesctf-01/README`. The file shows that the `./img` directory is writable.


So then, we tried the payload `name=123&email="" -oQ/tmp -X/var/www/html/matesctf-01/img/logfile.txt some"@email.com&message=&submit=` and realized that the website had filtered the option -o. We didn't know what the options do at first, so we have to look at the document of the sendmail function to find out what they do. What we learned is that the `-X` option let you choose where the log file will be, and the -oQ option sets the Queue Directory for incoming mails.

We thought that the `-oQ` option is irrelevant because we didn't touch the queue dir, so we tried with the payload `name=123&email="" -X/var/www/html/matesctf-01/img/logfile.txt some"@email.com&message=&submit=` and then checked the log file. And we realized why the `-oQ` option where needed: the log file showed that we don't have the permission to the original queue dir. This meant we couldn't achieve complete RCE.

Some hours later trying out different options and failed, @mrsrc showed me a wonderful site: `https://exploitbox.io/paper/Pwning-PHP-Mail-Function-For-Fun-And-RCE.html`. This page shows us a lot of exploit vectors for this bug. I read that page for a while and saw a vector that we can use to achieve arbitrary read with option `-C`, the option that let us choose the config file. This vector is pretty simple: when we try to read a file that is not a config file with `-C`, every single lines of that file will be output as error into the log file, that way we can read every single file we want.

I tried reading a lot of file (a lot of them lead to some weird magic that I really don't understand, even now), but finally, this payload give me the login.php file which contains the flag: `name=123&email="" -C../login.php -X/var/www/html/matesctf-01/img/logfile.txt some"@email.com&message=&submit= `.

Note: We didn't know that relative path does work at first, so we have to find the web root (`/var/www/html/`) by guessing and trying. And the magic which I mentioned was that some files can only be read using relative path and some others can only be read using absolute path. For example: `-C/etc/passwd` does work, but `-C/../../../../../../etc/passwd` doesn't; `-C../login.php` works, but `-C/var/www/html/matesctf-01/login.php` doesn't, ... I really don't know why this happens, even now I don't.
