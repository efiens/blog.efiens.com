---
title: "Update Efiens Server Structure"
subtitle: ""
summary: "So Efiens blog has been restructured. From now on, we are no longer use single central server to distribute our contents, Ghost blog is okay, but not good enough for us."
authors: [cothan]
tags: []
categories: []
date: 2020-10-21T17:25:20-04:00
lastmod: 2020-10-21T17:25:20-04:00
featured: false
draft: false

image:
  caption: ""
  focal_point: ""
  preview_only: false

projects: []
---

## Efiens Server Structures

So Efiens's blog has been restructured. From now on, we are no longer use single central server to distribute our contents, Ghost blog is okay, but not good enough for us. 

Efiens's blog is faster than ever. 

For years, we have a burden to maintain our server, which is not actually so simple, we have blog, front page, deployed in the same server, we forget to do `apt-get update` every now and then, we have exploit toolkits on our server, sometime we don't know that connect backs are us or them, and we were so scare that someday something may happen to our server, since we try to minimize our budget, many tasks, such as VPN, Discord's bot, Web Services and security tools are in 01 single server, as long as we go, we need to change this situation. 

So here are our plan: 

- All static contents will be deployed using Netlify. Because it's fast and free. 
- All security tool kits from now have a freedom to be deployed on temporary servers, we only need to fire and forget, even if we accidentally burn our server, we happily create a new one. Many wonderful philosophies in life start from simple, stupid things. 
- Yes, we plan to have a mail server too, our attitude with the mail server is to not store in our secret life in there, it's not replace our private emails, but it's extend our professional careers, we will do our best to secure our mail server. 

With Blog, the soul of our team, has moved to Netlify. Front Page will soon be move to static contents, turn out, it's easier for us, to write our content in any format, Asciidoc, Latex, Markdown, with a simple pull request, your content will be deployed instantly. And the world can reach it in `5ms`, isn't it awesome? 

Compare to the loading time between Ghost Blog and Netlify: `200ms` vs `5ms`. Do your math. :) 

Let's talk about budget, since the start, for years, we had received generous sponsors from alumni, VNG, those budget from early start mean a lot to us, hosting Virtual Private Server (VPS) and renewing `efiens.com` domain had cost a lot and keep increasing per year. 

When we bought `efiens.com`, it's dirt cheap, for years, we gained world wide web attention (that's good news), our domain has increased its ranking, follow that, our domain registrar `Godaddy` increase renewal price and put us in hostile situation every time. So we drop Godaddy, move to Cloudflare, the renew fee is now fixed, $9 per year, it's back to dirty cheap again. But for sure we don't want to give up our domain at anytime until the end of time.

About VPS, we cut from 2 servers to only 1 server: Mail server. And that's it. Other servers are for fire and forget purpose, they has short life span, probably 3 days after a CTF, or 2 months for Qualifying Rounds, thus, it's cheap.

For the long run, this choice not only save us some money (although it's doesn't matter at the moment), but also keep our head up for incoming challenges, we get in touch with modern web technology, content distribution, writing markdown, Latex, in which, maybe useful for some of us in the future. Simplifying our architecture is to drop the burdens in our shoulder.

No one has to wake up in the middle of the night, rush to update our server when we read about a new networking exploits, simply have a good sleep. 

## Blogging Structure

##= So... How to write content in this blogging style ? 

Simple in 3 steps:

- Run `git clone git@github.com:efiens/blog.efiens.com.git`
- Run `cd blog.efiens.com`
- Run `hugo server`

If you don't have any busy ports, by default hugo will start at `http://localhost:1313/`


This is interactive writing, so you need to prepare a code editor that support Markdown, like Visual Code, Sublime, Notepad++ or Vim, whatever works.

If you name is not appeared as a folder in `content/authors/`, then:

- `hugo new  --kind authors authors/new_name`. Replace `new_name` with the nickname you want. 
- `cd content/authors/new_name/`
- Pick a png or jpg picture that represent you, name it `avatar.jpg` or `avatar.png`
- Modify `_index.md`

Done. You only need to do this once. Then commit it. 

- `git add content/authors/new_name`
- `git commit -m "Add myself to Efiens Blog"`

To start to write a post, then: 

- `hugo new --kind post post/this-is-a-post`. Remember the `-` is important, it's automatically replace by space in the title. Why there is `-` there? Because `bash` separate arguments by space. 
- `cd content/post/this-is-a-post/`
- Edit `index.md`, if you want to use **Asciidoc** like me, just rename it to `index.adoc`. 
- If you want to attach any image, just include the image in same folder, then call it.

image::efiens.png[]

Done. You can start to write a post. 


In case you get errors:

- `Ctr+C` to stop hugo and then run `hugo server` again. Sometime the error from cache. 
- Undo what you just did, because what you're writing in the markdown file is rendering in real time. 

Syntax highting is available, supported languages are at `config/_default/params.toml` line 60, if your language is not there, then add one. 

To add the right language, check here: `https://cdnjs.com/libraries/highlight.js/`. `Ctr+F` search for `languages/java`, it's case sensitive so you want to grab the right name. 

```c
int8_t shift1(int32_t edx, int8_t eax)
{
	int32_t t1, t2, t3;
	uint32_t ut1, ut2, ut3;

	int32_t ret;

	edx = edx + eax;
	t1 = edx;
	t2 = (int32_t) t1 >> 0x1f;
	ut2 = (uint32_t)t2 >> 0x1c;
	t3 = edx + ut2;
	t3 = t3 & 0xf;
	t3 = edx - eax;

	return t3;	
```

After you done with writing the post, it's time to `commit` and `push` to Efiens Organization repo. 
Run: 

- `git add content/post/this-is-a-post`
- `git commit -m "Add post for CTF xyz"`


Done. Easy. 

Finish? Check to see if you missed anything ? 

- Run `git push` and your content will be publish within 1 minutes. 

Netlify will rebuild the website right after it changes. 

So quick and so easy. 


### Do I need to care about other files? 

No, you only need to care about `content/authors` and `content/post`

- Each folder in `content/authors` represent for each `author`
- Each folder in `content/post` represent for each `post`

### What about other files? 

This blog.efiens.com will not stop here, we will add more features to this blog, since it support many many features, we can add `talks`, `publication` section to our blog.

Eventually, this blog become a wikipedia for us, the collection of our knowledge. 

## Conclusion

New blogging platform is awesome. We are not longer stick at one simple central web server. You can feel free to port your CTF writeup in markdown in here. Just copy and paste it. 

Done. 