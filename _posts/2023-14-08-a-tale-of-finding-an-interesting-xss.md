---
layout: post
title: A tale of finding an interesting XSS vulnerability
date: 14/08/2023
author: Nehal Zaman
tags: ["xss"]
categories: [writeups]
render_with_liquid: false
---

![](/assets/images/writeups/a-tale-of-finding-an-interesting-xss/banner.png)

# INTRODUCTION 

Hello everyone, I trust you're all doing great. 

Over the past weekend, my friend [samh4cks](https://twitter.com/samh4cks) and I stumbled upon an intriguing XSS vulnerability while participating in a bug bounty program.

The focus of this blog post is to delve into our exciting discovery. So, without further ado, let's dive right in.

# TARGET OVERVIEW

![](/assets/images/writeups/a-tale-of-finding-an-interesting-xss/1.png)

Picture this scenario: we're setting our sights on `target.com`. In our quest, we've encountered a parameter named `labid` that's mirroring itself back in our responses.

To get into the nitty-gritty, we've pinpointed three distinct instances where the input from users is echoing through the system.

```html
.
.
SNIP
.
.
// console.log("wobinich: /<SOME PATH>?label=1234");
// console.log("wowarich: /<SOME PATH>?label=1234");
.
.
SNIP
.
.
<iframe src="/<SOME PATH>?label=1234" name="workfloor" id="workfloor" class="workfloor"></iframe>
.
.
SNIP
.
.
```

This is where the plot thickens. If this user-fed input hasn't undergone proper sanitization, our application becomes susceptible to the nefarious world of `cross-site scripting` (`XSS`) attacks.

# CHECKING WITH NORMAL PAYLOAD

![](/assets/images/writeups/a-tale-of-finding-an-interesting-xss/2.png)

We are using the payload `"></iframe><script>alert(1)</script>`. Our strategy involves cleverly closing the `iframe` tag with the first part `">`, and then fully ending the `iframe` block with the `</iframe>` tag. We then slip in the `script` tags to run our chosen JavaScript code.

Surprisingly, our initial attempt to trigger the sought-after `XSS` hasn't quite hit the mark.

```html
.
.
SNIP
.
.
<iframe src="/<SOME PATH>?label="></if<x>rame><S<x>cript>alert(1)</script>" name="workfloor" id="workfloor" class="workfloor"></iframe>
.
.
SNIP
.
.
```

Things take an intriguing turn as we notice an unusual `<x>` tag sitting between the `iframe` and `script` tags. Interestingly, this tag seems to be standing guard, preventing our injected JavaScript from doing its thing.

```html
.
.
SNIP
.
.
<iframe src="/<SOME PATH>?label="><nehal_samarth>Nehal_Samarth</nehal_samarth>" name="workfloor" id="workfloor" class="workfloor"></iframe>
.
.
SNIP
.
.
```

When we introduce an unfamiliar tag like `nehal_samarth`, a curious thing happens—the mysterious `<x>` tag seems to vanish into thin air. This curious disappearing act hints at some kind of filtering mechanism at play.

# CRLF CHARACTERS TO THE RESCUE

As a refresher, let's recall that there's another location where user input is being echoed.

```html
.
.
SNIP
.
.
// console.log("wowarich: /<SOME PATH>?label=1234");
.
.
SNIP
.
.
```

Given that the above code is within comments, we wouldn't expect our injected code to execute.

However, there's a crafty approach we can employ involving CRLF characters represented as `%0d` and `%0a`. If the backend doesn't properly sanitize these characters, we have a chance to break free from the confines of comments and introduce a new, unremarked line.

![](/assets/images/writeups/a-tale-of-finding-an-interesting-xss/3.png)

In this scenario, we've employed the payload `%0d%0a"%3ETestingCRLF`.

```html
.
.
SNIP
.
.
// console.log("wobinich: /<SOME PATH>?label=
TestingCRLF");
.
.
```

Excitingly, we've managed to successfully venture beyond the limits of the commented line.

# TRIGERRING XSS

Now that we've managed to jump to a new line, let's dive into trying some JavaScript magic.

Our approach involves using a special code: `%0D%0Aalert("XSS");//`. The `%0d%0a` part is like a secret handshake that takes us to a fresh line.

Inside, we have `alert("XSS")`, which is a snippet of JavaScript we want to run. One important thing to note is that we don't need those `script` tags this time. We're sliding our code into a JavaScript function, so the tags aren't necessary. The `;//` at the end is like saying "over and out" to our injected code.

But here's the twist. The function where our code hangs out seems to stash it in the session for safekeeping. The real surprise? The XSS trick only springs to life when we hit that refresh button.

![](/assets/images/writeups/a-tale-of-finding-an-interesting-xss/4.png)

# CONCLUSION

In wrapping things up, firstly, we uncovered a vulnerability in the `labid` parameter, making the application susceptible to XSS mischief. 

However, the usual methods didn't do the trick in this case. So, we took a creative approach by using CRLF injection to slip past the defenses and land on a new line. 

With that foothold, we slyly injected our JavaScript code into a specific function. But here's the twist – this function only springs into action after a good ol' page refresh. And that's how we worked our way around and brought this adventure to a close.

That's all in this writeup.

Thanks for reading this far. Hope you liked it.

