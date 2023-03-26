## Persistence - very easy
- At the challenge overview tells us the `/flag` endpoint it retrieves random data for each `GET` request, but told us to keep trying for `1000` times.

![Persistence_overview.png](https://github.com/Sec0gh/CTF/blob/main/Cyber%20Apocalypse%202023%20-%20The%20Cursed%20Mission/Misc%20iamges/Persistence_overview.png)
- Each request sends random data like that.

![Persistence.png](https://github.com/Sec0gh/CTF/blob/main/Cyber%20Apocalypse%202023%20-%20The%20Cursed%20Mission/Misc%20iamges/Persistence.png)
- So there is no other choice but to send many requests to retrieve the flag from all random data, we can do that with a little script using bash.
```bash
$ for i in {1..1000}; do curl http://target_IP:PORT; done
```
- It wasn't continue else for a small number of requests and sent the flag.

![misc.png](https://github.com/Sec0gh/CTF/blob/main/Cyber%20Apocalypse%202023%20-%20The%20Cursed%20Mission/Misc%20iamges/misc.png)

-------
## Restricted - easy
- At first, I tried to connect with the `host IP` and its `PORT`, and it responded with a banner that there is an `SSH` service on this port.
```bash
$ nc 178.62.64.13 31674
SSH-2.0-OpenSSH_8.4p1 Debian-5+deb11u1
```
- With a little of enumeration in the attached files of challenge, there is a user is called `restricted` in the `sshd_config` file.

![Restricted_user.png](https://github.com/Sec0gh/CTF/blob/main/Cyber%20Apocalypse%202023%20-%20The%20Cursed%20Mission/Misc%20iamges/Restricted_user.png)
- I connected with the ssh with the `restricted` user.
```bash
$ ssh restricted@178.62.64.13 -p 31674 
```
- But if I tried to execute any commands, it will display an error message `command not found`.

![Restricted_rbash.png](https://github.com/Sec0gh/CTF/blob/main/Cyber%20Apocalypse%202023%20-%20The%20Cursed%20Mission/Misc%20iamges/Restricted_rbash.png)
- But through the error messages, I have gone to ask google about `rbash`, and I knew it is called a `restricted shell`.
- I did some searches also to how to bypass the Restricted shell and i have caught this resource from:
> https://null-byte.wonderhowto.com/how-to/escape-restricted-shell-environments-linux-0341685/
- I tried a lot of options to bypass it but this one succeeded.
- So we can use this option to escape the restricted shell:
```
ssh user@IP -t "bash --noprofile"
```
- Start a remote shell with an unrestricted profile.
```bash
$ ssh restricted@178.62.64.13 -p 31674 -t "bash --noprofile"
```

![Restricted_flag.png](https://github.com/Sec0gh/CTF/blob/main/Cyber%20Apocalypse%202023%20-%20The%20Cursed%20Mission/Misc%20iamges/Restricted_flag.png)
