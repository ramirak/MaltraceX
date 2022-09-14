# MaltraceX
## Check your system integrity and scan for malicious files

<p align="center">
<img src="https://user-images.githubusercontent.com/63206167/189479573-a1c6060a-6069-44db-bdae-b3784ef352d5.png" width="200">
</p>

## How-To

- Before you decide to execute any unknown application take a snapshot of your system.
- Change the scanning path in maltrace.conf to the path you would like to scan.
- Choose wheter you want to scan new hashes with Virus Total and add your VT api key.
- The mapping of your system will be saved to a 'hashes.mt' file.
- After you execute any possible malicious file you can run the program again and check the integrity.
- The new mapping will be compared to the old mapping and results will be outputed to a 'traces.mt' file.
- Any update to an existing file or creating of a file will be notified.
- Of course changes to some system files happens all the time so you might see many changes not related to the malicious app.

## Features 
- Take a snapshot of your system, either on Windows or Linux.
- Scan your system again and compare against your old snapshot and figure out which changes were made.
- Find out if new files were created in your chosen system path.
- Virus Total integration - Choose whether to compare file hashes with VT database to get detection report from dozens of AVs.
- List specific folder files and easily choose which file to scan

## Example log

```
----------------------------------------------------------------------------------
--------------------------------MaltraceX Log File---------------------------------
----------------------------------------------------------------------------------

Found new trace: /mnt/c/Windows/mal.exe was created on: Sat Sep 10 13:45:17 2022
File Hash: 0a73291ab5607aef7db23863cf8e72f55bcb3c273bb47f00edf011515aeb5894

---------------------------------------------------------------------------------------------------
----------------------------------------Virus Total report:----------------------------------------
---------------------------------------------------------------------------------------------------
Total Malicious: 43
Total Undetected: 16
File Reputation: -88
Suggested label: ransomware.wannacryptor/wanna
---------------------------------------------
Engines results:
---------------------------------------------
Bkav - undetected
Lionic - malicious
Elastic - malicious
Cynet - malicious
FireEye - malicious
CAT-QuickHeal - malicious
McAfee - malicious
Malwarebytes - undetected
VIPRE - malicious
Sangfor - malicious
K7AntiVirus - malicious
Alibaba - type-unsupported
K7GW - malicious
CrowdStrike - type-unsupported
Baidu - undetected
VirIT - undetected
Cyren - malicious
SymantecMobileInsight - type-unsupported
Symantec - malicious
tehtris - type-unsupported
ESET-NOD32 - malicious
APEX - type-unsupported
TrendMicro-HouseCall - malicious
Avast - malicious
ClamAV - malicious
Kaspersky - malicious
BitDefender - malicious
NANO-Antivirus - malicious
ViRobot - undetected
MicroWorld-eScan - malicious
Tencent - malicious
Ad-Aware - undetected
Trustlook - type-unsupported
Sophos - malicious
Comodo - malicious
F-Secure - undetected
DrWeb - malicious
Zillya - undetected
TrendMicro - malicious
McAfee-GW-Edition - malicious
SentinelOne - type-unsupported
Trapmine - type-unsupported
Emsisoft - malicious
Paloalto - type-unsupported
GData - malicious
Jiangmin - malicious
Webroot - type-unsupported
Avira - malicious
Kingsoft - undetected
Gridinsoft - malicious
Arcabit - malicious
SUPERAntiSpyware - undetected
ZoneAlarm - undetected
Avast-Mobile - type-unsupported
Microsoft - malicious
TACHYON - undetected
BitDefenderFalx - type-unsupported
AhnLab-V3 - malicious
Acronis - undetected
VBA32 - malicious
ALYac - undetected
MAX - malicious
Cylance - type-unsupported
Zoner - undetected
Rising - malicious
Yandex - undetected
Ikarus - malicious
MaxSecure - malicious
Fortinet - malicious
BitDefenderTheta - malicious
AVG - malicious
Cybereason - type-unsupported
Panda - malicious

----------------------------------------------------------------------------------

File - /mnt/c/Windows/system32/svchost.exe was changed on: Sat Sep 10 13:45:17 2022
Original hash : b51183de9bcc1294835d162e757053939ef666dcb8dc083d1326c3c33dd4edbc
New hash : 83596dc0a40eee825a51c6844c70a014b28776c1516d53114b71c0ea9c8fd506
Could not find file's hash in Virus Total database

----------------------------------------------------------------------------------

```
