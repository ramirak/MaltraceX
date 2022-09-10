# Maltrace
## Check your system integrity

<p align="center">
<img src="https://user-images.githubusercontent.com/63206167/189479573-a1c6060a-6069-44db-bdae-b3784ef352d5.png" width="200">
</p>

## Howto

- Before you decide to execute any unknown application take a snapshot of your system.
- Change the scanning path in maltrace.conf to the path you would like to scan.
- The mapping of your system will be saved to a 'hashes.mt' file.
- After you execute any possible malicious file you can run the program again and check the integrity.
- The new mapping will be compared to the old mapping and results will be outputed to a 'traces.mt' file.
- Any update to an existing file or creating of a file will be notified.
- Of course changes to some system files happens all the time so you might see many changes not related to the malicious app.

## Example log

```
----------------------------------------------------------------------------------
--------------------------------Maltrace Log File---------------------------------
----------------------------------------------------------------------------------

Found new trace: /mnt/c/Windows/mal.exe was created on: Sat Sep 10 13:45:17 2022

----------------------------------------------------------------------------------

File - /mnt/c/Windows/system32/svchost.exe has changed on: Sat Sep 10 13:45:17 2022
Original hash : b51183de9bcc1294835d162e757053939ef666dcb8dc083d1326c3c33dd4edbc
Changed hash : 83596dc0a40eee825a51c6844c70a014b28776c1516d53114b71c0ea9c8fd506

----------------------------------------------------------------------------------
```
