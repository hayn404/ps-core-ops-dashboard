@echo off
REM Daily TCP-KPI export — called by Windows Task Scheduler.
REM Refreshes the Kerberos ticket from the keytab (no password needed),
REM then runs the export. Java/JDBC reads the ticket from the cache below
REM (jaas.conf uses useTicketCache=true), same as DBeaver does.
cd /d "%~dp0\.."

set KRB5CCNAME=FILE:%TEMP%\krb5cc
"C:\Program Files\MIT\Kerberos\bin\kinit" -kt C:\ProgramData\MIT\Kerberos5\ossuser.keytab ossuser >> tools\daily_update.log 2>&1
if errorlevel 1 (
    echo %DATE% %TIME% kinit FAILED - check VPN and keytab path >> tools\daily_update.log
    exit /b 1
)

call .venv\Scripts\activate
python tools\daily_update.py
