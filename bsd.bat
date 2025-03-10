@echo off
setlocal

:: Define paths
set SYSMON_DIR=C:\Sysmon
set SYSMON_ZIP_PATH=%USERPROFILE%\Downloads\Sysmon.zip
set SYSMON_URL=https://download.sysinternals.com/files/Sysmon.zip
set SYSMON_CONFIG_URL=https://wazuh.com/resources/blog/emulation-of-attack-techniques-and-detection-with-wazuh/sysmonconfig.xml
set WAZUH_CONFIG_PATH="C:\Program Files (x86)\ossec-agent\ossec.conf"

set YARA_DIR="C:\Program Files (x86)\ossec-agent\active-response\bin\yara"
set YARA_ZIP_PATH=%USERPROFILE%\Downloads\yara.zip
set YARA_URL=https://github.com/VirusTotal/yara/releases/download/v4.5.2/yara-v4.5.2-2326-win64.zip
set YARA_RULES_PY=https://raw.githubusercontent.com/CyberOpsLab/blx-stealer-detection/main/agent/download_yara_rules.py
set YARA_BATCH=https://raw.githubusercontent.com/CyberOpsLab/blx-stealer-detection/main/agent/yara.bat
set YARA_RULES=https://raw.githubusercontent.com/CyberOpsLab/blx-stealer-detection/main/agent/yara_rules.yar

:: --- SYSMON INSTALLATION ---
if not exist "%SYSMON_DIR%" mkdir "%SYSMON_DIR%"
powershell -Command "& {Invoke-WebRequest -Uri '%SYSMON_URL%' -OutFile '%SYSMON_ZIP_PATH%'}"
powershell -Command "& {Expand-Archive -Path '%SYSMON_ZIP_PATH%' -DestinationPath '%SYSMON_DIR%' -Force}"
powershell -Command "& {Invoke-WebRequest -Uri '%SYSMON_CONFIG_URL%' -OutFile '%SYSMON_DIR%\sysmonconfig.xml'}"
cd /d "%SYSMON_DIR%"
Sysmon64.exe -accepteula -i sysmonconfig.xml

:: Update Wazuh configuration
powershell -Command "& {(Get-Content -Path %WAZUH_CONFIG_PATH%) -replace '</ossec_config>', '    <localfile>`r`n      <location>Microsoft-Windows-Sysmon/Operational</location>`r`n      <log_format>eventchannel</log_format>`r`n    </localfile>`r`n</ossec_config>' | Set-Content -Path %WAZUH_CONFIG_PATH%}"

:: --- YARA INSTALLATION ---
if not exist "%YARA_DIR%" mkdir "%YARA_DIR%"
powershell -Command "& {Invoke-WebRequest -Uri '%YARA_URL%' -OutFile '%YARA_ZIP_PATH%'}"
powershell -Command "& {Expand-Archive -Path '%YARA_ZIP_PATH%' -DestinationPath '%YARA_DIR%' -Force}"
powershell -Command "& {Copy-Item -Path '%YARA_DIR%\yara64.exe' -Destination '%YARA_DIR%' -Force}"

:: --- DOWNLOAD YARA RULES & CONFIGURATION ---
powershell -Command "& {Invoke-WebRequest -Uri '%YARA_RULES_PY%' -OutFile '%YARA_DIR%\download_yara_rules.py'}"
powershell -Command "& {Invoke-WebRequest -Uri '%YARA_BATCH%' -OutFile 'C:\Program Files (x86)\ossec-agent\active-response\bin\yara.bat'}"
powershell -Command "& {Invoke-WebRequest -Uri '%YARA_RULES%' -OutFile '%YARA_DIR%\rules\yara_rules.yar'}"

:: Install Python package for YARA rule downloads
python -m pip install valhallaAPI
python "%YARA_DIR%\download_yara_rules.py"

:: --- UPDATE WAZUH CONFIGURATION ---
powershell -Command "& {(Get-Content -Path %WAZUH_CONFIG_PATH%) -replace '</syscheck>', '<directories realtime="yes">C:\Users\*\Downloads</directories>`r`n</syscheck>' | Set-Content -Path %WAZUH_CONFIG_PATH%}"

:: Restart Wazuh agent
powershell -Command "& {Restart-Service -Name wazuh -Force}"

exit
