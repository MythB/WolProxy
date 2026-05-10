@echo off
pip install -r requirements.txt
if exist "C:\Windows\System32\drivers\npcap.sys" (
    echo Npcap bulundu.
) else (
    echo Lutfen Npcap'i https://npcap.com adresinden indirip kurun.
    pause
    exit /b
)
py -m PyInstaller --onefile --noconsole --icon=wol_proxy.ico --add-data "wol_proxy.ico;." --version-file=version_info.txt --collect-all scapy WolProxy.py
pause