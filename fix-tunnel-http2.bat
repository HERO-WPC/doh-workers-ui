@echo off
chcp 65001 >nul
echo [1/3] 将 cloudflared 服务改为 HTTP/2(绕过 QUIC 被干扰)...
sc config cloudflared binPath= "D:\桌面\doh-workers-ui\tools\cloudflared.exe tunnel run --protocol http2 --token-file C:\ProgramData\cloudflared\token"
echo [2/3] 重启服务...
net stop cloudflared
net start cloudflared
echo [3/3] 当前状态:
sc query cloudflared | findstr STATE
timeout /t 5 >nul
