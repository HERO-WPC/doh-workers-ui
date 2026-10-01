@echo off
rem Start the DoH monitor. Safe to run more than once:
rem if port 8080 is already listening, an instance is running, so skip.
rem NOTE: keep this file ASCII-only with CRLF endings - cmd.exe reads .bat
rem       in the OEM code page, so non-ASCII comments get mangled into commands.
rem
rem Full parameter set (matches the instance normally run). Do NOT drop the
rem --itdog group: without it the national-evaluation feature stays off and the
rem /itdog panel would only show historical data.
rem   --count 8                             keep 8 A records in DNS (DoH main domain)
rem   --interval 600                        10 min high-frequency probe round
rem   --pool-interval 7200                  2 h full-pool probe
rem   --itdog --itdog-top 35 --itdog-port 443 --itdog-weight 0.5
rem   --itdog-hours 5 --itdog-sleep 28 --itdog-max-age 48
rem                                          national eval: top35 / 5 h / 28 s throttle
rem   --upgrade-score-gain 3.0              min score gain before replacing a DNS IP
rem   --min-samples 24 --min-availability 90 --min-serve-hours 4 --hysteresis 5.0
rem   --monitor-domains ...                 domain end-to-end + national check
rem   --ntprxx-patrol ...                   reverse-proxy domain A-record patrol:
rem                                          if any IP drops below 95% national
rem                                          reachability, replace it with the best
rem                                          itdog-scored candidate (add-then-delete)
rem
rem Defaults kept implicit: --db tools\monitor.db, --pool tools\ips-latest.csv,
rem web 0.0.0.0:8080; DoH host/path, panel auth path, monitored domains and the
rem patrol zone all come from tools\.monitor.env (see .monitor.env.example).
cd /d "%~dp0.."
netstat -an | findstr ":8080 " | findstr /i "LISTENING" >nul 2>&1
if not errorlevel 1 (
  echo [monitor-start] port 8080 already listening - monitor running, skip
  exit /b 0
)
start "" /b pythonw tools\monitor.py --count 8 --interval 600 --pool-interval 7200 --itdog --itdog-top 35 --itdog-port 443 --itdog-weight 0.5 --itdog-hours 5 --itdog-sleep 28 --itdog-max-age 48 --upgrade-score-gain 3.0 --min-samples 24 --min-availability 90 --min-serve-hours 4 --hysteresis 5.0 --ntprxx-patrol --ntprxx-threshold 95 --ntprxx-hours 3 --ntprxx-sleep 28 --ntprxx-keep 3 >> "%~dp0monitor-stdout.log" 2>&1