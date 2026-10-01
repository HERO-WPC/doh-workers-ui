@echo off
rem ---------------------------------------------------------------------------
rem Wrapper for the LOCAL-ONLY repo (.git-local).
rem
rem That repo tracks only what must never be published: the reverse-engineering
rem tooling (itdog/ kkce/ tcptest/ tcping/), scraped page/JS artifacts, and the
rem internal design/dev notes. Everything publishable (worker-doh + tools/) lives
rem in the main repo .git instead.
rem
rem Usage (from the repo root, or anywhere via tools\git-local.bat):
rem   tools\git-local.bat status
rem   tools\git-local.bat log --oneline
rem   tools\git-local.bat add itdog
rem   tools\git-local.bat commit -m "..."
rem
rem Why "add" forces -f: both repos share the same working tree, and the main
rem .gitignore already marks the local-only files as ignored. Ignore rules can
rem only be added, never overridden -> a forced add is the only way in.
rem !! NEVER use -f with "." or -A: that would also stage tools/monitor.db (38 MB),
rem    .cf-token and .monitor.env. Always pass explicit paths.
rem
rem Keep this file ASCII-only with CRLF endings (cmd.exe reads .bat in the OEM
rem code page, so non-ASCII text gets mangled).
rem ---------------------------------------------------------------------------
setlocal
set "REPO=%~dp0.."
set "GITDIR=%REPO%\.git-local"
if not exist "%GITDIR%" (
  echo [git-local] %GITDIR% not found - the local-only repo is not initialized
  exit /b 1
)
if /i "%~1"=="add" (
  if "%~2"=="" (
    echo [git-local] usage: tools\git-local.bat add ^<path^> [more paths...]
    echo             do NOT pass "." or -A: it would stage the db and secrets
    exit /b 2
  )
  git --git-dir="%GITDIR%" --work-tree="%REPO%" add -f %2 %3 %4 %5 %6 %7 %8 %9
) else (
  git --git-dir="%GITDIR%" --work-tree="%REPO%" -c core.quotepath=false %*
)
endlocal
