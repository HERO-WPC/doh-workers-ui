' monitor-watchdog-hidden.vbs - launch monitor-watchdog.ps1 with NO visible window.
'
' Why: the scheduled task doh-monitor-watchdog runs every 5 minutes as the logged-on
' user (InteractiveToken), so running powershell.exe directly flashed a console
' window on the desktop every 5 minutes. wscript has no console of its own, and
' WshShell.Run with window style 0 starts powershell without ever showing a window.
'
' The task action is therefore:
'   wscript.exe //B "D:\...\tools\monitor-watchdog-hidden.vbs"
'
' Keep this file ASCII-only with CRLF endings.
Option Explicit

Dim fso, sh, here, ps1, cmd
Set fso = CreateObject("Scripting.FileSystemObject")
Set sh  = CreateObject("WScript.Shell")

here = fso.GetParentFolderName(WScript.ScriptFullName)
ps1  = here & "\monitor-watchdog.ps1"

If Not fso.FileExists(ps1) Then
    ' Nothing to run - exit quietly. (The watchdog itself logs to monitor-watchdog.log.)
    WScript.Quit 1
End If

cmd = "powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File """ & ps1 & """"

' 0 = hidden window, True = wait for it to finish (the task instance lasts a few seconds)
sh.Run cmd, 0, True
