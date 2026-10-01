<#
  monitor-watchdog.ps1 —— 检测 DoH monitor 是否在运行; 不在就唤醒(拉起)。

  由计划任务 doh-monitor-watchdog 每 5 分钟调用一次(另注册了"登录时"触发)。
  也可手动跑:  powershell -NoProfile -ExecutionPolicy Bypass -File tools\monitor-watchdog.ps1

  判据(三级, 逐级更严):
    1) 进程: 命令行含 monitor.py 的 python/pythonw 进程数
    2) 端口: 8080 是否 LISTENING
    3) 健康: 对 http://127.0.0.1:8080/ 发一次请求(未认证返回 401 也算"活着" = 服务在应答)
  动作:
    - 无进程 且 无监听            -> 立即拉起 (tools\monitor-start.bat)
    - 有进程 但 无监听/不响应      -> 记一次"异常"; 连续 3 次(约 15 分钟)才判定卡死:
                                     结束该 monitor 进程后拉起
    - 正常                        -> 清空异常计数
  日志: tools\monitor-watchdog.log (超过 1MB 轮转为 .1)
#>
$ErrorActionPreference = 'Continue'
$root   = $PSScriptRoot                     # tools\
$logPath = Join-Path $root 'monitor-watchdog.log'
$cntPath = Join-Path $root '.watchdog-badcount'
$batPath = Join-Path $root 'monitor-start.bat'
$Port   = 8080

function Write-Log([string]$msg) {
    $line = "{0} {1}" -f (Get-Date -Format 'MM-dd HH:mm:ss'), $msg
    try {
        if ((Test-Path $logPath) -and ((Get-Item $logPath).Length -gt 1MB)) {
            Move-Item -Force $logPath ($logPath + '.1')
        }
        Add-Content -Path $logPath -Value $line -Encoding UTF8
    } catch { }
    Write-Output $line
}

function Get-MonitorProcs {
    Get-CimInstance Win32_Process -Filter "Name='pythonw.exe' OR Name='python.exe'" -ErrorAction SilentlyContinue |
        Where-Object { $_.CommandLine -and ($_.CommandLine -match 'monitor\.py') }
}

function Test-Port {
    try {
        return [bool](Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction Stop)
    } catch {
        $o = netstat -an | Select-String (":$Port\s") | Select-String 'LISTENING'
        return [bool]$o
    }
}

function Test-Health {
    # 只要能拿到 HTTP 应答就算活着(未认证会 401, 那也是应答)
    try {
        $r = Invoke-WebRequest -Uri ("http://127.0.0.1:{0}/" -f $Port) -TimeoutSec 5 -UseBasicParsing
        return $true
    } catch {
        if ($_.Exception.Response) { return $true }   # 收到响应(如 401) = 服务在应答
        return $false
    }
}

function Start-Monitor([string]$why) {
    if (-not (Test-Path $batPath)) { Write-Log "!! 找不到 $batPath, 无法拉起"; return }
    # 私有配置缺失时 monitor.py 会故意拒绝启动(占位符 = 会写错 DNS)。这里先拦一道,
    # 否则看门狗每 5 分钟拉起一次、进程立刻退出, 只会刷日志。
    $envPath = Join-Path $root '.monitor.env'
    if (-not (Test-Path $envPath)) {
        Write-Log ("!! 缺少 {0} (私有部署标识), 不拉起 —— monitor.py 会拒绝启动; 模板见 .monitor.env.example" -f $envPath)
        return
    }
    Write-Log ("唤醒: 拉起 monitor ({0})" -f $why)
    Start-Process -FilePath 'cmd.exe' -ArgumentList '/c', ('"{0}"' -f $batPath) -WindowStyle Hidden
    Start-Sleep -Seconds 6
    $p = Get-MonitorProcs
    if ($p) { Write-Log ("已拉起, PID={0}" -f (($p | ForEach-Object { $_.ProcessId }) -join ',')) }
    else    { Write-Log "拉起后仍未发现 monitor 进程(请看 monitor-stdout.log / monitor.log)" }
}

# ---------------- 主流程 ----------------
# 暂停开关: 维护时想故意停掉 monitor, 就在 tools\ 下建一个 .watchdog-pause 文件;
# 看门狗会跳过所有动作(只记一行日志), 删掉该文件即恢复。
$pausePath = Join-Path $root '.watchdog-pause'
if (Test-Path $pausePath) {
    Write-Log "已暂停(存在 .watchdog-pause), 跳过本次检查"
    exit 0
}

$procs  = @(Get-MonitorProcs)
$listen = Test-Port
$alive  = if ($listen) { Test-Health } else { $false }

if ($procs.Count -gt 0 -and $listen -and $alive) {
    if (Test-Path $cntPath) { Remove-Item -Force $cntPath -ErrorAction SilentlyContinue }
    Write-Log ("正常: monitor 在跑 (PID {0}), 8080 监听且应答" -f (($procs | ForEach-Object { $_.ProcessId }) -join ','))
    exit 0
}

if ($procs.Count -eq 0 -and -not $listen) {
    Start-Monitor '无进程且 8080 未监听'
    exit 0
}

# 走到这里 = 有进程但端口不通/不应答, 或(异常地)无进程但端口在监听
$bad = 0
if (Test-Path $cntPath) { $bad = [int](Get-Content $cntPath -ErrorAction SilentlyContinue) }
$bad++
Set-Content -Path $cntPath -Value $bad -Encoding ASCII
Write-Log ("异常第 {0} 次: 进程 {1} 个, 8080 监听={2}, 健康={3}" -f $bad, $procs.Count, $listen, $alive)

if ($bad -ge 3) {
    Write-Log "连续 3 次异常 -> 判定卡死, 结束旧进程后重新拉起"
    foreach ($p in $procs) {
        try { Stop-Process -Id $p.ProcessId -Force -ErrorAction Stop; Write-Log ("  已结束 PID {0}" -f $p.ProcessId) }
        catch { Write-Log ("  结束 PID {0} 失败: {1}" -f $p.ProcessId, $_.Exception.Message) }
    }
    Start-Sleep -Seconds 2
    Remove-Item -Force $cntPath -ErrorAction SilentlyContinue
    Start-Monitor '连续 3 次健康检查失败'
}
exit 0