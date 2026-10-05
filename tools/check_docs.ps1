<#
    check_docs.ps1 —— 文档与项目一致性审计

    ============================ 为什么需要它 ============================

    文档一多就会慢慢和代码脱节 —— 版本号忘了改、测试项数对不上、
    目录重排后路径失效、配置项加了没写。这类错误**不会让程序崩**，
    只会让接手的人白费功夫，所以最容易积累。

    这个脚本把那些"会被改动的数字与路径"抽出来自动核对。
    提交前跑一遍，或者加进发布流程。

    用法（任意目录）：
        powershell -NoProfile -ExecutionPolicy Bypass -File tools\check_docs.ps1

    退出码：0 = 没发现问题；1 = 有需要看的地方（细节打在输出里）

    注意：脚本会**跳过 _archive/**（那是历史快照，里面的旧数字是对的）。
#>

$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent $PSScriptRoot
$script:bad = 0

function Ok  ($m) { Write-Host "  [OK]  $m" -ForegroundColor Green }
function Bad ($m) { Write-Host "  [BAD] $m" -ForegroundColor Red; $script:bad++ }
function Note($m) { Write-Host "  [--]  $m" -ForegroundColor DarkGray }

function ReadU8($path) { [System.IO.File]::ReadAllText($path, [System.Text.Encoding]::UTF8) }

# 要审计的文档（排除归档快照）
$docs = @()
$docs += Get-ChildItem $repo -File -Filter *.md -ErrorAction SilentlyContinue
$docs += Get-ChildItem "$repo\开发文档" -File -Filter *.md -ErrorAction SilentlyContinue
$docs  = $docs | Where-Object { $_.FullName -notmatch '\\_archive\\' } | Sort-Object FullName

Write-Host "`n审计仓库：$repo" -ForegroundColor White
Write-Host "文档数：$($docs.Count)`n" -ForegroundColor DarkGray

# ---------------------------------------------------------------- 1) 版本号
Write-Host "=== 1) 版本号 ===" -ForegroundColor Cyan
$srcC = ReadU8 "$repo\src\FairGuard.c"
$ver  = [regex]::Match($srcC, 'GUARD_VERSION\s+"([^"]+)"').Groups[1].Value
Note "源码 GUARD_VERSION = $ver"

$verBad = 0
foreach ($f in $docs) {
    $t = ReadU8 $f.FullName
    foreach ($m in [regex]::Matches($t, 'FairGuard\s+(\d+\.\d+)\s+start')) {
        if ($m.Groups[1].Value -ne $ver) { Bad "$($f.Name)：启动头示例写的是 $($m.Groups[1].Value)，当前 $ver"; $verBad++ }
    }
    foreach ($m in [regex]::Matches($t, '\|\s*版本\s*\|\s*\**(\d+\.\d+)\**')) {
        if ($m.Groups[1].Value -ne $ver) { Bad "$($f.Name)：版本表写的是 $($m.Groups[1].Value)，当前 $ver"; $verBad++ }
    }
}
if ($verBad -eq 0) { Ok "所有启动头示例与版本表都是 $ver" }

# ---------------------------------------------------------------- 2) 自检项数
Write-Host "`n=== 2) 自检项数 ===" -ForegroundColor Cyan
$nDet = ([regex]::Matches((ReadU8 "$repo\test\test_detector.c"), '\bcheck\("')).Count
$nAbi = ([regex]::Matches((ReadU8 "$repo\test\test_abi.c"),      '\bcheck\("')).Count
Note "test_detector = $nDet 项，test_abi = $nAbi 项"

$nBad = 0
foreach ($f in $docs) {
    $t = ReadU8 $f.FullName
    # 抓 "判据...NN 项" 与 "调用约定...NN 项" 这类表述
    foreach ($m in [regex]::Matches($t, '判据[^\n。]{0,14}?(\d+)\s*项')) {
        if ([int]$m.Groups[1].Value -ne $nDet) { Bad "$($f.Name)：'$($m.Value)' —— 实际 $nDet 项"; $nBad++ }
    }
    foreach ($m in [regex]::Matches($t, '调用约定[^\n。]{0,14}?(\d+)\s*项')) {
        if ([int]$m.Groups[1].Value -ne $nAbi) { Bad "$($f.Name)：'$($m.Value)' —— 实际 $nAbi 项"; $nBad++ }
    }
}
if ($nBad -eq 0) { Ok "文档提到的自检项数与代码一致" }

# ------------------------------------------------------- 3) 文件大小（提醒性质）
Write-Host "`n=== 3) 编译产物大小 ===" -ForegroundColor Cyan
$dll = "$repo\FairGuard.dll"
$rep = "$repo\FairGuardReport.exe"
if (Test-Path $dll) {
    $kb = [math]::Round((Get-Item $dll).Length / 1KB)
    Note "FairGuard.dll 实际 $((Get-Item $dll).Length) 字节（约 $kb KB）"
    # 每次编译字节数都不同（链接器不确定），所以文档里不该写死精确值。
    # 逐行检查，并支持 <!-- check-docs:ignore --> 忽略标记 --
    # 历史叙述里会出现"原来写着 37,005 字节"这种句子，那是对的，不该报。
    foreach ($f in $docs) {
        foreach ($line in ((ReadU8 $f.FullName) -split "`n")) {
            if ($line -match 'check-docs:ignore') { continue }
            foreach ($m in [regex]::Matches($line, 'FairGuard\.dll[^\n]{0,48}?([\d]{2},[\d]{3})\s*字节')) {
                Bad "$($f.Name)：把 DLL 精确字节数写进文档了（$($m.Groups[1].Value)）—— 每次编译都不同，请改成'约 NN KB'，或在该行加 check-docs:ignore 标记"
            }
        }
    }
} else { Note "FairGuard.dll 不存在（还没编译）" }

# ------------------------------------------------- 4) 文档引用的文件是否存在
Write-Host "`n=== 4) 文档里引用的项目文件 ===" -ForegroundColor Cyan
$pat = '(?<![\w\\/])(?:src|test|tools|开发文档)[\\/][^\s`）)、,，。]+?\.(?:c|h|md|bat|ps1|txt|inj|ini)(?![\w])'
# 文档里也会引用**同工作区的别的项目**（它们是参考资料，不在本仓库里），
# 这些不算"失效引用"，用已知前缀排除掉。
$external = @('RAReplayPlugin', 'ChatBox', 'Ares-Phobos-etc', 'AutoKit', 'NoCopyProtect', 'AutoLoad', '心灵终结')
$miss = 0
foreach ($f in $docs) {
    foreach ($m in [regex]::Matches((ReadU8 $f.FullName), $pat)) {
        $rel = $m.Value -replace '/', '\'
        $isExternal = $false
        foreach ($e in $external) { if ($rel -like "$e*") { $isExternal = $true; break } }
        if ($isExternal) { continue }
        if (-not (Test-Path (Join-Path $repo $rel))) { Bad "$($f.Name)：引用了不存在的文件  $rel"; $miss++ }
    }
}
if ($miss -eq 0) { Ok "文档引用的项目文件都存在" }

# ------------------------------------------------------------- 5) ini 键一致性
Write-Host "`n=== 5) 配置键（ini vs 代码）===" -ForegroundColor Cyan
$iniPath = "$repo\FairGuard.ini"
if (Test-Path $iniPath) {
    $iniKeys = @(); $sec = ''
    foreach ($l in (Get-Content $iniPath -Encoding UTF8)) {
        if ($l -match '^\s*\[(.+)\]') { $sec = $Matches[1]; continue }
        if ($l -match '^\s*([A-Za-z]\w*)\s*=') { $iniKeys += "$sec/$($Matches[1])" }
    }
    $codeKeys = [regex]::Matches($srcC, 'GetPrivateProfile(?:Int|String)A\("([^"]+)",\s*"([^"]+)"') |
                ForEach-Object { "$($_.Groups[1].Value)/$($_.Groups[2].Value)" } | Sort-Object -Unique
    $missing = $codeKeys | Where-Object { $iniKeys -notcontains $_ }
    $extra   = $iniKeys | Where-Object { $codeKeys -notcontains $_ }
    if ($missing) { Bad "代码要读但 ini 里没有：$($missing -join ', ')" } else { Ok "代码要读的键都在 ini 里" }
    if ($extra)   { Bad "ini 里有但代码不读：$($extra -join ', ')" }   else { Ok "ini 里没有多余键" }
} else { Bad "FairGuard.ini 不存在" }

# --------------------------------------------------- 6) .bat 必须纯 ASCII
Write-Host "`n=== 6) .bat 文件必须是纯 ASCII ===" -ForegroundColor Cyan
$batBad = 0
Get-ChildItem $repo -Recurse -Filter *.bat -ErrorAction SilentlyContinue |
  Where-Object { $_.FullName -notmatch '\\_archive\\' } | ForEach-Object {
    $b = [System.IO.File]::ReadAllBytes($_.FullName)
    $n = ($b | Where-Object { $_ -gt 127 }).Count
    if ($n) { Bad "$($_.Name)：含 $n 个非 ASCII 字节（cmd 会按代码页误解析）"; $batBad++ }
    else    { Ok "$($_.Name) 纯 ASCII" }
}
if ($batBad -eq 0 -and -not (Get-ChildItem $repo -Recurse -Filter *.bat)) { Note "没找到 .bat" }

# --------------------------------------------- 7) 编译产物不应被 git 跟踪
Write-Host "`n=== 7) 编译产物不应进 git ===" -ForegroundColor Cyan
Push-Location $repo
$tracked = @(git ls-files | Where-Object { $_ -match '\.(dll|exe|o|zip)$' -and $_ -notmatch '\.inj$' })
Pop-Location
if ($tracked.Count) { Bad "这些产物被 git 跟踪了：$($tracked -join ', ')" } else { Ok "没有产物入库（.inj 不算）" }

# ------------------------------------------------------------------ 汇总
Write-Host "`n" -NoNewline
if ($script:bad -eq 0) {
    Write-Host "================  全部一致  ================" -ForegroundColor Green
    exit 0
} else {
    Write-Host "=========  发现 $($script:bad) 处需要修正  =========" -ForegroundColor Red
    Write-Host "（历史快照 _archive\ 已跳过；叙述历史时提到的旧数字请人工判断）" -ForegroundColor DarkGray
    exit 1
}
