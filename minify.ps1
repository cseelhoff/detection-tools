param(
    [string]$InputFile  = '.\Reset-LocalWinPasswords.ps1',
    [string]$OutputFile = '.\ShortVersion-Reset-LocalWinPasswords.ps1'
)

$src    = Get-Content -Raw $InputFile
$tokens = $null
$errs   = $null
[void][System.Management.Automation.Language.Parser]::ParseInput($src, [ref]$tokens, [ref]$errs)

# Keep the *source text* of every token via its extent; drop comments + line-continuations.
# NewLines we convert to ';' so statement separation survives the collapse.
# Keep extent so we can detect whitespace between tokens in the source.
$pieces = foreach ($t in $tokens) {
    switch ($t.Kind) {
        'Comment'        { continue }
        'LineContinuation' { continue }
        'EndOfInput'     { continue }
        'NewLine'        { [pscustomobject]@{ Kind='Sep'; Text=';'; Start=$t.Extent.StartOffset; End=$t.Extent.EndOffset }; continue }
        default {
            [pscustomobject]@{ Kind = "$($t.Kind)"; Text = $t.Extent.Text; Start=$t.Extent.StartOffset; End=$t.Extent.EndOffset }
        }
    }
}

function Test-WordChar([char]$c) {
    return ($c -match '[A-Za-z0-9_\$]')
}

$sb   = [System.Text.StringBuilder]::new()
$prev = $null
$paren = 0  # depth of ( or [  — newlines inside these are whitespace, not separators
foreach ($p in $pieces) {
    if ($null -eq $prev) { [void]$sb.Append($p.Text); $prev = $p; continue }

    if ($p.Kind -eq 'Sep') {
        if ($paren -gt 0) { $prev = $p; continue }  # newline inside ( or [ -> drop
        # Only emit ';' if last char isn't already a separator/opener.
        $last = if ($sb.Length) { $sb[$sb.Length - 1] } else { ' ' }
        if ($last -notin ';','{','(','[','|','&','=',',') { [void]$sb.Append(';') }
        $prev = $p
        continue
    }

    $prevLast  = $sb[$sb.Length - 1]
    $currFirst = $p.Text[0]

    # Detect whether there was whitespace between prev and curr tokens in the source.
    # If so, we should preserve *at least* a space (critical for native commands
    # like `icacls $akf /grant 'A' 'B'` where arg separation is whitespace).
    $hadSourceGap = ($null -ne $prev.End) -and ($p.Start -gt $prev.End)

    # Safe to fuse (no space needed) when the boundary char pair is unambiguous:
    # punctuation/operator on either side that can't form a new token when joined.
    $safeFuse = $false
    if ($prevLast -in @(';','{','}','(',')','[',']','|','&',',','=','+','*','/','<','>','!','@','`','"',"'")) {
        # But keep quote-to-quote separated (native args), and keep quote-to-word handled below.
        if ($prevLast -notin @("'",'"')) { $safeFuse = $true }
    }
    if ($currFirst -in @(';','{','}','(',')','[',']','|','&',',','=','`',':','.')) {
        $safeFuse = $true
    }

    $needSpace = $false
    if ($hadSourceGap -and -not $safeFuse) { $needSpace = $true }
    elseif ((Test-WordChar $prevLast) -and (Test-WordChar $currFirst)) { $needSpace = $true }
    elseif ($p.Kind -eq 'Parameter' -and (Test-WordChar $prevLast))  { $needSpace = $true }
    elseif ($prev.Kind -eq 'Parameter' -and (Test-WordChar $currFirst)) { $needSpace = $true }
    elseif ($prevLast -eq "'" -or $prevLast -eq '"') {
        if (Test-WordChar $currFirst) { $needSpace = $true }
    }

    if ($needSpace) { [void]$sb.Append(' ') }
    [void]$sb.Append($p.Text)

    # Track paren/bracket depth (naive — ok because tokens are atomic).
    if     ($p.Text -eq '(' -or $p.Text -eq '[') { $paren++ }
    elseif ($p.Text -eq ')' -or $p.Text -eq ']') { if ($paren -gt 0) { $paren-- } }

    $prev = $p
}

$out = $sb.ToString()
# Collapse runs of ';'
$out = $out -replace ';{2,}', ';'
# Trim stray semicolons right after openers or before closers.
$out = $out -replace '([\{\(\[\|])\s*;', '$1'
$out = $out -replace ';(\s*[\}\)\]])', '$1'

Set-Content -Path $OutputFile -Value $out -Encoding ascii -NoNewline
Write-Host "Wrote $OutputFile ($($out.Length) chars)"
if ($errs) { Write-Warning "Parser reported $($errs.Count) error(s) in source." }

# Build base64-encoded Tanium command
$encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($out))
$taniumCmd = "cmd /c %SystemRoot%\SysNative\WindowsPowerShell\v1.0\powershell.exe -ExecutionPolicy Bypass -Command `"& ([scriptblock]::Create([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('$encoded')))) '`$1' '`$2'`""

$taniumFile = '.\tanium-mini.ps1'
Set-Content -Path $taniumFile -Value $taniumCmd -Encoding ascii -NoNewline
Write-Host "Wrote $taniumFile ($($taniumCmd.Length) chars)"
