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
$pieces = foreach ($t in $tokens) {
    switch ($t.Kind) {
        'Comment'        { continue }
        'LineContinuation' { continue }
        'EndOfInput'     { continue }
        'NewLine'        { [pscustomobject]@{ Kind='Sep'; Text=';' }; continue }
        default {
            [pscustomobject]@{ Kind = "$($t.Kind)"; Text = $t.Extent.Text }
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

    # Need a space when two "word-like" characters would otherwise fuse, OR when
    # the next token is a parameter (-Foo) following a word (so `Get-LocalUser-Name`
    # doesn't collapse), OR between two string/number literals.
    $needSpace = $false
    if ((Test-WordChar $prevLast) -and (Test-WordChar $currFirst)) { $needSpace = $true }
    elseif ($p.Kind -eq 'Parameter' -and (Test-WordChar $prevLast))  { $needSpace = $true }
    elseif ($prev.Kind -eq 'Parameter' -and (Test-WordChar $currFirst)) { $needSpace = $true }
    elseif ($prevLast -eq "'" -or $prevLast -eq '"') {
        # Literal string just ended; a following word char would be parsed as part
        # of a new command — keep them separated unless an operator/punct follows.
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
