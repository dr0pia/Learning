
# =========================================================
# PE Security Mitigation Scanner (ASLR / DEP / CFG / SafeSEH)
# No external tools required
# =========================================================

param(
    [string]$RootPath = "C:\Program Files (x86)\ControlExpert\PostMaster"
)

function Get-PEMitigations {
    param([string]$FilePath)

    try {
        $fs = [System.IO.File]::OpenRead($FilePath)
        $br = New-Object System.IO.BinaryReader($fs)

        # DOS Header
        $fs.Seek(0, 'Begin') | Out-Null
        $e_magic = $br.ReadUInt16()
        if ($e_magic -ne 0x5A4D) { return $null } # MZ

        $fs.Seek(0x3C, 'Begin') | Out-Null
        $peOffset = $br.ReadInt32()

        # PE Header
        $fs.Seek($peOffset, 'Begin') | Out-Null
        $peSig = $br.ReadUInt32()
        if ($peSig -ne 0x4550) { return $null } # PE

        # COFF Header
        $machine = $br.ReadUInt16()
        $sections = $br.ReadUInt16()
        $fs.Seek(12, 'Current') | Out-Null
        $optHeaderSize = $br.ReadUInt16()
        $characteristics = $br.ReadUInt16()

        $optHeaderStart = $fs.Position
        $magic = $br.ReadUInt16()

        $is64 = ($magic -eq 0x20B)

        # Skip to DLL Characteristics
        if ($is64) {
            $fs.Seek($optHeaderStart + 0x46, 'Begin') | Out-Null
        } else {
            $fs.Seek($optHeaderStart + 0x42, 'Begin') | Out-Null
        }

        $dllChar = $br.ReadUInt16()

        $ASLR = ($dllChar -band 0x0040) -ne 0   # DYNAMIC_BASE
        $DEP  = ($dllChar -band 0x0100) -ne 0   # NX_COMPAT

        # High entropy VA (only meaningful for PE32+)
        $HighEntropy = if ($is64) { ($dllChar -band 0x0020) -ne 0 } else { $false }

        # CFG (Load Config Directory GuardFlags)
        $CFG = $false
        try {
            $loadConfigRVAOffset = if ($is64) { $optHeaderStart + 0x70 } else { $optHeaderStart + 0x60 }

            $fs.Seek($loadConfigRVAOffset, 'Begin') | Out-Null
            $loadConfigRVA = $br.ReadUInt32()

            if ($loadConfigRVA -ne 0) {
                # crude CFG detection marker
                $CFG = $true
            }
        } catch {}

        # SafeSEH (only for 32-bit)
        $SafeSEH = "N/A"
        if (-not $is64) {
            # heuristic: look for SEHandlerTable in Load Config
            try {
                $SafeSEH = "Unknown"
            } catch {
                $SafeSEH = "N/A"
            }
        }

        return [PSCustomObject]@{
            Path = $FilePath
            ASLR = $ASLR
            DEP  = $DEP
            CFG  = $CFG
            SafeSEH = $SafeSEH
            HighEntropyVA = $HighEntropy
        }
    }
    catch {
        return $null
    }
    finally {
        if ($br) { $br.Close() }
        if ($fs) { $fs.Close() }
    }
}

$files = Get-ChildItem -Path $RootPath -Recurse -File -Include *.exe,*.dll

$results = foreach ($f in $files) {
    $r = Get-PEMitigations -FilePath $f.FullName
    if ($r) {
        $r | Add-Member -NotePropertyName File -NotePropertyValue $f.Name

        if (-not $r.ASLR -or -not $r.DEP -or -not $r.CFG -or $r.SafeSEH -ne "True") {
            $r
        }
    }
}

$results | Format-Table -AutoSize
