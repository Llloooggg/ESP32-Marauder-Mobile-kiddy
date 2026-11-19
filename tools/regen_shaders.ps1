<#
.SYNOPSIS
    Compiles the Vulkan compute shaders in app/src/main/cpp/shader and writes the
    SPIR-V into headers the native library includes.

.DESCRIPTION
    Keep the .comp source and the generated _spv.h in the same commit. The reason the
    check has to exist at all is that nobody can eyeball SPIR-V: what makes a bad
    shader impossible to ship by accident is that the app runs a known-answer test
    through the driver on the device (mkgpu::self_test) and refuses the GPU backend
    when it fails, so a stale or wrong header shows up as "GPU refused: <reason>"
    rather than as wrong cracking results.

    Requires the NDK's shader-tools (glslc), which ships with the NDK this repo pins.

.EXAMPLE
    tools\regen_shaders.ps1
    tools\regen_shaders.ps1 -NdkDir "$env:LOCALAPPDATA\Android\Sdk\ndk\27.0.12077973"
#>
param(
    [string]$NdkDir = "$env:LOCALAPPDATA\Android\Sdk\ndk\27.0.12077973"
)

$ErrorActionPreference = 'Stop'

$repoRoot = Split-Path -Parent $PSScriptRoot
$cppDir = Join-Path $repoRoot 'app\src\main\cpp'
$shaderDir = Join-Path $cppDir 'shader'
$glslc = Join-Path $NdkDir 'shader-tools\windows-x86_64\glslc.exe'
if (-not (Test-Path $glslc)) { throw "glslc not found at $glslc (pass -NdkDir)" }

foreach ($comp in Get-ChildItem -Path $shaderDir -Filter '*.comp') {
    $baseName = [System.IO.Path]::GetFileNameWithoutExtension($comp.Name)
    $outHeader = Join-Path $cppDir ($baseName + '_spv.h')
    $tmpSpv = Join-Path $env:TEMP ($baseName + '.spv')

    & $glslc '--target-env=vulkan1.0' '-O' '-o' $tmpSpv $comp.FullName 2>&1 | ForEach-Object { $_.ToString() }
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path $tmpSpv)) {
        throw "glslc failed for $($comp.Name)"
    }

    $bytes = [System.IO.File]::ReadAllBytes($tmpSpv)
    if ($bytes.Length % 4 -ne 0) { throw "$($comp.Name): SPIR-V length $($bytes.Length) is not a multiple of 4" }
    $words = [uint32[]]::new($bytes.Length / 4)
    for ($i = 0; $i -lt $words.Length; $i++) {
        $words[$i] = [uint32]$bytes[$i * 4] -bor ([uint32]$bytes[$i * 4 + 1] -shl 8) -bor
                     ([uint32]$bytes[$i * 4 + 2] -shl 16) -bor ([uint32]$bytes[$i * 4 + 3] -shl 24)
    }

    $sb = [System.Text.StringBuilder]::new()
    [void]$sb.AppendLine('// GENERATED from shader/' + $comp.Name + ' by tools/regen_shaders.ps1 - do not edit by hand.')
    [void]$sb.AppendLine('// Regenerate after changing the shader; the device-side known-answer test in')
    [void]$sb.AppendLine('// vulkan_engine.cpp is what catches a header that no longer matches its source.')
    [void]$sb.AppendLine('//')
    [void]$sb.AppendLine('// Little-endian uint32 words, i.e. the SPIR-V binary image verbatim.')
    [void]$sb.AppendLine('#pragma once')
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine('#include <cstddef>')
    [void]$sb.AppendLine('#include <cstdint>')
    [void]$sb.AppendLine('')
    [void]$sb.AppendLine('namespace mkshader {')
    [void]$sb.AppendLine('inline const uint32_t ' + $baseName + '_spv[] = {')
    for ($i = 0; $i -lt $words.Length; $i += 8) {
        $take = [Math]::Min(8, $words.Length - $i)
        $line = @()
        for ($j = 0; $j -lt $take; $j++) { $line += ('0x' + $words[$i + $j].ToString('x8') + 'u') }
        [void]$sb.AppendLine('    ' + ($line -join ', ') + ',')
    }
    [void]$sb.AppendLine('};')
    [void]$sb.AppendLine('inline const size_t ' + $baseName + '_spv_len = sizeof(' + $baseName + '_spv);')
    [void]$sb.AppendLine('}  // namespace mkshader')

    [System.IO.File]::WriteAllText($outHeader, $sb.ToString())
    "generated $outHeader  ($($bytes.Length) bytes of SPIR-V)"
}
