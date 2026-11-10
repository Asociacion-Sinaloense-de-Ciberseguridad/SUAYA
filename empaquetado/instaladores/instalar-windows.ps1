<#
.SYNOPSIS
Instala SUAYA en Windows desde el paquete de una publicación.

.DESCRIPTION
Descargue en una misma carpeta el paquete suaya-<versión>-x86_64-pc-windows-msvc.zip,
el archivo SHA256SUMS y este script. Después, haga clic derecho sobre el script y
elija «Ejecutar con PowerShell», o ejecute desde una terminal:

    powershell -ExecutionPolicy Bypass -File .\instalar-windows.ps1

El script verifica la suma SHA-256 del paquete, copia los programas en
%LOCALAPPDATA%\Programs\SUAYA y agrega esa carpeta al PATH de su usuario.
No necesita permisos de administrador.

.PARAMETER Destino
Carpeta de instalación.

.PARAMETER SinPath
No modifica el PATH del usuario.

.PARAMETER Desinstalar
Elimina la carpeta de instalación y la quita del PATH del usuario.

.PARAMETER SinPausa
No espera a que se pulse Enter al terminar.
#>
param(
    [string]$Destino = (Join-Path $env:LOCALAPPDATA 'Programs\SUAYA'),
    [switch]$SinPath,
    [switch]$Desinstalar,
    [switch]$SinPausa
)

$ErrorActionPreference = 'Stop'
$destinoPropio = $PSBoundParameters.ContainsKey('Destino')

function Leer-PathUsuario {
    $clave = [Microsoft.Win32.Registry]::CurrentUser.OpenSubKey('Environment')
    if (-not $clave) { return '' }
    try {
        return [string]$clave.GetValue('Path', '', [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
    } finally {
        $clave.Close()
    }
}

function Escribir-PathUsuario([string]$valor) {
    $clave = [Microsoft.Win32.Registry]::CurrentUser.CreateSubKey('Environment')
    try {
        # ExpandString conserva las entradas con variables, como %USERPROFILE%.
        $clave.SetValue('Path', $valor, [Microsoft.Win32.RegistryValueKind]::ExpandString)
    } finally {
        $clave.Close()
    }
    # Avisa a Windows del cambio para que las terminales nuevas lo vean.
    [Environment]::SetEnvironmentVariable('SUAYA_INSTALADOR', '1', 'User')
    [Environment]::SetEnvironmentVariable('SUAYA_INSTALADOR', $null, 'User')
}

function Es-Destino([string]$entrada) {
    return [Environment]::ExpandEnvironmentVariables($entrada).TrimEnd('\') -ieq $Destino.TrimEnd('\')
}

function Instalar {
    $aqui = $PSScriptRoot
    $paquetes = @(Get-ChildItem -LiteralPath $aqui -Filter 'suaya-*-x86_64-pc-windows-msvc.zip')
    if ($paquetes.Count -eq 0) {
        throw "No se encontró suaya-<versión>-x86_64-pc-windows-msvc.zip en $aqui."
    }
    if ($paquetes.Count -gt 1) {
        throw "Hay varios paquetes de SUAYA en ${aqui}: deje solo el que quiere instalar."
    }
    $paquete = $paquetes[0]

    $sumas = Join-Path $aqui 'SHA256SUMS'
    if (Test-Path -LiteralPath $sumas) {
        $esperado = $null
        foreach ($linea in Get-Content -LiteralPath $sumas) {
            $partes = $linea.Trim() -split '\s+', 2
            if ($partes.Count -eq 2 -and $partes[1].TrimStart('*') -eq $paquete.Name) {
                $esperado = $partes[0].ToLower()
                break
            }
        }
        if (-not $esperado) { throw "SHA256SUMS no incluye $($paquete.Name)." }
        $real = (Get-FileHash -LiteralPath $paquete.FullName -Algorithm SHA256).Hash.ToLower()
        if ($real -ne $esperado) {
            throw "La suma SHA-256 de $($paquete.Name) no coincide con SHA256SUMS: no se instala."
        }
        Write-Host "Suma SHA-256 verificada: $($paquete.Name)"
    } else {
        Write-Warning 'No se encontró SHA256SUMS junto al script: la descarga no se verificó.'
    }

    $temporal = Join-Path ([IO.Path]::GetTempPath()) ('suaya-' + [guid]::NewGuid().ToString('N'))
    try {
        Expand-Archive -LiteralPath $paquete.FullName -DestinationPath $temporal
        $origen = Get-ChildItem -LiteralPath $temporal -Directory | Select-Object -First 1
        if (-not $origen -or -not (Test-Path -LiteralPath (Join-Path $origen.FullName 'suaya.exe'))) {
            throw 'El paquete no contiene suaya.exe.'
        }
        New-Item -ItemType Directory -Force -Path $Destino | Out-Null
        Copy-Item -Path (Join-Path $origen.FullName '*') -Destination $Destino -Recurse -Force
        Get-ChildItem -LiteralPath $Destino -Recurse -File | Unblock-File
    } finally {
        if (Test-Path -LiteralPath $temporal) { Remove-Item -LiteralPath $temporal -Recurse -Force }
    }

    if (-not $SinPath) {
        $entradas = @((Leer-PathUsuario) -split ';' | Where-Object { $_ })
        if (-not ($entradas | Where-Object { Es-Destino $_ })) {
            Escribir-PathUsuario ((@($entradas) + $Destino) -join ';')
            Write-Host "Se agregó $Destino al PATH de su usuario: abra una terminal nueva para usar «suaya»."
        }
    }

    & (Join-Path $Destino 'suaya.exe') --version
    if ($LASTEXITCODE -ne 0) { throw 'suaya.exe no se pudo ejecutar.' }
    Write-Host "SUAYA quedó instalado en $Destino."
    $orden = 'powershell -ExecutionPolicy Bypass -File .\instalar-windows.ps1 -Desinstalar'
    if ($destinoPropio) { $orden += " -Destino `"$Destino`"" }
    Write-Host "Para desinstalarlo: $orden"
}

function Desinstalar {
    # Solo se borra lo que instala el paquete; la carpeta se quita si queda vacía.
    $habia = Test-Path -LiteralPath (Join-Path $Destino 'suaya.exe')
    foreach ($nombre in 'suaya.exe', 'suaya-api.exe', 'LICENSE', 'NOTICE', 'README.md', 'build-manifest.json', 'suaya.1') {
        $archivo = Join-Path $Destino $nombre
        if (Test-Path -LiteralPath $archivo -PathType Leaf) { Remove-Item -LiteralPath $archivo -Force }
    }
    $completado = Join-Path $Destino 'completado'
    if (Test-Path -LiteralPath $completado -PathType Container) { Remove-Item -LiteralPath $completado -Recurse -Force }
    if ((Test-Path -LiteralPath $Destino -PathType Container) -and -not (Get-ChildItem -LiteralPath $Destino -Force)) {
        Remove-Item -LiteralPath $Destino -Force
    }
    if (-not $SinPath) {
        $entradas = @((Leer-PathUsuario) -split ';' | Where-Object { $_ })
        $restantes = @($entradas | Where-Object { -not (Es-Destino $_) })
        if ($restantes.Count -ne $entradas.Count) { Escribir-PathUsuario ($restantes -join ';') }
    }
    if ($habia) {
        Write-Host "SUAYA se desinstaló de $Destino."
    } else {
        Write-Host "No había una instalación de SUAYA en $Destino."
    }
}

$codigo = 0
try {
    if ($Desinstalar) { Desinstalar } else { Instalar }
} catch {
    Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red
    $codigo = 1
}
if (-not $SinPausa) { [void](Read-Host 'Pulse Enter para cerrar') }
exit $codigo