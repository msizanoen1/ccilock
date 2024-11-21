$lp_subject = 'CN=ConfigCI Local Policy Signer'

$installationPath = & "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe" -prerelease -latest -property installationPath
if ($installationPath -and (test-path "$installationPath\Common7\Tools\vsdevcmd.bat")) {
    & "${env:COMSPEC}" /s /c "`"$installationPath\Common7\Tools\vsdevcmd.bat`" -no_logo && set" | foreach-object {
        $name, $value = $_ -split '=', 2
        set-content env:\"$name" $value
    }
}

if (Test-Path out) {
    Remove-Item -Recurse -Force out
}

New-Item -Path out -ItemType Directory | Out-Null
New-Item -Path out\deploy -ItemType Directory | Out-Null
New-Item -Path out\deploy\efi -ItemType Directory | Out-Null
New-Item -Path out\deploy\system -ItemType Directory | Out-Null

$lp_cert = Get-ChildItem -Path Cert:\CurrentUser\My `
    | Where-Object Subject -EQ $lp_subject

if ($null -eq $lp_cert) {
    $lp_cert = New-SelfSignedCertificate `
        -CertStoreLocation Cert:\CurrentUser\My `
        -Type CodeSigningCert `
        -Subject $lp_subject
}

Export-Certificate -Cert $lp_cert -FilePath out\ConfigCI_LocalPolicySigner.cer | Out-Null
Copy-Item templates\* out

Add-SignerRule -FilePath out\ConfigCI_Lock.xml -CertificatePath out\ConfigCI_LocalPolicySigner.cer -Update -Supplemental

$ConfigCI_Lock_ID = '{d4f068de-ba77-4c40-930f-82710d8f9e23}'
$ConfigCI_Unlock_ID = '{ae010c44-2a28-400c-9e0b-3b0708b30088}'

ConvertFrom-CIPolicy out\ConfigCI_Lock.xml out\ConfigCI_Lock.cip | Out-Null
ConvertFrom-CIPolicy out\ConfigCI_Unlock.xml out\ConfigCI_Unlock.cip | Out-Null

signtool sign -v -f out\ConfigCI_LocalPolicySigner.cer -p7 out -p7co 1.3.6.1.4.1.311.79.1 -fd sha256 out\*.cip

Copy-Item -Path out\ConfigCI_Lock.cip.p7 -Destination out\deploy\efi\${ConfigCI_Lock_ID}.cip
Copy-Item -Path out\ConfigCI_Unlock.cip.p7 -Destination out\deploy\system\${ConfigCI_Unlock_ID}.cip
