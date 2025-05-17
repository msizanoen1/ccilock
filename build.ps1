function Initialize-CIPolicyGUID {
  param ([string]$FilePath, [string]$PolicyID, [string]$BasePolicyID)
  $PolicyXML = [xml](Get-Content -Path $FilePath)
  $PolicyIDElement = $PolicyXML.CreateElement("PolicyID", $PolicyXML.SiPolicy.NamespaceURI)
  $PolicyIDElement.InnerText = $PolicyID
  $BasePolicyIDElement = $PolicyXML.CreateElement("BasePolicyID", $PolicyXML.SiPolicy.NamespaceURI)
  $BasePolicyIDElement.InnerText = $BasePolicyID
  $PolicyXML.SiPolicy.AppendChild($PolicyIDElement) | Out-Null
  $PolicyXML.SiPolicy.AppendChild($BasePolicyIDElement) | Out-Null
  $PolicyXML.Save($FilePath)
}

if (Test-Path policyInfo.json) {
  $config = Get-Content policyInfo.json | ConvertFrom-Json
}
else {
  $config = @{}
}

if ($null -eq $config.LockPolicyID) {
  $config.LockPolicyID = [guid]::NewGuid().ToString().ToUpper()
}

if ($null -eq $config.UnlockPolicyID) {
  $config.UnlockPolicyID = [guid]::NewGuid().ToString().ToUpper()
}

$policyVersion = [version]::Parse("0.0.0.0")
if ($null -ne $config.PolicyVersion) {
  $policyVersion = [version]::Parse($config.PolicyVersion)
}
$nextPolicyVersion = [version]::new($policyVersion.Major, $policyVersion.Minor, $policyVersion.Build + 1, $policyVersion.Revision)
$config.PolicyVersion = "$nextPolicyVersion"

$config | ConvertTo-Json | Out-File policyInfo.json

$DeviceProtection_Lock_ID = '{' + $config.LockPolicyID + '}'
$DeviceProtection_Unlock_ID = '{' + $config.UnlockPolicyID + '}'

$lp_subject = 'CN=Device Protection Local Policy Signer'

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
New-Item -Path out\removal\efi -ItemType Directory | Out-Null

$lp_cert = Get-ChildItem -Path Cert:\CurrentUser\My `
| Where-Object Subject -EQ $lp_subject

if ($null -eq $lp_cert) {
  $lp_cert = New-SelfSignedCertificate `
    -CertStoreLocation Cert:\CurrentUser\My `
    -Type CodeSigningCert `
    -Subject $lp_subject
}

Export-Certificate -Cert $lp_cert -FilePath out\DeviceProtection_LocalPolicySigner.cer | Out-Null
Copy-Item templates\* out

Initialize-CIPolicyGUID -FilePath out\DeviceProtection_Lock.xml -PolicyID $DeviceProtection_Lock_ID -BasePolicyID $DeviceProtection_Lock_ID
Initialize-CIPolicyGUID -FilePath out\DeviceProtection_Removal.xml -PolicyID $DeviceProtection_Lock_ID -BasePolicyID $DeviceProtection_Lock_ID
Initialize-CIPolicyGUID -FilePath out\DeviceProtection_Unlock.xml -PolicyID $DeviceProtection_Unlock_ID -BasePolicyID $DeviceProtection_Lock_ID

Set-CIPolicyVersion -FilePath out\DeviceProtection_Lock.xml -Version "$policyVersion"
Set-CIPolicyVersion -FilePath out\DeviceProtection_Removal.xml -Version "$policyVersion"
Set-CIPolicyVersion -FilePath out\DeviceProtection_Unlock.xml -Version "$policyVersion"

Add-SignerRule -FilePath out\DeviceProtection_Lock.xml -CertificatePath out\DeviceProtection_LocalPolicySigner.cer -Update -Supplemental
Add-SignerRule -FilePath out\DeviceProtection_Removal.xml -CertificatePath out\DeviceProtection_LocalPolicySigner.cer -Update -Supplemental
Add-SignerRule -FilePath out\DeviceProtection_Unlock.xml -CertificatePath out\DeviceProtection_LocalPolicySigner.cer -Update

ConvertFrom-CIPolicy out\DeviceProtection_Lock.xml out\DeviceProtection_Lock.cip | Out-Null
ConvertFrom-CIPolicy out\DeviceProtection_Unlock.xml out\DeviceProtection_Unlock.cip | Out-Null
ConvertFrom-CIPolicy out\DeviceProtection_Removal.xml out\DeviceProtection_Removal.cip | Out-Null

signtool sign -v -f out\DeviceProtection_LocalPolicySigner.cer -p7 out -p7co 1.3.6.1.4.1.311.79.1 -fd sha256 out\*.cip

Copy-Item -Path out\DeviceProtection_Lock.cip.p7 -Destination out\deploy\efi\${DeviceProtection_Lock_ID}.cip
Copy-Item -Path out\DeviceProtection_Unlock.cip.p7 -Destination out\deploy\system\${DeviceProtection_Unlock_ID}.cip
Copy-Item -Path out\DeviceProtection_Removal.cip.p7 -Destination out\removal\efi\${DeviceProtection_Lock_ID}.cip
