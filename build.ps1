function Initialize-CIPolicy {
  param ([string]$FilePath, [string]$PolicyID, [string]$BasePolicyID, [string]$PolicyVersion)

  $PolicyXML = [xml](Get-Content $FilePath)

  $SiPolicyElement = $PolicyXML.SiPolicy

  $PolicyIDElement = $PolicyXML.CreateElement("PolicyID", $SiPolicyElement.NamespaceURI)
  $PolicyIDElement.InnerText = $PolicyID
  $BasePolicyIDElement = $PolicyXML.CreateElement("BasePolicyID", $SiPolicyElement.NamespaceURI)
  $BasePolicyIDElement.InnerText = $BasePolicyID
  $PlatformIDElement = $PolicyXML.CreateElement("PlatformID", $SiPolicyElement.NamespaceURI)
  $PlatformIDElement.InnerText = '{2E07F7E4-194C-4D20-B7C9-6F44A6C5A234}'
  $VersionExElement = $PolicyXML.CreateElement("VersionEx", $SiPolicyElement.NamespaceURI)
  $VersionExElement.InnerText = $PolicyVersion

  $SiPolicyElement.AppendChild($PolicyIDElement) | Out-Null
  $SiPolicyElement.AppendChild($BasePolicyIDElement) | Out-Null
  $SiPolicyElement.AppendChild($PlatformIDElement) | Out-Null
  $SiPolicyElement.AppendChild($VersionExElement) | Out-Null

  Set-Content $FilePath $PolicyXML.OuterXml
}

function Update-DenyRules {
  param ([string]$FilePath)

  $PolicyXML = [xml](Get-Content $FilePath)
  $denyRuleIDs = @()

  foreach ($denyRule in $PolicyXML.SiPolicy.FileRules.GetElementsByTagName("Deny")) {
    $denyRuleIDs += $denyRule.ID
  }

  foreach ($allowedSigner in $PolicyXML.GetElementsByTagName("AllowedSigner")) {
    foreach ($denyRuleID in $denyRuleIDs) {
      $exceptDenyRuleElement = $PolicyXML.CreateElement("ExceptDenyRule", $PolicyXML.SiPolicy.NamespaceURI)
      $exceptDenyRuleElement.SetAttribute("DenyRuleID", $denyRuleID)
      $allowedSigner.AppendChild($exceptDenyRuleElement) | Out-Null
    }
  }

  Set-Content $FilePath $PolicyXML.OuterXml
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

if ($null -eq $config.PolicyVersion) {
  $config.PolicyVersion = "0.0.0.0"
}

$policyVersion = [version]::Parse($config.PolicyVersion)
$nextPolicyVersion = [version]::new($policyVersion.Major, $policyVersion.Minor, $policyVersion.Build + 1, $policyVersion.Revision)
$config.PolicyVersion = "$nextPolicyVersion"

ConvertTo-Json $config | Out-File policyInfo.json

$DeviceProtection_Lock_ID = '{' + $config.LockPolicyID + '}'
$DeviceProtection_Unlock_ID = '{' + $config.UnlockPolicyID + '}'

$lp_subject = 'CN=Device Protection Local Policy Signer'

$installationPath = & "${ENV:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe" `
  -sort `
  -prerelease `
  -requires Microsoft.VisualStudio.Component.Windows10SDK.* Microsoft.VisualStudio.Component.Windows11SDK.* `
  -requiresAny `
  -property installationPath
if ($installationPath -and (Test-Path "$installationPath\Common7\Tools\vsdevcmd.bat")) {
  :loop foreach ($var in @(& "${ENV:COMSPEC}" /s /c "`"$installationPath\Common7\Tools\vsdevcmd.bat`" -no_logo && set")) {
    $name, $value = $var -split '=', 2
    if ($name -eq 'PATH') {
      foreach ($searchPath in $value -split ';') {
        if (Test-Path "$searchPath\signtool.exe") {
          $signtool = "$searchPath\signtool.exe"
          break loop
        }
      }
    }
  }
}

if ($null -eq $signtool) {
  Write-Host 'Cannot find signtool.exe, aborting'
  exit 1
}

if (Test-Path out) {
  Remove-Item -Recurse -Force out
}

if (Test-Path tmp) {
  Remove-Item -Recurse -Force tmp
}

New-Item -Path out -ItemType Directory | Out-Null
New-Item -Path tmp -ItemType Directory | Out-Null

$lp_cert = Get-ChildItem -Path Cert:\CurrentUser\My | Where-Object Subject -EQ $lp_subject

if ($null -eq $lp_cert) {
  $lp_cert = New-SelfSignedCertificate `
    -CertStoreLocation Cert:\CurrentUser\My `
    -Type CodeSigningCert `
    -Subject $lp_subject
}

Export-Certificate -Cert $lp_cert -FilePath tmp\DeviceProtection_LocalPolicySigner.cer | Out-Null
Copy-Item templates\* tmp
Copy-Item templates\DeviceProtection_Lock.xml tmp\DeviceProtection_Removal.xml

Update-DenyRules tmp\DeviceProtection_Lock.xml
Update-DenyRules tmp\DeviceProtection_Removal.xml

Initialize-CIPolicy -FilePath tmp\DeviceProtection_Lock.xml -PolicyID $DeviceProtection_Lock_ID -BasePolicyID $DeviceProtection_Lock_ID -PolicyVersion "$policyVersion"
Initialize-CIPolicy -FilePath tmp\DeviceProtection_Removal.xml -PolicyID $DeviceProtection_Lock_ID -BasePolicyID $DeviceProtection_Lock_ID -PolicyVersion "$policyVersion"
Initialize-CIPolicy -FilePath tmp\DeviceProtection_Unlock.xml -PolicyID $DeviceProtection_Unlock_ID -BasePolicyID $DeviceProtection_Lock_ID -PolicyVersion "$policyVersion"

Add-SignerRule -FilePath tmp\DeviceProtection_Lock.xml -CertificatePath tmp\DeviceProtection_LocalPolicySigner.cer -Update -Supplemental
Add-SignerRule -FilePath tmp\DeviceProtection_Removal.xml -CertificatePath tmp\DeviceProtection_LocalPolicySigner.cer -Update -Supplemental
Add-SignerRule -FilePath tmp\DeviceProtection_Unlock.xml -CertificatePath tmp\DeviceProtection_LocalPolicySigner.cer -Update

Set-RuleOption -FilePath tmp\DeviceProtection_Removal.xml -Option 3
Set-RuleOption -FilePath tmp\DeviceProtection_Removal.xml -Option 6

Set-CIPolicyIdInfo -FilePath tmp\DeviceProtection_Lock.xml -PolicyName "Device Protection Lock Policy" -PolicyId "DeviceProtection_Lock"
Set-CIPolicyIdInfo -FilePath tmp\DeviceProtection_Removal.xml -PolicyName "Device Protection Removal Policy" -PolicyId "DeviceProtection_Removal"
Set-CIPolicyIdInfo -FilePath tmp\DeviceProtection_Unlock.xml -PolicyName "Device Protection Unlock Key" -PolicyId "DeviceProtection_Unlock"

ConvertFrom-CIPolicy tmp\DeviceProtection_Lock.xml tmp\DeviceProtection_Lock.cip | Out-Null
ConvertFrom-CIPolicy tmp\DeviceProtection_Unlock.xml tmp\DeviceProtection_Unlock.cip | Out-Null
ConvertFrom-CIPolicy tmp\DeviceProtection_Removal.xml tmp\DeviceProtection_Removal.cip | Out-Null

& $signtool sign -v -f tmp\DeviceProtection_LocalPolicySigner.cer -p7 out -p7co 1.3.6.1.4.1.311.79.1 -fd sha256 tmp\*.cip
