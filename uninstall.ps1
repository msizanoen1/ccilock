$policies = (citool --list-policies --json | ConvertFrom-Json).Policies
$policyInfo = (Get-Content policyInfo.json | ConvertFrom-Json)
$lockPolicyId = $policyInfo.LockPolicyID
$unlockPolicyId = $policyInfo.UnlockPolicyID

$installed = $false
$policyLocked = $false

foreach ($policy in $policies) {
  if ($policy.PolicyID -ieq $lockPolicyId) {
    if ($policy.PolicyOptions -notcontains 'Enabled:Unsigned System Integrity Policy') {
      $policyLocked = $true
    }
    $installed = $true
    break
  }
}

if (!$installed) {
  Write-Host 'Policy not installed'
  citool --remove-policy $unlockPolicyId --json | Out-Null
  exit
}

if ($policyLocked) {
  $result = (citool --update-policy out\DeviceProtection_Removal.cip.p7 --json | ConvertFrom-Json).OperationResult
  if ($result -ne 0) {
    Write-Host "An error occured: $result"
    exit $result
  }
  Write-Host 'Reboot and run this script again to complete uninstallation'
}
else {
  $result = (citool --remove-policy $lockPolicyId --json | ConvertFrom-Json).OperationResult
  if ($result -ne 0) {
    Write-Host "An error occured: $result"
    exit $result
  }
  $result = (citool --remove-policy $unlockPolicyId --json | ConvertFrom-Json).OperationResult
  if ($result -ne 0) {
    Write-Host "An error occured: $result"
    exit $result
  }
  Write-Host 'Uninstalled successfully'
}
