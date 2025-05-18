$policies = (citool --list-policies --json | ConvertFrom-Json).Policies
$lockPolicyId = (Get-Content policyInfo.json | ConvertFrom-Json).LockPolicyID

$policyEnforcing = $false

foreach ($policy in $policies) {
  if (($policy.PolicyID -ieq $lockPolicyId) -and ($policy.PolicyOptions -notcontains 'Enabled:Unsigned System Integrity Policy')) {
    $policyEnforcing = $true
    break
  }
}

if ($policyEnforcing) {
  $result = (citool --update-policy out\DeviceProtection_Removal.cip.p7 --json | ConvertFrom-Json).OperationResult
  if ($result -ne 0) {
    Write-Host "An error occured: $result"
    exit $result
  }
  Write-Host 'Restart your device and run this script again to complete uninstallation'
}
else {
  $unlockPolicyId = (Get-Content policyInfo.json | ConvertFrom-Json).UnlockPolicyID
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
