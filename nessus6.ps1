[cmdletbinding()]
Param()

# Carlos Perez provided this bit of code to help with ignoring the self-signed
# certificate on Nessus. If you are not using a self-signed certificate you
# don't need this bit of code.
if ([System.Net.ServicePointManager]::CertificatePolicy.ToString() -ne 'IgnoreCerts')
{
    $Domain = [AppDomain]::CurrentDomain
    $DynAssembly = New-Object System.Reflection.AssemblyName('IgnoreCerts')
    $AssemblyBuilder = $Domain.DefineDynamicAssembly($DynAssembly, [System.Reflection.Emit.AssemblyBuilderAccess]::Run)
    $ModuleBuilder = $AssemblyBuilder.DefineDynamicModule('IgnoreCerts', $false)
    $TypeBuilder = $ModuleBuilder.DefineType('IgnoreCerts', 'AutoLayout, AnsiClass, Class, Public, BeforeFieldInit', [System.Object], [System.Net.ICertificatePolicy])
    $TypeBuilder.DefineDefaultConstructor('PrivateScope, Public, HideBySig, SpecialName, RTSpecialName') | Out-Null
    $MethodInfo = [System.Net.ICertificatePolicy].GetMethod('CheckValidationResult')
    $MethodBuilder = $TypeBuilder.DefineMethod($MethodInfo.Name, 'PrivateScope, Public, Virtual, HideBySig, VtableLayoutMask', $MethodInfo.CallingConvention, $MethodInfo.ReturnType, ([Type[]] ($MethodInfo.GetParameters() | % {$_.ParameterType})))
    $ILGen = $MethodBuilder.GetILGenerator()
    $ILGen.Emit([Reflection.Emit.Opcodes]::Ldc_I4_1)
    $ILGen.Emit([Reflection.Emit.Opcodes]::Ret)
    $TypeBuilder.CreateType() | Out-Null

    # Disable SSL certificate validation
    [System.Net.ServicePointManager]::CertificatePolicy = New-Object IgnoreCerts
}


#-----------------------------------------------------------------------------
# Function Definitions
#-----------------------------------------------------------------------------
Function Connect ()
{
	param(
		[string] $Method,
		[string] $Resource,
		[hashtable] $Data = @{},
		[string] $FileName = ""
	)

	$IrmParams = @{
		ContentType = "application/json"
		Method = $Method
		Headers = @{"X-Cookie" = "token=$token"}
		Uri = $Base + $Resource
	}

	# Use an empty dictionary for the body on GET requests
	if ($Method -eq "Get"){
		$IrmParams.Add("Body", @{})
	} else {
		$body = ConvertTo-Json $Data
		$IrmParams.Add("Body", $body)
	}

	# Write response to a file if the filename is provided.
	if ($FileName -ne ""){
		$IrmParams.Add("OutFile", $FileName)
	}

	$resp = Invoke-RestMethod @IrmParams

	Write-Verbose $IrmParams.Body 
	Write-Verbose $resp

	return $resp
}


Function Login ($username, $password)
{
	$data = @{"username" = $username; "password" = $password}
	$resp = Connect -Method "Post" -Resource "/session" -Data $data 

	return $resp.token
}


Function Logout
{
	$resp = Connect -Method "Delete" -Resource "/session"
}


Function GetPolicies
{
	$pols = @{}
	$resp = Connect -Method "Get" -Resource "/editor/policy/templates"

	foreach ($pol in $resp.templates)
	{
		$pols.Add($pol.uuid, $pol.title)
	}

	return $pols
}


Function GetHistoryIds($sid)
{
	$hids = @{}
	$resp = Connect -Method "Get" -Resource "/scans/$sid"

	foreach ($hist in $resp.history)
	{
		$hids.Add($hist.uuid, $hist.history_id)
	}

	return $hids
}


Function GetScanHistory($sid, $hid)
{
	$data = @{"history_id" = $hid}
	$resp = Connect -Method "Get" -Resource "/scans/$sid" -Data $data

	return $resp.info
}


Function Add($name, $desc, $targets, $policy)
{
	$settings = @{}
	$settings.Add("name", $name)
	$settings.Add("description", $desc)
	$settings.Add("text_targets", $targets)

	$data = @{}
	$data.Add("uuid", $policy)
	$data.Add("settings", $settings)

	$resp = Connect -Method "Post" -Resource "/scans" -Data $data

	return $resp.scan
}


Function Launch($sid)
{
	$resp = Connect -Method "Post" -Resource "/scans/$sid/launch"

	return $resp.scan_uuid
}


Function Status($sid, $hid)
{
	$resp = GetScanHistory $sid $hid

	return $resp.status
}


Function ExportStatus($sid, $fid)
{
	$resp = Connect -Method "Get" -Resource "/scans/$sid/export/$fid/status"

	return $resp.status
}


Function Export($sid, $hid)
{
	$data = @{}
	$data.Add("history_id", $hid)
	$data.Add("format", "html")
	$data.Add("chapters", "vuln_hosts_summary;vuln_by_host;remediations")

	$resp = Connect -Method "Post" -Resource "/scans/$sid/export" -Data $data
	$fid = $resp.file

	do
	{
		Start-Sleep -Seconds 5
		$status = ExportStatus $sid $fid
	}
	while ($status -ne "ready")

	return $fid
}


Function Download($sid, $fid)
{
	$file = "nessus-$sid-$fid.html"
	$resp = Connect -Method "Get" -Resource "/scans/$sid/export/$fid/download" -FileName $file
}


Function GetScans
{
	$scans = @{}
	$resp = Connect -Method "Get" -Resource "/scans"

	foreach ($scan in $resp.scans){
		$scans.add($scan.id, $scan.name)
	}

	$scans
}


#-----------------------------------------------------------------------------
# Main Program
#-----------------------------------------------------------------------------
$base = "https://<nessus_ip_or_hostname>:8834"
$token = ""
$username = "admin"
$password = "password"

Write-Host "Login"
$token = Login $username $password

Write-Host "Adding new scan."
$policies = GetPolicies
$policy = $policies.Get_Item("Basic Network Scan")
$scan = Add "New Scan From PS" "New Network Scan Launched by PS" "192.168.1.0/24" $policy
$sid = $scan.id

Write-Host "Launching new scan."
$scan_uuid = Launch($sid)
$history_ids = GetHistoryIds $sid
$hid = $history_ids.Get_Item($scan_uuid)

Write-Host "Waiting for new scan to complete."
do
{
	Start-Sleep -Seconds 5
	$status = Status $sid $hid
}
while ($status -ne "completed")

Write-Host "Exporting the completed scan."
$fid = Export $sid $hid
Download $sid $fid

Write-Host "Logout of Nessus"
Logout