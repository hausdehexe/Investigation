 param (
    [Parameter(Mandatory=$true)][string]$destinationPath
 )

 # check if the argument paths contain backslash if not, add it
if ($destinationPath.Substring($destinationPath.Length-1)  -ne '\') {
    $destinationPath = $destinationPath + "\"
}

# definition of global variables 
$computerName = hostname

# definition of empty array to store results 
$processIDs = @()
$schtasksDll = @();
$schtasksExe = @();
$schtasksExeNoParam = @();
$schtasksDllFinal = @();
$startup = @();
$usersLocation = @();
$serviceLocation = @();
$runningProcesses = @()

# create output folder for results in case it does not exist
if (!(Test-Path -Path $destinationPath ))
{
    New-Item -ItemType Directory -Force -Path $destinationPath 
} 

# check system architecture
if ([System.Environment]::Is64BitProcess) {
    $programFilesPath = "C:\Program Files"
} else {
    $programFilesPath = "C:\Program Files (x86)"
}

# get all running processes and store it to array by ID
Get-Process | ForEach-Object {
    $processIDs += $_.Id
}

# save running processes and loaded DLL files to the array  
Foreach ($processID in $processIDs) {
    $process = Get-Process -Id $processID  | select -ExpandProperty modules -ErrorAction SilentlyContinue | select-object -ExpandProperty  FileName
      
    $runningProcesses += ($process | Out-String).Trim()
}

# get scheduled tasks from the system
$schtasksCommand = schtasks /query /v /fo LIST 

# create two variable containing DLL and EXE files
foreach($line in $schtasksCommand) {
    if($line -match 'Task To Run:'){
       $splitted_line = $line -split ':'
       $schtasksExe += ($splitted_line[1] | Select-String -Pattern '.exe')    
       $schtasksDll += $splitted_line[1] | Select-String -Pattern '.dll' 
    }
}

# prepare the final list of scheduled tasks EXE
foreach($line in $schtasksExe) {
    $taskNoExe = $line -split ".exe"
    $variablePath = ($taskNoExe[0] + ".exe").ToLower().Replace('"','')

    if($variablePath -match "windir")
    {
       $schtasksExeNoParam += ($variablePath -replace '%windir%', 'C:\Windows').Trim()
    } 
    if($variablePath -match "systemroot")
    {
       $schtasksExeNoParam += ($variablePath -replace '%systemroot%', 'C:\Windows').Trim()
    }
    if($variablePath -match "programfiles")
    {
        $schtasksExeNoParam += ($variablePath -replace '%programfiles%', $programFilesPath).Trim()
    }
}

# prepare the final list of scheduled tasks DLL
foreach($taskDll in $schtasksDll) {
    # .exe refers to rundll32.exe
    $taskNoExe = $taskDll -split ".exe"
    $taskNoParameter = $taskNoExe[1] -split ","
   
    $taskNoSpace = $taskNoParameter[0] -replace " ", ""
    if($taskNoSpace -match "windir")
    {
        $schtasksDllFinal += ($taskNoSpace -replace '%windir%', 'C:\Windows').Trim()
    } 
    else {
        $schtasksDllFinal += ("C:\Windows\System32\" + $taskNoSpace).Trim()
    }   
}

# process the startup locations 
$startupItems = wmic startup list full
foreach($item in $startupItems)
{
    if($item -match 'Command='){
        $getExecutablePath = ($item -replace '"', '') -split '=' 
       
        if($getExecutablePath[1] -match 'rundll32') {
            # process dll
            $splittedDll = $getExecutablePath[1] -split "rundll32.exe"
            $splittedDllFinal = ($splittedDll -replace " ", "") -split ","
            $startup += ($splittedDllFinal[1] | Out-String).Trim()
        }
        else {
            $splitBySpace = $getExecutablePath[1] -split ".exe", ""
            # replace windir variable
            if($splitBySpace[0] -match 'windir')
            {
                $startup += ((($splitBySpace[0] -replace '%windir%', 'C:\Windows') + ".exe") | Out-String).Trim()
            }
            else {
                $startup += (($splitBySpace[0] + ".exe") | Out-String).Trim()
            }
        }
    }
}

# get the users from the system
$userNames = Get-ChildItem C:\Users -ErrorAction SilentlyContinue | Select -ExpandProperty Name

# fill the array of users locations
# get only EXE and DLL friles from Downloads, Desktop and AppData folders
foreach($userName in $userNames) {
    if($userName -ne "Public") {
      $userPath = "C:\Users\" + $userName 
      $userPathAppData = "C:\Users\" + $userName + "\AppData\"
      $userPathDownloads = "C:\Users\" + $userName + "\Downloads\"
      $userPathDesktop = "C:\Users\" + $userName + "\Desktop\"
      $usersLocation += (Get-ChildItem $userPathAppData -ErrorAction SilentlyContinue -Recurse -Include "*.exe", "*.dll"  | Format-Table -HideTableHeaders -Property FullName | Out-String).Trim()
      $usersLocation += (Get-ChildItem $userPathDownloads -Recurse -Include "*.exe", "*.dll" -ErrorAction SilentlyContinue | Format-Table -HideTableHeaders -Property FullName | Out-String).Trim()
      $usersLocation += (Get-ChildItem $userPathDesktop -Recurse -Include "*.exe", "*.dll" -ErrorAction SilentlyContinue | Format-Table -HideTableHeaders -Property FullName | Out-String).Trim()
      }
}

# command to get services on the system
$services = Get-WMIObject win32_service | Select-Object -ExpandProperty PathName 

# fill the array for services
foreach($service in $services) 
{
    $service_split = $service -split ".exe" 
    $serviceLocation += (($service_split[0] -replace '"','') + ".exe").Trim()
}

$listOfFilesToBeHashed = @()

foreach($item in $serviceLocation)
{
    $listOfFilesToBeHashed += $item.ToLower()
}

foreach($item in $usersLocation)
{
    $listOfFilesToBeHashed += $item.ToLower()
}

foreach($item in $startup)
{
    $listOfFilesToBeHashed += $item.ToLower()
}

foreach($item in $schtasksDllFinal)
{
    $listOfFilesToBeHashed += $item.ToLower()
}

foreach($item in $schtasksExeNoParam)
{
    $listOfFilesToBeHashed += $item.ToLower()
}

foreach($item in $runningProcesses)
{
    $listOfFilesToBeHashed += $item.ToLower()
}

$filesToBeHashedPath = $destinationPath + "filesToBeHashed.txt"
$uniqueFilesToBeHashedPath = $destinationPath + "uniqueFilesToBeHashed.txt"

# remove duplicate records from files to be hashed
$listOfFilesToBeHashed | Sort-Object -Unique | Set-Content -Path $filesToBeHashedPath
Get-Content $filesToBeHashedPath | Sort-Object -Unique | Set-Content -Path $uniqueFilesToBeHashedPath
$uniqueListOfFilesToBeHashed = Get-Content $uniqueFilesToBeHashedPath

Write-Host '*** Hashing of files started ***' 

$md5 = @();
foreach($item in $uniqueListOfFilesToBeHashed) {
    if($item -ne "") {
    $md5 += Get-FileHash  $item  -Algorithm MD5 -ErrorAction SilentlyContinue  | Select-Object Hash -ExpandProperty Hash
    }
}

$filePath = @();
foreach($item in $uniqueListOfFilesToBeHashed) {
    if($item -ne "") {
    $filePath += Get-FileHash -Path $item -Algorithm SHA1 -ErrorAction SilentlyContinue  | Select-Object Path -ExpandProperty Path
    }
}

$sha1 = @();
foreach($item in $uniqueListOfFilesToBeHashed) {
    if($item -ne "") {
    $sha1 += Get-FileHash -Path $item -Algorithm SHA1 -ErrorAction SilentlyContinue  | Select-Object Hash -ExpandProperty Hash
    }
}

$sha256 = @();
foreach($item in $uniqueListOfFilesToBeHashed) {
    if($item -ne "") {
    $sha256 += Get-FileHash -Path $item -Algorithm SHA256 -ErrorAction SilentlyContinue  | Select-Object Hash -ExpandProperty Hash
    }
}

# create array for file hashes and insert header of the file
$fileHashes = @();
$fileHashes += "MD5,SHA1,SHA256"

$fileHashesWithPath = @();
$fileHashesWithPath += "FILEPATH,MD5,SHA1,SHA256"

$counter = 0;

# generate file hashes
foreach($item in $md5)
{
    $fileHashes += (($md5[$counter] + "," + $sha1[$counter] + "," + $sha256[$counter]) | format-list)
    $fileHashesWithPath += (($filePath[$counter] + "," + $md5[$counter] + "," + $sha1[$counter] + "," + $sha256[$counter]) | format-list)
    $counter++
}

$fileHashesPath = $destinationPath + $computerName + "_hashes.csv"
$fileHashesWithPathPath = $destinationPath + $computerName + "_hashesWithPath.csv"

$fileHashes > $fileHashesPath 
$fileHashesWithPath > $fileHashesWithPathPath

Remove-Item -Path $filesToBeHashedPath -Force
Remove-Item -Path $uniqueFilesToBeHashedPath -Force
   
Write-Host '*** Script completed its task ***' 