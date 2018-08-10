<#
Powershell vRNI Healthcheck script
Requires posh-ssh module --> Find-Module Posh-SSH | Install-Module
v1.0 vMan.ch, 20.01.2018 - Initial Version

    SSH to each server in Nodes using posh-ssh and run command "cli show-service-status" and searches for any service "not running"

    Script requires Powershell v3 and above.

    Run the command below to store user and pass in secure credential XML for each environment

        $cred = Get-Credential
        $cred | Export-Clixml -Path "G:\Scripts\vRNI-HealthCheck\config\vRNI.xml"

#>

param
(
    [array]$nodes,
    [String]$creds,
    [String]$Email,
    [String]$FileName,
    [String]$OutputLocation

)

#Logging Function
Function Log([String]$message, [String]$LogType, [String]$LogFile){
    $date = Get-Date -UFormat '%m-%d-%Y %H:%M:%S'
    $message = $date + "`t" + $LogType + "`t" + $message
    $message >> $LogFile
}

#Get Stored Credentials

$ScriptPath = (Get-Item -Path ".\" -Verbose).FullName

if($creds -gt ""){

    $cred = Import-Clixml -Path "$ScriptPath\config\$creds.xml"
    }
    else
    {
    echo "No Credentials Selected"
    Exit
    }

#vars
$RunDateTime = (Get-date)
$RunDateTime = $RunDateTime.tostring("yyyyMMddHHmmss")
$LogFileLoc = $ScriptPath + '\Log\Logfile.log'
$mailserver = 'smtp.vman.ch'
$mailport = 25


if($Email -imatch '^.*@vman\.ch$'){

    Log -Message "$email matches the vMan.ch domain" -LogType "JOB-$RunDateTime" -LogFile $LogFileLoc
    Echo "$email matches the vMan.ch domain"

    $SMTPcred = Import-Clixml -Path "$ScriptPath\config\smtp.xml"

    $SMTPU = $SMTPcred.GetNetworkCredential().Username
    $SMTPP = $SMTPcred.GetNetworkCredential().Password
    }
    else
    {
    Log -Message "$email is not in the vMan.ch domain, will not send mail but report generation will continue" -LogType "JOB-$RunDateTime" -LogFile $LogFileLoc
    Echo "$email is not in the vMan.ch domain, will not send mail but report generation will continue"
	$Email = ''
    }

#Send Email Function
Function SS64Mail($SMTPServer, $SMTPPort, $SMTPuser, $SMTPPass, $strSubject, $strBody, $strSenderemail, $strRecipientemail, $AttachFile)
   {
   [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { return $true }
      $MailMessage = New-Object System.Net.Mail.MailMessage
      $SMTPClient = New-Object System.Net.Mail.smtpClient ($SMTPServer, $SMTPPort)
	  $SMTPClient.EnableSsl = $true
	  $SMTPClient.Credentials = New-Object System.Net.NetworkCredential($SMTPuser, $SMTPPass)
      $Recipient = New-Object System.Net.Mail.MailAddress($strRecipientemail, "Recipient")
      $Sender = New-Object System.Net.Mail.MailAddress($strSenderemail, "vRNI SSH HealthChecker")
     
      $MailMessage.Sender = $Sender
      $MailMessage.From = $Sender
      $MailMessage.Subject = $strSubject
      $MailMessage.To.add($Recipient)
      $MailMessage.IsBodyHtml = $true
      $MailMessage.Body = $strBody
      if ($AttachFile -ne $null) {$MailMessage.attachments.add($AttachFile) }
      $SMTPClient.Send($MailMessage)
   }

$NodeReport = @()

ForEach ($node in $nodes) {

$RunDateTimeReport = (Get-date)
$RunDateTimeReport = $RunDateTimeReport.tostring("HH:mm:ss dd/MM/yyyy")

  Log -Message "Create new SSH session to $node" -LogType "JOB-$RunDateTime" -LogFile $LogFileLoc

  New-SSHSession -ComputerName $node -Credential $cred -AcceptKey -Force

  Log -Message "Running command cli show-service-status on $node" -LogType "JOB-$RunDateTime" -LogFile $LogFileLoc

  $commandOutput = Invoke-SSHCommand -SessionId 0 -Command "cli show-service-status"

   $ServiceStatus = $commandOutput.Output -replace '([^0-9])\d([^A-Za-z])([m])'
   $ServiceStatus = $ServiceStatus -replace '([^0-9])\d\d'
   $ServiceStatus = $ServiceStatus -replace '\x1B'

       If ($ServiceStatus -match '(not)\b'){

        Log -Message "A service is reporting as not running on $node, see below" -LogType "JOB-$RunDateTime" -LogFile $LogFileLoc
        Log -Message "$ServiceStatus" -LogType "JOB-$RunDateTime" -LogFile $LogFileLoc

        $SendEmail = $true

        }

       else

       {
       Log -Message "All services are reporing as running" -LogType "JOB-$RunDateTime" -LogFile $LogFileLoc
       }
   
        ForEach ($ServStatus in $ServiceStatus){

               $NodeReport += New-Object PSObject -Property @{

                node = $node
                services = $ServStatus
                TimeStamp = $RunDateTimeReport

                }

           }

#Terminate SSH session
Log -Message "Terminating SSH session for $node" -LogType "JOB-$RunDateTime" -LogFile $LogFileLoc
Remove-SSHSession -SessionId 0

Clear-Variable node,ServiceStatus,RunDateTimeReport,ServiceStatus,commandOutput

}


Log -Message "Generating Report to file system" -LogType "JOB-$RunDateTime" -LogFile $LogFileLoc

$ReportOutput = $OutputLocation + $FileName

$NodeReport | Export-Csv $ReportOutput -NoTypeInformation


If ($SendEmail){

        Log -Message "Emailing $Email an alert" -LogType "JOB-$RunDateTime" -LogFile $LogFileLoc
            $body = "<font color=red>One or more vRNI nodes are reporting a service as not running</font><br><br>" 
            $body += "See attached report for details<br><br>"

        SS64Mail $mailserver $mailport $SMTPU $SMTPP "vRNI Healthcheck at $RunDateTime detected an issue" $body 'info@vman.ch' $email $ReportOutput
        Log -Message "Email sent to $email" -LogType "JOB-$RunDateTime" -LogFile $LogFileLoc

}

Log -Message "Script Finished" -LogType "JOB-$RunDateTime" -LogFile $LogFileLoc