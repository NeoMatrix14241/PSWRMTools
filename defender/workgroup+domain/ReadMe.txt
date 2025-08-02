No mac addresses for you :) we use IPv4 address and hostname this time because we are not stupid

reason is that they are in the cloud and they are not included in the DHCP server address leases so we fuck off

additional setup for workgroup windows server member are needed

To fuck off, go to windows server which is not a domain member but a workgroup


The instructions below shall be done so we fuck off

Remote PC
1.) In remote (windows server for example) open powershell and execute the ff commands
	Enable-PSRemoting -Force          -> This is fucking important don't fuck it up

2.) Enable Windows Remote Management in firewall
	- Open windows defender firewall with advanced security
	- Go to inbound rules
	- Locate Windows Remote Management (HTTP-In) -> Note: There could be two or more, each are needed to be modified
	- One by one, Right-click each > Properties
	- Go to Scopes, Local IP address and Remote IP address shall be set to "Any IP Address"
	- Go to Advanced, Specify profiles to which this rules applies, check all domain, private, and public

3.) Enable Windows Management Instrumentation in firewall
	- Open windows defender firewall with advanced security
	- Go to inbound rules
	- Locate the ff:
		- Windows Management Instrumentation (ASync-In)
		- Windows Management Instrumentation (DCOM-In)
		- Windows Management Instrumentation (WMI-In)
	- One by one, Right-click each > Properties
	- Go to Scopes, Local IP address and Remote IP address shall be set to "Any IP Address"
	- Go to Advanced, Specify profiles to which this rules applies, check all domain, private, and public


Client PC
1.) In client pc (where you are) open powershell as admin and execute the ff commands
	Enable-WSManCredSSP -Role Client -DelegateComputer <WORKGROUP MEMBER HOSTNAME> -Force          -> This is fucking important don't fuck it up
	Set-Item WSMan:\localhost\Client\TrustedHosts -Value "192.168.126.192" -Force          -> This is fucking important don't fuck it up

And Well fucking done mate!

coming up a detailed documentation because apparently, we don't make shit done because we are one lazy motherfuckers.