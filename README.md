# Investigate-Suspicious-File

Scenario :

You are a level one security operations center (SOC) analyst at a financial services company. You have received an alert about a suspicious file being downloaded on an employee's computer. 

You investigate this alert and discover that the employee received an email containing an attachment. The attachment was a password-protected spreadsheet file. The spreadsheet's password was provided in the email. The employee downloaded the file, then entered the password to open the file. When the employee opened the file, a malicious payload was then executed on their computer. 

You retrieve the malicious file and create a SHA256 hash of the file.


Step 2: Review the details of the alert

Here is a timeline of the events leading up to this alert:

1:11 p.m.: An employee receives an email containing a file attachment.

1:13 p.m.: The employee successfully downloads and opens the file.

1:15 p.m.: Multiple unauthorized executable files are created on the employee's computer.

1:20 p.m.: An intrusion detection system detects the executable files and sends out an alert to the SOC.

SHA256 file hash: 54e6ea47eb04634d3e87fd7787e2136ccfbcc80ade34f246a12cf93bab527f6b


The file hash was scanned using Virus Total to check if the file is malicious. 58/72 security vendors flagged the file as malicious.

                                                              PYRAMID OF PAIN
  

Domain names: org.misecure.com is reported as a malicious contacted domain under the Relations tab in the VirusTotal report.

![image](https://github.com/user-attachments/assets/8d98c118-6b12-46be-88c0-7068cbbf529d)


IP address: 104.115.151.81 is listed as one of many IP addresses under the Relations tab in the VirusTotal report. 

![image](https://github.com/user-attachments/assets/553a2111-7998-4189-9e80-38e58db194e5)


Hash value: 287d612e29b71c90aa54947313810a25 is a MD5 hash listed under the Details tab in the VirusTotal report.

![image](https://github.com/user-attachments/assets/3c6609af-2709-4200-830c-ad4cdd84dd3c)


Network/host artifacts: Network-related artifacts that have been observed in this malware are HTTP requests made to the org.misecure.com domain. 

![image](https://github.com/user-attachments/assets/afeb2384-899b-4d3d-b491-c91a3407cda6)

Tools: Input capture is observed. Malicious actors use input capture to steal user input such as passwords, credit card numbers, and other sensitive information.

![image](https://github.com/user-attachments/assets/684f6048-869c-4363-9495-8f9f49d888bb)


TTPs: Command and control is listed as a tactic. Malicious actors use command and control to establish communication channels between an infected system and their own system.


![image](https://github.com/user-attachments/assets/68ad5e49-43ed-43e2-8757-dcfe0cbb152b)








