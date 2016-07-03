# Guinevere - Automated Security Assessment Reporting Tool

This tool works with Gauntlet (a private tool) to automate assessment reporting.

Main features include:
* Generate Assessment Report
* Export Assessment
* Generate Retest Report
* Generate Pentest Checklist


### Generate Assessment Report
This option will generate you .docx report based on the vulnerabilities identified during an assessment. The report will contain a bullet list of findings, the vulnerability report write-up, and a table of interesting hosts to include host names and ports. Each report write up automatically calculates the number of affected hosts and updates the report verbiage accordingly.

### Export Assessment
An SQL dump of the assessment data from gauntlet will be export to a .sql file. This file can later be imported into by other analysts.

### Generate Retest Report
A .docx retest report will be generated. The tool will evaluate the original assessment findings against the retest findings. The retest findings don't need to be ranked as only the severity level of a vulnerability found in the orginial assessment will be used. New vulnerabilities and new hosts found during the retest will also be ignored. The report will contain a list of vulnerabilities along with their status (Remediated, Partially Remediated, or Not Remediated). A table will also be provided that contains hosts that are still vulnerable. A statistics table is also provided to be used with building graphs or charts.

### Generate Pentest Checklist - *BETA*
The Pentest Checklist is an HTML document used for information managment while conducting a pentest. The generated report provides the analyst with a list of host and their open ports along with space for note taking. This is stil under development and provides basic functionalty. The data is retrieved from the Gauntlet database. The "-T" flag can be used to display out from tools such as Nessus but is very verbose. 

## Usage
```
usage: Guinevere.py [-h] [-H DB_HOST] [-U DB_USER] [-P DB_PASS] [-p DB_PORT]
                    [-l LINES] [-A] [-V] [-sC] [-sH] [-sM] [-sL] [-sI] [-aD]
                    [-T]

optional arguments:
  -h, --help            show this help message and exit
  -H DB_HOST, --db-host DB_HOST
                        MySQL Database Host. Default set in script
  -U DB_USER, --db-user DB_USER
                        MySQL Database Username. Default set in script
  -P DB_PASS, --db-pass DB_PASS
                        MySQL Database Password. Default set in script
  -p DB_PORT, --db-port DB_PORT
                        MySQL Database Port. Default set in script
  -l LINES, --lines LINES
                        Number of lines to display when selecting an engagement. Default is 10
  -A, --all-vulns       Include all vulnerability headings when there are no associated report narratives
  -V, --all-verb        Include all vureto vulnerability verbiage when there are no associated report narratives
  --ports               Exclude port information vulnerability write-up portion of the report
  -sC                   Exclude Critical-Severity Vulnerabilities
  -sH                   Exclude High-Severity Vulnerabilities
  -sM                   Exclude Medium-Severity Vulnerabilities
  -sL                   Include Low-Severity Vulnerabilities
  -sI                   Include Informational-Severity Vulnerabilities
  -aD, --assessment-date
                        Include the date when selecting an assessment to report on
  -T, --tool-output     Include Tool Output When Printing G-Checklist
  ```
