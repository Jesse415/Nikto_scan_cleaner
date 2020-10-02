# Nikto_scan_cleaner
This is a small tool that parse through a file(txt or otherwise)
that has a full Nikto scan. The tool goes through each Nikto scan
and if there is a string/flag to which the Nikto scan has it will
change the binary value from a 0 to a 1 for every string noted.
The output of the file is a .CSV file used for Machine Learning
classification.

## Running
To run (currently) edit nikto_scan_cleaner.py line number 105
to read in the name of the file you wish to parse. NOTE: Make sure
the first line is '- Nikto' as this is what separates each scan.

## Output
The output file (can be changed) is noted on line 20 'CLEAN.csv'.

This file is currently set as:
IP,Hostname,Anti-clickjacking,X-XSS-Protection,No CGI Directories found,valid response with junk HTTP,Allowed HTTP Methods,which may suggest a WAF,shellshock,OSVDB-637,OSVDB-578

Every value after Hostname is a binary value that is default set to
0 and if the scan finds the mathcing string it is changed to 1.

