# http-response-header-directives-checker
A Python script that automates checking of HTTP response header directives for multiple URLs.

# Requirements
-	Windows/Linux OS
-	Python
-	response_header_script.py (script file)
-	addresslist.csv

# Usage
1.	Make sure Python is installed on the OS of your choice.
    - For Windows, run ```python --version``` in Command Prompt. If not detected, download the installer from the official site of Python (www.python.org) and run it.
    - For Linux, ```run python --version``` in Terminal. If not detected, run ```sudo apt-get install python```.

2.	For usage of the iplist.csv, each request sent takes in one address per row (see example below):
    ![example3](https://user-images.githubusercontent.com/75235391/205540799-8a6f8fe9-4163-42c5-b921-ca07764e6551.png)

3.	Before running the script, make sure response_header_script.py and addresslist.csv is in the same location (exact location does not matter).

4.	Open Command Prompt/Terminal and navigate to the location of response_header_script.py and addresslist.csv using ```cd```.

5.	Run the script using the command ```python response_header_script.py``` in Command Prompt/Terminal. A new file named response_header_list.csv should be created in the same location.

6.	The new response_header_list.csv file will display the domain and URL, header output and misconfigured and missing header directives.
