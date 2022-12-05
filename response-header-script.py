import requests
import csv
import pandas as pd
import re
from urllib.parse import urlparse
from requests.packages import urllib3

# DISABLES WARNING MESSAGES FOR REQUESTS WITHOUT CERTIFICATE VERIFICATION
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# CREATES NEW CSV FILE WITH COLUMN HEADERS
with open ("response_header_list.csv",'a') as csvfile:
    column_headers=['DOMAIN','URL','OUTPUT','DESCRIPTION','RECOMMENDATION']
    f = pd.DataFrame(columns=column_headers)
    f.to_csv("response_header_list.csv",index=False)

with open("addresslist.csv") as csv_file:
    csv_reader = csv.reader(csv_file, delimiter=',')
    for row in csv_reader:
        try:
            #READS IN URL, TO BE USED FOR 'URL' COLUMN
            url = row[0]

            #REMOVES EVERYTHING EXCEPT DOMAIN, TO BE USED FOR 'DOMAIN' COLUMN
            strippedurl = urlparse(url).netloc

            #PERFORMS HTTP RESPONSE HEADER REQUEST, TO BE USED FOR 'OUTPUT' COLUMN
            # response = requests.get(url, allow_redirects=True, verify=False)
            response = requests.head(url, allow_redirects=True, verify=False)

            #EMPTY LIST THAT WILL MAKE UP FINAL OUTPUT
            final_output = []

            ################## TRY/CATCH SECTION WITH HEADERS ##################
            try:
                final_output.append("Cache-Control: " + response.headers["Cache-Control"])
            except KeyError:
                final_output.append("Cache-Control MISSING")
            
            try:
                final_output.append("Content-Security-Policy: " + response.headers["Content-Security-Policy"])
            except KeyError:
                final_output.append("Content-Security-Policy MISSING")
            
            try:
                final_output.append("Set-Cookie: " + response.headers["Set-Cookie"])
            except KeyError:
                final_output.append("Set-Cookie MISSING")
            
            try:
                final_output.append("Strict-Transport-Security: " + response.headers["Strict-Transport-Security"])
            except KeyError:
                final_output.append("Strict-Transport-Security MISSING")
            
            try:
                final_output.append("X-Content-Type-Options: " + response.headers["X-Content-Type-Options"])
            except KeyError:
                final_output.append("X-Content-Type-Options MISSING")

            try:
                final_output.append("X-Frame-Options: " + response.headers["X-Frame-Options"])
            except KeyError:
                final_output.append("X-Frame-Options MISSING")

            final_output="\n".join(final_output)

            ################## END OF TRY/CATCH SECTION WITH HEADERS ##################
            
            ################## TRY/CATCH SECTION FOR HEADERS TO BE ADDED TO 'DESCRIPTION' COLUMN ##################
            
            flagged_headers=[]
            recommended_headers=[]

            try:
                if ("no-store" in response.headers["Cache-Control"]) and ("no-cache" in response.headers["Cache-Control"]) and ("must-revalidate" in response.headers["Cache-Control"]):
                    pass
                else:
                    recommended_headers.append("* Cache-Control: no-store, no-cache, must-revalidate")
            except KeyError:
                flagged_headers.append("* Cache-Control")
                recommended_headers.append("* Cache-Control: no-store, no-cache, must-revalidate")

            try:
                
                if ("max-age" in response.headers["Set-Cookie"]) and ("Path=/" in response.headers["Set-Cookie"]) and ("HttpOnly" in response.headers["Set-Cookie"]) and ("Secure" in response.headers["Set-Cookie"]) and ("SameSite=Strict" in response.headers["Set-Cookie"]):
                    pass
                else:
                    recommended_headers.append("* Set-Cookie: max-age; Path=/; HttpOnly; Secure; SameSite=Strict")
            except KeyError:
                flagged_headers.append("* Set-Cookie")
                recommended_headers.append("* Set-Cookie: max-age; Path=/; HttpOnly; Secure; SameSite=Strict")

            try:
                max_age=response.headers["Strict-Transport-Security"]
                max_age=re.findall(r'\d+', max_age)
                max_age=max_age[0]
                max_age=int(max_age)
                if ("includeSubDomains" in response.headers["Strict-Transport-Security"]) and ("max-age=" in response.headers["Strict-Transport-Security"]) and (int(max_age) in range(16070400,31536000)):
                    pass
                else:
                    recommended_headers.append("* Strict-Transport-Security: max-age=31536000 or any value lower such as 16070400; includeSubDomains")
            except KeyError:
                flagged_headers.append("* Strict-Transport-Security")
                recommended_headers.append("* Strict-Transport-Security: max-age=31536000 or any value lower such as 16070400; includeSubDomains")
            
            try:
                if response.headers["X-Content-Type-Options"] == "nosniff":
                    pass
                else:
                    recommended_headers.append("* X-Content-Type-Options: nosniff")
            except KeyError:
                flagged_headers.append("* X-Content-Type-Options")
                recommended_headers.append("* X-Content-Type-Options: nosniff")

            try:
                if ("SAMEORIGIN" in response.headers["X-Frame-Options"]) or ("DENY" in response.headers["X-Frame-Options"]):
                    pass
                else:
                    recommended_headers.append("* X-Frame-Options: SAMEORIGIN or X-Frame-Options: DENY")
            except KeyError:
                flagged_headers.append("* X-Frame-Options")
                recommended_headers.append("* X-Frame-Options: SAMEORIGIN or X-Frame-Options: DENY")

            ################## END OF TRY/CATCH SECTION FOR HEADERS TO BE ADDED TO 'DESCRIPTION' COLUMN ##################

            flagged_headers="\n".join(flagged_headers)
            recommended_headers="\n".join(recommended_headers)

            #DESCRIPTION AND RECOMMENDATION TEMPLATES THAT TAKES IN FLAGGED MISCONFIGURATIONS, TO BE USED FOR 'DESCRIPTION' AND 'RECOMMENDATION' COLUMNS
            if flagged_headers == "":
                final_description = "The application has no missing HTTP security headers in HTTP response.\n"
            else:
                final_description = "The application does not include or has the following misconfigured HTTP security headers in HTTP response:\n" + flagged_headers
            final_recommendation = "The server should be configured with the various HTTP security headers to reduce the attack vectors to the application:\n" + recommended_headers

            f = pd.read_csv('response_header_list.csv')
            f = pd.concat([f, pd.DataFrame.from_records([{'DOMAIN': strippedurl, 'URL': url, 'OUTPUT': final_output, 'DESCRIPTION': final_description, 'RECOMMENDATION': final_recommendation}])])

            f.to_csv("response_header_list.csv",index=False)
        
        except:
            print("Error occurred with " + url)
