How does it work?
The main stages of work:

Launch via the command line:
The program starts with the parameters (--url, --timeout, --delay, --wordlist, --subdomains). For example:

python admin_finder.py --url https://example.com --wordlist passwords.txt --subdomains subs.txt

Asynchronous requests:
It uses the aiohttp and asyncio libraries for simultaneous (asynchronous) checks of multiple addresses.

Logging:
All the work results and vulnerabilities found are recorded in the sci_results.log file.

Step-by-step checks:
Definition of CMS (WordPress, Joomla, Drupal, etc.) by characteristic features in the site code or by headers.
Scan subdomains (if a subdomain dictionary is specified).
Checking the cPanel port (2083) for availability.
Search for hosting logins (cpanel, plesk, directadmin, etc.).
Search for admin panels using popular paths (/admin, /wp-admin, /administrator, etc.).
Brute force passwords for found admin panels (uses a list from a file or a standard one).
Checking for SQL injection and XSS on found forms.

What can she do?

Program features:
Automatically find admin panels on the site using popular paths.
Determine the CMS used (WordPress, Joomla, Drupal, Magento, OpenCart).
Scan subdomains (if a dictionary is specified).
Check the openness of the cPanel port (2083).
Find hosting logins (cpanel, whm, webmail, plesk, etc.).
Try to find the password to the admin panel using brute force.
Check for SQL Injection (SQLi) and XSS vulnerabilities.
Log all actions and results.

What is it used for?
Pentesters and security specialists use such tools to find vulnerabilities and verify the security of sites.
Webmasters can check their sites for open admin panels and potential holes.

Important!
Using the program on other people's websites without permission is illegal!
Use it only for testing your resources or with the consent of the owner.
