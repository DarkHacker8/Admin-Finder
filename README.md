This program is an asynchronous web scanner written in Python using the aiohttp library to make parallel HTTP requests. It is designed for a comprehensive analysis of a website and includes several functions for detecting vulnerabilities and information about the target resource.

How does the program work?
Accepts the site URL and additional parameters via the command line (timeout, delay between requests, paths to files with lists of passwords and subdomains). Asynchronously performs multiple checks and scans using asyncio and aiohttp to handle multiple requests simultaneously, which greatly speeds up the process. Logs the results to the sci_results.log file. 

Main features of the program:
Site CMS (content management system) detection based on characteristic features in the page contents, HTTP headers, and the presence of typical files (for example, WordPress, Joomla, Drupal, etc.).
Scanning subdomains based on a list from the file, checking their availability.
Checking the open cPanel port (2083) to detect the hosting control panel.
Search for login pages in hosting panels using common paths (cpanel, whm, webmail, etc.).
Search for administrative panels using a set of typical paths (admin, wp-admin, backend, etc.).
Brute force passwords for admin panels using a preset or standard password list.
Checking for SQL injection (SQLi) and cross-site scripting (XSS) vulnerabilities using standard payloads.
Using a semaphore to limit the number of parallel requests (up to 10 at a time).

Technical Features:
Uses argparse for easy startup with parameters.
Logging using the logging module.
Asynchronous HTTP requests with timeouts and exception handling.
Color output to the console for easy perception of the results (via colorama).

Finally:
It is an advanced tool for automated website analysis that can help in:
Determining the CMS used.
Search for hidden subdomains and administrative panels.
Checking the site's security for common vulnerabilities (SQLi, XSS).
Search for entry points in the hosting control panel.

Such a scanner can be used by information security specialists to conduct an initial audit of a website and identify potential weaknesses.
