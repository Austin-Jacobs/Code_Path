# codePathweek78

 WordPress vs. Kali
 
 **Homework Instructions**: 

For these week's assignment, discover and demonstrate similar proofs-of-concept for at least an additional three and (up to five) exploits affecting an older version of WP.

All exploits were tested and implemented within a WPDistillery 4.2 environment.

**1. HTTP GET Request through author id**
* Exploit Summary: Obtain information about User ID through the author interface
  * Type: User Enumeration
  * Fixed in version: N/a
  * OSInt Recon: [Author Enumeration](https://perishablepress.com/stop-user-enumeration-wordpress/)
* Gif: <img src="W78_1.gif" alt="HTTP Get Request">
* Steps to Recreate: 
  * In browser, enter ```192.168.33.10?author=<author id>```
  * Change ```<author id>``` to a numerical value. I used ```<1>```
  * Observe the page as redirected where admin is returned user.

**2. Wordpress CodeArt Plugin IDOR**
* Exploit Summary: Obtain access to WP config file with authentication keys
  * Type: IDOR
  * Fixed in version: N/a
  * Plugin version: 1.0.11
  * OSInt Recon: [IDOR](https://www.exploit-db.com/exploits/35460)
* Gif: <img src="W78_4.gif" alt="Plugin IDOR">
* Steps to Recreate: 
  * Install [CodeArt Plugin](https://github.com/ArtemSkit/CSCI4349_Week7/blob/master/plugins_repo/google-mp3-audio-player.zip)
  * Guest user can use the following link to access the WP config file. ```http://wpdistillery.vm/wp-content/plugins/google-mp3-audio-player/direct_download.php?file=../../../wp-config.php```

**3. Login Error Messages**
* Exploit Summary: Obtain information about users for the site
  * Type: User Enumeration
  * Fixed in version: N/a
  * OSInt Recon: [CVE-2009-2335](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2009-2335)
* Gif: <img src="W78_2.gif" alt="Login Error">
* Steps to Recreate: 
  * Navigate to the WP Login page ```http://192.168.33.10/wp-login.php?loggedout=true```
  * Typing in a username known to exist and a random password results in the following message being sent: **ERROR: The password you entered for the username admin is incorrect**.
  * Typing in a username known to not exist and a random password results in the following message being sent: **ERROR: Invalid username**.

**4. WordPress 4.2 Path Traversal + Directory Listing + File Deletion Vulnerabilities **
* Exploit Summary: 
  * Type: IDOR and Directory Traversal
  * Fixed in version: N/a
  * OSInt Recon: [IDOR Traversal](https://www.homelab.it/index.php/2014/08/06/wordpress-3-4-vulnerabilities/)
* Gif: <img src="W78_5.gif" alt="Directory IDOR">
* Steps to Recreate: 
  * Choose a plugin
  * Choose both the 'deactivate' and 'delete' options
  * Change the plugin location with the target directory to be deleted
    * An example of this is changing the ```akismet%2Fakismet.php``` to ```/../../wp-admin/plugins.php``` 
**5. Directory Traversal and Exposure**
* Exploit Summary: 
  * Type: Information Exposure
  * Fixed in version: N/a
  * OSInt Recon: [CVE-548](https://cwe.mitre.org/data/definitions/548.html)
* Gif: <img src="W78_3.gif" alt="HTTP Get Request">
* Steps to Recreate: 
  * Navigate to ```192.168.33.10/wp-admin/cs``` or ```192.168.33.10/wp-admin/js```
  * Observe the files available to through the page
