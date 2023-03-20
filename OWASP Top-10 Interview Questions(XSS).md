# OWASP Top-10 Interview Questions (Cross-Site Scripting XSS) - 
## What is Cross-Site Scripting (XSS)? - 
    By using the Cross-Site Scripting (XSS) technique, users executed malicious scripts (also called payloads) unintentionally by clicking on untrusted links, and hence, these scripts pass cookies information to attackers.
## What information can an attacker steal using XSS? - 
    By using XSS, the session id of the genuine user can be stolen by the attacker. The browser uses the session id to identify your credentials in an application and helps you keep login in till you sign off from an application. An attacker can write a code to extract information from cookies that contain session-id and other information. Later, the same session id can be used by an attacker to browse the application on behalf of the user without actually logged in to the application.
## Apart from mailing links of error pages, are there other methods of exploiting XSS? - 
    Other methods where attackers store malicious scripts (also called payloads) are discussion forums, the comment section of websites, and other similar platforms. Whenever the user navigates those pages, payloads got executed, and the user's cookies information automatically sends to an attacker.
## What are the types of XSS? - 
    Cross-site Scripting can be divided into three types:
    * Stored XSS
    * Reflected XSS
    * DOM-based XSS
## What is Stored XSS? - 
    In Stored XSS, the attacker plants a malicious script (also called payload) on a web page. Comment pages, forums, and other similar platforms can be used to store payloads. When the user browses these pages, these payloads are executed and sends cookies information to an attacker.
## What is Reflected XSS? - 
    Reflected XSS is one of the most widespread attack techniques used by attackers. In this type of attack, the user sends a malicious request by clicking on malicious links (contains an XSS payload) to a web server available on social networking sites and other platforms. As a result, the webserver replied to the user with an HTTP response containing the payload, which was executed in the browser and stole the user's cookies.
## What is DOM-based XSS? - 
    DOM-based XSS is a type of cross-site scripting that appears in DOM(Document Object Model), instead of HTML.
## How can I prevent XSS? - 
    XSS can be prevented by sanitizing user input to the application. Always allowed those elements as input which is absolutely essential for that field. 
## Can XSS be prevented without modifying the source code? - 
    "http only" attribute can also be used to prevent XSS.
## What is Cross-Site Tracing (XST)? How can it be prevented? - 
    By using XST technique, attackers are able to steal cookies by bypassing "http only" attribute. XST technique can be prevented by disabling the TRACE method on the webserver.
## List out key HTML entities used in XSS ? - 
    > (greater than)
    ' (apostrophe or single quote)
    " (double quote)
    < (less than)
    & (ampersand)
