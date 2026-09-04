"""
Single source of truth for the attack/malware encyclopedia.

Previously this content existed as 11 separate near-duplicate templates
(SQL_Injection.html, Cross_Site_Scripting.html, ...), each with its own
copy-pasted nav/footer, a different Bootstrap CDN pin, and inline <style>
blocks. attacks.html also carried a second, independent copy of the
title/image/description used for the card grid.

This module is that data, in one place. Both the /Attacks grid and the
single templates/attack_detail.html route read from ATTACKS below, so
adding a new attack type is a new dict entry, not a new template + route.
"""

ATTACKS = [
    {
        "slug": 'SQL_Injection',
        "title": 'SQL Injection',
        "card_img": 'SQL_Injection_images.jpg',
        "desc": 'Malicious SQL code injected into a database query to manipulate or access data.',
        "hero_img": '/static/Attacks/Blog/SQL_Injection/Blog_SQL_Injection_Images.jpg',
        "long_title": 'Understanding SQL Injection: A Comprehensive Guide',
        "intro": 'SQL Injection is one of the most prevalent web application vulnerabilities that can lead to severe security breaches. As developers and security professionals, understanding how SQL Injection works and how to prevent it is crucial in safeguarding sensitive data. This blog post aims to provide an in-depth overview of SQL Injection, its types, impacts, and best practices for prevention.',
        "sections": [
            {
                "heading": 'What is SQL Injection?',
                "body": 'SQL Injection (SQLi) occurs when an attacker exploits a vulnerability in an application’s software by injecting malicious SQL code into an input field. This SQL code is then executed by the database, allowing the attacker to manipulate the database in unintended ways. SQL Injection can lead to unauthorized access to sensitive information, data corruption, and even complete system compromise.',
            },
            {
                "heading": 'Types of SQL Injection',
                "body": "1. Classic SQL Injection: The basic form where the attacker directly inputs malicious SQL code. 2. Blind SQL Injection: The attacker does not see the result of the SQL query. Instead, they infer information based on the application's behavior. For instance, changing the application’s response time or error messages can give hints about the database structure. 3. Time-Based Blind SQL Injection: The attacker uses time delays to infer the response from the server. For example, adding a delay in the query can reveal information based on whether the response is delayed. 4.Out-of-Band SQL Injection: This method relies on the database server to make an external request to deliver data to the attacker. This type is less common and generally used when other methods are not viable.",
            },
        ],
        "external_link": 'https://www.hacksplaining.com/lessons/sql-injection/start',
    },
    {
        "slug": 'Cross_Site_Scripting',
        "title": 'Cross-Site Scripting',
        "card_img": 'cross_site_scripting_images.jpg',
        "desc": 'Injecting malicious scripts into web pages viewed by other users.',
        "hero_img": '/static/Attacks/Blog/Cross_Site_Scripting/Cross_Site_Scripting_images.jpg',
        "long_title": 'Understanding Cross-Site Scripting (XSS): A Comprehensive Guide',
        "intro": "In today's digital landscape, web applications are becoming increasingly sophisticated, allowing users to interact with each other and the server in various ways. However, with this increase in complexity comes the risk of vulnerabilities, one of the most prevalent being Cross-Site Scripting (XSS). In this blog post, we will delve into what XSS is, how it works, its different types, potential consequences, and ways to protect your web applications against this threat.",
        "sections": [
            {
                "heading": 'What is Cross-Site Scripting (XSS)?',
                "body": 'Cross-Site Scripting (XSS) is a type of security vulnerability typically found in web applications. It allows attackers to inject malicious scripts into web pages viewed by users. When other users load the affected page, the malicious script executes in their browsers as if it came from the trusted website, leading to various harmful actions such as data theft, session hijacking, and more.',
            },
            {
                "heading": 'Types of XSS Attacks',
                "body": "1. Stored XSS (Persistent XSS): In a stored XSS attack, the malicious script is permanently stored on the target server (e.g., in a database). When users load the affected page, the script executes without any additional action from the attacker. This type of XSS can be particularly damaging as it affects all users accessing the infected content. 2. Reflected XSS (Non-Persistent XSS): In reflected XSS, the malicious script is not stored on the server but rather reflected off a web server. This attack typically occurs when an attacker sends a link to a victim, which, when clicked, executes the script immediately. This type of attack requires the victim to interact with the malicious link. 3. DOM-Based XSS: DOM-based XSS occurs when the vulnerability exists in the client-side code rather than server-side code. The attack manipulates the Document Object Model (DOM) in the browser, allowing the attacker to execute scripts in the context of the victim's browser.",
            },
        ],
        "external_link": 'https://www.hacksplaining.com/lessons/xss-stored/start',
    },
    {
        "slug": 'Command_Execution',
        "title": 'Command Execution',
        "card_img": 'Command_Execution_Images.jpg',
        "desc": 'Remotely executing unauthorized system commands to gain control.',
        "hero_img": '/static/Attacks/Blog/Command_Execution/Command_Execution_Images.jpg',
        "long_title": 'Understanding Command Execution Vulnerabilities: A Comprehensive Overview',
        "intro": "In the ever-evolving landscape of cybersecurity, command execution vulnerabilities pose a significant threat to web applications and systems. These vulnerabilities allow attackers to execute arbitrary commands on a server or device, leading to unauthorized access, data breaches, and potentially catastrophic consequences. In this blog, we'll explore what command execution vulnerabilities are, how they work, the different types, their implications, and best practices for prevention.",
        "sections": [
            {
                "heading": 'What is Command Execution ?',
                "body": 'Command execution vulnerabilities occur when an application allows users to execute commands on the server or operating system without proper validation or sanitization. This can happen through various input mechanisms, such as web forms, APIs, or URL parameters. When these inputs are not adequately controlled, attackers can manipulate them to execute arbitrary commands, gaining control over the system.',
            },
            {
                "heading": 'Types of Command Execution Vulnerabilities',
                "body": 'Command execution vulnerabilities can be categorized into two main types: 1. Remote Command Execution (RCE): RCE vulnerabilities allow attackers to execute commands remotely on a server or device. This type of vulnerability is particularly dangerous because it grants attackers full control over the target system. RCE is often found in web applications that fail to properly validate user inputs or use insecure system calls. 2. Local Command Execution (LCE): LCE vulnerabilities allow attackers to execute commands on the local server environment. While this may seem less severe than RCE, it can still lead to serious consequences, such as accessing sensitive files, manipulating databases, or compromising application logic.',
            },
        ],
        "external_link": 'https://www.hacksplaining.com/lessons/xss-stored/start',
    },
    {
        "slug": 'Trojan_horse',
        "title": 'Trojan Horse',
        "card_img": 'Trojan_Horse_Images.jpg',
        "desc": 'Malware disguised as legitimate software to trick users into installing it.',
        "hero_img": '/static/Attacks/Blog/Trojan_horse/Trojan_horse_Images.jpg',
        "long_title": 'Understanding Trojan Horses: The Hidden Threat in Cybersecurity',
        "intro": 'In the realm of cybersecurity, the term "Trojan horse" conjures images of deception and hidden dangers. Just like the ancient Greek tale of a wooden horse used to infiltrate the city of Troy, modern Trojan horses are malicious software programs that disguise themselves as legitimate applications or files. In this blog post, we will explore what Trojan horses are, how they operate, the different types, their potential impacts, and how to protect yourself against these insidious threats.',
        "sections": [
            {
                "heading": 'What is a Trojan Horse ?',
                "body": 'A Trojan horse, often referred to simply as a "Trojan," is a type of malware that pretends to be a legitimate program to trick users into installing it. Unlike viruses or worms, Trojans do not replicate themselves; instead, they rely on social engineering techniques to deceive users into downloading or executing them. Once installed, a Trojan can perform various malicious activities, such as stealing sensitive information, installing additional malware, or granting unauthorized access to an attacker.',
            },
            {
                "heading": 'Types of Trojan Horses',
                "body": 'Trojans come in various forms, each with its own purpose and method of operation. Here are some common types: 1. Remote Access Trojans (RATs): RATs provide attackers with remote access to the infected system, allowing them to control the device and access sensitive data. Attackers can use RATs for spying, stealing credentials, or deploying additional malware. 2. Banking Trojans: These Trojans are designed specifically to steal banking information. They often monitor users’ online banking sessions and capture login credentials, making them a significant threat to financial security. 3. Trojan Downloaders: These programs download and install additional malicious software onto the infected system. They often serve as a gateway for other types of malware, including ransomware and adware. 4. Trojan Horses for DDoS Attacks: These Trojans infect devices to create a botnet that can be used to launch DDoS attacks against targeted servers, overwhelming them with traffic and causing downtime. 5. Ransomware Trojans: Some Trojans act as ransomware, encrypting files on the infected system and demanding payment for decryption. These attacks can lead to significant data loss and financial damage.',
            },
        ],
        "external_link": None,
    },
    {
        "slug": 'Spyware',
        "title": 'Spyware',
        "card_img": 'Spyware_images.jpg',
        "desc": 'Software that secretly monitors activity and collects data without consent.',
        "hero_img": '/static/Attacks/Blog/Spyware/Spyware_Images.jpg',
        "long_title": 'Spyware: The Silent Intruder in Your Digital Life',
        "intro": 'In the digital age, privacy is a growing concern as our lives increasingly intertwine with technology. Among the various types of malware that threaten our online security, spyware stands out as one of the most insidious forms. This blog explores what spyware is, how it operates, the various types of spyware, its potential impacts, and how to protect yourself from its harmful effects.',
        "sections": [
            {
                "heading": 'What is Spyware ?',
                "body": "Spyware is a type of malicious software designed to infiltrate a user's device without their knowledge. Once installed, it secretly monitors and collects information about the user’s activities, such as browsing habits, keystrokes, login credentials, and personal information. Unlike other forms of malware, spyware typically operates discreetly, making it difficult for users to detect its presence.",
            },
            {
                "heading": 'Types of Spyware',
                "body": 'Trojans come in various forms, each with its own purpose and method of operation. Here are some common types:Spyware comes in various forms, each designed for different purposes. Here are some common types: 1. Adware: While primarily focused on displaying advertisements, some adware can also collect user data and track browsing habits. This data is often used to deliver targeted ads, but it can also compromise user privacy. 2. Keyloggers: Keyloggers are designed to record every keystroke made by the user. This information can include sensitive data such as passwords, credit card numbers, and personal messages, making keyloggers particularly dangerous. 3. Browser Hijackers: These malicious programs alter the user’s browser settings, redirecting searches and modifying homepages. Browser hijackers often collect data about browsing habits to sell to advertisers. 4. System Monitors: System monitors track user behavior and system activity, collecting data on installed applications, network traffic, and system configurations. This information can be used for various malicious purposes, including identity theft and corporate espionage. 5. Trojan Spyware: These Trojans masquerade as legitimate software, tricking users into installing them. Once inside, they can monitor and capture sensitive information without the user’s consent.',
            },
        ],
        "external_link": None,
    },
    {
        "slug": 'Worm',
        "title": 'Worm',
        "card_img": 'Worm_images.jpg',
        "desc": 'Self-replicating malware that spreads across networks, consuming resources.',
        "hero_img": '/static/Attacks/Blog/Worm/Worm_Images.jpg',
        "long_title": 'Understanding Worms: The Self-Replicating Cyber Threat',
        "intro": 'In the complex world of cybersecurity, worms stand out as one of the most persistent and damaging forms of malware. Unlike other types of malware, worms can spread autonomously, moving from one system to another without the need for user interaction. In this blog post, we will explore what worms are, how they work, the different types, their potential impacts, and how to protect yourself and your systems from this widespread cyber threat.',
        "sections": [
            {
                "heading": 'What is a Worm ?',
                "body": 'A worm is a type of malicious software (malware) that replicates itself and spreads across networks without needing to attach itself to other programs. Unlike viruses, which require user actions like opening infected files to spread, worms are fully independent. Once introduced into a network, a worm can exploit vulnerabilities in operating systems or applications to replicate itself and infect other systems.',
            },
            {
                "heading": 'Types of Worms',
                "body": 'Worms come in various forms, each with its own unique method of propagation and impact. Here are some common types: 1. Email Worms: These worms spread through email attachments or links. They often masquerade as legitimate files or messages to trick users into downloading them. Once opened, the worm can access the user’s contact list and send itself to all their contacts, continuing the infection. 2. Internet Worms: These worms exploit vulnerabilities in internet-facing applications or network services. They scan for vulnerable devices on the internet and propagate without any user action. 3. File-Sharing Worms: File-sharing worms hide themselves in shared files or folders on networks. When users download and open an infected file, the worm spreads to their system and then looks for more files to infect. 4. Instant Messaging (IM) Worms: IM worms spread through instant messaging platforms. They often send infected links or attachments to users on the victim’s contact list, encouraging them to click on or download the malicious content. 5. Network Worms: Network worms exploit vulnerabilities in network protocols. They propagate through network connections, infecting devices connected to the same network, including computers, servers, and IoT devices.',
            },
        ],
        "external_link": None,
    },
    {
        "slug": 'Adware',
        "title": 'Adware',
        "card_img": 'Adware_Images.jpg',
        "desc": 'Software that displays unwanted ads and often collects data for targeting.',
        "hero_img": '/static/Attacks/Blog/Adware/Adware_Images.jpg',
        "long_title": 'Adware: The Annoying Yet Dangerous Threat to Your Privacy',
        "intro": "In today's interconnected digital world, not all malware is created equally. While some forms of malware are designed to steal data or cripple systems, others, like adware, seem more like a nuisance than a real threat. However, adware is more than just an annoyance—it can pose serious risks to your privacy, security, and overall computing experience. In this blog, we will explore what adware is, how it works, its potential impacts, and how to protect yourself from it.",
        "sections": [
            {
                "heading": 'What is Adware ?',
                "body": 'Adware is a type of malware that automatically delivers unwanted advertisements to a user’s device. The primary purpose of adware is to generate revenue for its developers by forcing ads into the user’s web browsers, applications, or operating systems. These ads may appear in various forms, such as pop-ups, banners, or uncloseable windows, and they often promote dubious products or services.',
            },
            {
                "heading": 'Types of Adware',
                "body": "Adware comes in different forms, each with varying levels of impact. The most common types include: 1. Pop-Up Adware: This type displays persistent pop-up windows that appear frequently, often on every webpage visited. These pop-ups are designed to attract clicks, sometimes leading to harmful websites. 2. In-App Adware: Many free mobile apps use in-app adware to generate revenue by displaying ads. While not always malicious, these ads can slow down the app’s performance and interrupt user experience. 3. Browser Hijackers: This type of adware modifies your browser settings, changing the homepage, search engine, or redirecting you to unwanted websites filled with ads. It’s one of the most disruptive types of adware as it directly interferes with your browsing activities. 4. Malvertising: ThMalvertising refers to ads that contain malicious code designed to exploit vulnerabilities in the user's browser or operating system. Clicking on these ads can lead to infections or redirect users to harmful websites.",
            },
        ],
        "external_link": None,
    },
    {
        "slug": 'Keyloggers',
        "title": 'Keyloggers',
        "card_img": 'Keylogger_Images.jpg',
        "desc": 'Programs that record keystrokes to capture passwords and personal data.',
        "hero_img": '/static/Attacks/Blog/Keyloggers/Keyloggers_Images.jpg',
        "long_title": 'Keyloggers: The Silent Threat to Your Privacy',
        "intro": 'In the world of cybersecurity, few tools are as stealthy and invasive as keyloggers. These malicious programs silently track every keystroke you make, capturing sensitive information such as passwords, credit card numbers, and personal messages. Whether used by cybercriminals, corporations, or even governments, keyloggers are a dangerous tool that can compromise your privacy and security without your knowledge. In this blog, we’ll delve into what keyloggers are, how they work, their potential impacts, and how to protect yourself against them.',
        "sections": [
            {
                "heading": 'What is a Keylogger ?',
                "body": 'A keylogger, short for "keystroke logger," is a type of surveillance software or hardware that records every keystroke made on a computer or mobile device. The main goal of keyloggers is to collect information that can be used for unauthorized access to accounts, financial data, or personal information. Keyloggers can be software-based, hardware-based, or even installed as part of a larger malware attack.',
            },
            {
                "heading": 'Types of Keyloggers',
                "body": 'Keyloggers can be categorized into two main types: software-based and hardware-based keyloggers. 1. Software-Based Keyloggers: These keyloggers are malicious software programs that are installed on a device to record keystrokes. They operate within the operating system and are the most common type of keyloggers. Kernel-Level Keyloggers: These keyloggers run at the kernel level (the core of the operating system), making them difficult to detect and remove. They can access low-level system functions to record keystrokes. User-Level Keyloggers: These operate at the application level and are typically easier to detect by antivirus software. They may be part of a trojan or malware package. 2. Hardware-Based Keyloggers: Hardware keyloggers are physical devices installed on the computer, often between the keyboard and the computer itself. These keyloggers don’t require software installation, making them more difficult to detect but easier to remove once found. USB Keyloggers: These are small devices inserted into a USB port between the keyboard and the computer. They capture the signals sent from the keyboard. Wireless Keyloggers: These keyloggers capture keystrokes from wireless keyboards by intercepting the signals transmitted between the keyboard and the receiver.',
            },
        ],
        "external_link": None,
    },
    {
        "slug": 'Phishing',
        "title": 'Phishing',
        "card_img": 'Phishing_Images.jpg',
        "desc": 'Deceptive scams tricking users into revealing sensitive information.',
        "hero_img": '/static/Attacks/Blog/Phishing/Phishing_Images.jpg',
        "long_title": 'Phishing: The Bait That Lures You In',
        "intro": 'Phishing is one of the most widespread and damaging forms of cybercrime today. It’s a type of social engineering attack where cybercriminals pose as trustworthy entities to deceive individuals into revealing sensitive information, such as passwords, credit card numbers, or social security numbers. In this blog, we’ll explore what phishing is, the different types of phishing attacks, how to recognize phishing attempts, and what steps you can take to protect yourself.',
        "sections": [
            {
                "heading": 'What is Phishing ?',
                "body": 'Phishing is a fraudulent attempt to obtain sensitive information by disguising oneself as a legitimate entity. It usually occurs through emails, text messages, or fake websites that appear to be from credible sources like banks, social media platforms, or well-known companies. Once a victim interacts with these malicious links or attachments, they may unknowingly hand over personal information or install malware onto their devices.',
            },
            {
                "heading": 'Types of Phishing Attacks',
                "body": 'Phishing attacks come in various forms, each tailored to specific victims or purposes. Here are the most common types: 1. Email Phishing: Email phishing is the most common type of phishing attack. Cybercriminals send emails that appear to be from legitimate organizations like banks, tech companies, or even government agencies. These emails typically contain a link that leads to a fake website designed to steal your login credentials or personal information. 2. Spear Phishing: Spear phishing is a more targeted form of phishing. Instead of sending generic emails to thousands of people, attackers customize the email to a specific individual or organization. They may reference personal details or include information that makes the email seem more authentic. 3. Whaling: Whaling is a type of spear phishing that targets high-level executives or important individuals within an organization, such as CEOs or CFOs. The stakes are higher, as gaining access to an executive’s credentials can allow the attacker to conduct more significant fraud or corporate espionage. 4. Smishing (SMS Phishing): Smishing involves phishing attempts through text messages or SMS. Cybercriminals send texts that prompt you to click on a link or call a number, where you’re asked to provide personal information. 5. Vishing (Voice Phishing): Vishing involves phishing attempts conducted over the phone. Scammers call victims pretending to be legitimate entities, such as a bank or government agency, and ask for sensitive information like account numbers or personal identification numbers (PINs). 6. Clone Phishing: Clone phishing involves duplicating a legitimate email and then resending it with malicious links or attachments. The attacker creates a “clone” of a previously received email from a trusted source, but swaps out the original content for harmful links. 7. Pharming: Pharming is a type of phishing where attackers manipulate DNS (Domain Name System) settings to redirect you to a fake website, even if you’ve entered the correct web address. This attack is more sophisticated and difficult to detect.',
            },
        ],
        "external_link": None,
    },
    {
        "slug": 'Rootkits',
        "title": 'Rootkits',
        "card_img": 'Rootkits_Images.jpg',
        "desc": 'Malicious software that hides its presence while granting unauthorized access.',
        "hero_img": '/static/Attacks/Blog/Rootkits/Rootkits_Images.jpg',
        "long_title": 'Rootkits: The Hidden Threats in Cybersecurity',
        "intro": 'In the ever-evolving landscape of cybersecurity, rootkits stand out as one of the most insidious threats. These malicious tools are designed to gain unauthorized access to systems while remaining undetected, making them particularly dangerous for both individuals and organizations. In this blog, we will explore what rootkits are, how they work, their types, the potential damage they can cause, and how to protect against them.',
        "sections": [
            {
                "heading": 'What is a Rootkit ?',
                "body": 'A rootkit is a collection of software tools that enable unauthorized access to a computer or network while hiding its presence. The term "root" refers to the administrative account in Unix and Linux systems that has full control over the operating system. A rootkit can be used by attackers to maintain access to compromised systems, often without the knowledge of the user or system administrator.',
            },
            {
                "heading": 'Types of Rootkits',
                "body": 'Rootkits can be categorized into different types based on their level of operation and methods of concealment: 1. User Mode Rootkits: These rootkits operate at the user level, targeting applications and processes. They can intercept system calls to hide their presence but are generally easier to detect compared to kernel mode rootkits. 2. Kernel Mode Rootkits: Kernel mode rootkits operate at the core of the operating system. They have higher privileges and can manipulate the system at a deeper level, making them more dangerous and harder to detect. 3. Bootkits: Bootkits infect the master boot record (MBR) or boot sector of a hard drive. They load before the operating system, allowing attackers to gain control of the system even before it boots up, making detection nearly impossible. 4. Firmware Rootkits: These rootkits target the firmware of hardware devices, such as network cards or hard drives. They can remain persistent even after the operating system is reinstalled or the hard drive is formatted. 5. Virtual Rootkits: Virtual rootkits operate by creating a virtual environment to hide their presence. They can manipulate the operating system and run unnoticed within a virtual machine, making detection more challenging.',
            },
        ],
        "external_link": None,
    },
    {
        "slug": 'Ransomware',
        "title": 'Ransomware',
        "card_img": 'Ransomware_Images.jpg',
        "desc": "Encrypts a user's files and demands a ransom for the decryption key.",
        "hero_img": '/static/Attacks/Blog/Ransomware/Ransomware_Images.jpg',
        "long_title": 'Ransomware: The Digital Kidnappers of the Cyber World',
        "intro": 'In recent years, ransomware has emerged as one of the most notorious and damaging forms of cybercrime, affecting individuals and organizations alike. This malicious software encrypts a victim’s files, rendering them inaccessible, and demands a ransom payment for the decryption key. In this blog, we will delve into the mechanics of ransomware, its impact, notable attacks, and essential preventive measures.',
        "sections": [
            {
                "heading": 'What is Ransomware ?',
                "body": "Ransomware is a type of malware that restricts access to a computer system or files, typically by encrypting them. Once the files are encrypted, the attacker demands a ransom payment, usually in cryptocurrency, in exchange for the decryption key that will unlock the files. The emotional and financial toll of ransomware attacks can be significant, leaving victims in distress and uncertain about their data's fate.",
            },
            {
                "heading": 'The Impact of Ransomware Attacks',
                "body": 'Ransomware attacks can have dire consequences for individuals and organizations, including: 1. Financial Loss: The costs associated with ransomware attacks can be staggering. Victims may pay hefty ransoms, and organizations often incur additional expenses related to recovery, downtime, and potential legal fees. 2. Data Loss: Even if a ransom is paid, there is no assurance that the decryption key will work or that the files will remain intact. In some cases, vital data may be permanently lost. 3. Reputational Damage: Organizations that fall victim to ransomware attacks may suffer reputational harm, leading to loss of customer trust and business relationships. This damage can have long-lasting effects. 4. Operational Disruption: Ransomware attacks can disrupt normal operations, leading to downtime that affects productivity and service delivery. Organizations may be forced to halt operations until the threat is resolved. 5. Legal and Compliance Issues: Organizations may face legal repercussions if sensitive customer data is compromised during a ransomware attack. Compliance violations can lead to fines and regulatory scrutiny.',
            },
        ],
        "external_link": None,
    },
    {
        "slug": 'Cryptojacking',
        "title": 'Cryptojacking',
        "card_img": 'Cryptojacking_Images.jpg',
        "desc": 'Unauthorized use of a device to mine cryptocurrency.',
        "hero_img": '/static/Attacks/Blog/Cryptojacking/Cryptojacking_Images.jpg',
        "long_title": 'Cryptojacking: The Covert Threat to Your Computing Resources',
        "intro": "As cryptocurrencies have gained popularity, a new form of cyber threat has emerged: cryptojacking. This insidious activity involves the unauthorized use of someone else's computer to mine cryptocurrencies, often without the user's knowledge. In this blog, we'll explore what cryptojacking is, how it works, its impact on victims, and how to protect yourself from this growing menace.",
        "sections": [
            {
                "heading": 'What is Cryptojacking ?',
                "body": "Cryptojacking is a type of cyber attack where malicious actors hijack the computing power of a device to mine cryptocurrencies, such as Bitcoin or Monero, without the owner’s consent. Unlike traditional malware, which often aims to steal data or ransom files, cryptojacking focuses on covertly generating cryptocurrency for the attacker, leveraging the victim's computing resources for profit.",
            },
            {
                "heading": 'The Impact of Cryptojacking',
                "body": 'Cryptojacking can have several detrimental effects on both individual users and organizations: 1. Decreased Performance: Cryptojacking can significantly slow down a device as it uses substantial processing power. Users may notice their computers running sluggishly or experiencing lag, which can disrupt productivity. 2. Increased Energy Costs: Mining cryptocurrency requires considerable energy, leading to higher electricity bills. Victims may find their energy consumption spikes unexpectedly, impacting overall costs. 3. Hardware Damage: Sustained high CPU and GPU usage can lead to overheating and wear and tear on hardware components, potentially causing permanent damage and necessitating costly repairs or replacements. 4. Security Vulnerabilities: Cryptojacking malware can open the door to other cyber threats. If an attacker can install cryptojacking software, they may also exploit vulnerabilities to install additional malicious software, steal data, or access sensitive information. 5. Reputation Damage for Organizations: For businesses, a cryptojacking attack can result in reputational harm. Customers and partners may lose trust in an organization if their systems are found to be compromised or if they experience service disruptions due to cryptojacking.',
            },
        ],
        "external_link": None,
    },
]

ATTACKS_BY_SLUG = {a["slug"]: a for a in ATTACKS}
