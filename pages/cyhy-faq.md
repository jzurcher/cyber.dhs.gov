# Cyber Hygiene F.A.Q.

This quick guide provides answers to the most frequest questions sent by Cyber Hygiene customers looking for more infomation and details related to this scanning service.   

* [What is the basic process of the Cyber Hygiene Vulnerability Scanning program?](#what-is-the-basic-process-of-the-cyber-hygiene-vulnerability-scanning-program)
* [We would like to add recipients to the reports distro list, how can we add them?](#we-would-like-to-add-recipients-to-the-reports-distro-list-how-can-we-add-them)
* [When does the Cyber Hygiene Vulnerability scan start?](#when-does-the-cyber-hygiene-vulnerability-scan-start)
* [How does DHS protect the confidentiality of the report?](#how-does-dhs-protect-the-confidentiality-of-the-report)
* [What information does DHS disclose about the participants of the program?  Would our organization be publicly identified as a participant?](#what-information-does-dhs-disclose-about-the-participants-of-the-program--would-our-organization-be-publicly-identified-as-a-participant)
* [Who/What entities have access to the findings of the reports?](#whowhat-entities-have-access-to-the-findings-of-the-reports)
* [How does DHS anonymize the data collected for use in supplemental reports?](#how-does-dhs-anonymize-the-data-collected-for-use-in-supplemental-reports)
* [On page two in the Cyber Hygiene agreement you mention 'You accept that your Agency bears the risk to its systems and networks described above.' Can you help me understand your definition of this line? If the scan is non-intrusive, then what risks would? Can we ammend this section?](#on-page-two-in-the-cyber-hygiene-agreement-you-mention-you-accept-that-your-agency-bears-the-risk-to-its-systems-and-networks-described-above-can-you-help-me-understand-your-definition-of-this-line-if-the-scan-is-non-intrusive-then-what-risks-would-can-we-ammend-this-section)
* [Are there any baseline statistics available that show of the average number of vulnerabilities per organization / host and the average days to remediate?](#are-there-any-baseline-statistics-available-that-show-of-the-average-number-of-vulnerabilities-per-organization--host-and-the-average-days-to-remediate)
* [Can we change the language on the NCATS legal agreements? ?](#can-we-change-the-language-on-the-ncats-legal-agreements)
* [Can NCATS sign a Non-Disclosure Agreement (NDA)?](#can-ncats-sign-a-non-disclosure-agreement-nda)
* [Why are there more Mitigated Vulnerabilities than Detected Vulnerabilities in a single year?](#why-are-there-more-mitigated-vulnerabilities-than-detected-vulnerabilities-in-a-single-year)
* [What does CIDR notation mean?](#what-does-cidr-notation-mean)
* [Are my reports subject to FOIA requests?](#are-my-reports-subject-to-foia-requests)
* [Can I have a copy of our  counter signed ROE?](#can-i-have-a-copy-of-our--counter-signed-roe)
* [I would like to understand the SecureDNS Validation report error correction process.](#i-would-like-to-understand-the-securedns-validation-report-error-correction-process)
* [DNSSEC address conflict canned language.](#dnssec-address-conflict-canned-language)
* [Can we report a potential false positive?](#can-we-report-a-potential-false-positive)
* [Will you add our private certificate authority in your root store?/ Trust Issues.](#will-you-add-our-private-certificate-authority-in-your-root-store-trust-issues)
* [Why would a vulnerability appear in one scan and not another?](#why-would-a-vulnerability-appear-in-one-scan-and-not-another)
* [Certificate Authorities (CA)](#certificate-authorities-ca)
* [M-15-01 Semi-annual Data Request.](#m-15-01-semi-annual-data-request)
* [M-15-01.](#m-15-01)
* [We have noticed scanning activity coming from 64.69.57.0/24 and or AWS. Can you confirm this traffic?](#we-have-noticed-scanning-activity-coming-from-646957024-and-or-aws-can-you-confirm-this-traffic)
* [Can you scan domains/AWS (Dynamic IP addresses/Cloud-hosted resources)?](#can-you-scan-domainsaws-dynamic-ip-addressescloud-hosted-resources)
* [Do you know when you will be able to scan IPv6 space?](#do-you-know-when-you-will-be-able-to-scan-ipv6-space)
* [I am seeing fluctuations in host counts, why is that?](#i-am-seeing-fluctuations-in-host-counts-why-is-that)
* [OS MISIDENTIFICATION and NMAP.](#os-misidentification-and-nmap)
* [NCATS/CyHy Authority To Operate.](#ncatscyhy-authority-to-operate)
* [Are there any risks associated with network scanning?](#are-there-any-risks-associated-with-network-scanning)
* [How long does the scanning usually take? ](#how-long-does-the-scanning-usually-take)
* [Why can't you scan domains?](#why-cant-you-scan-domains)
* [I am receiving reports about service impacts due to CyHy scanning against one of our Agency VPN systems?](#i-am-receiving-reports-about-service-impacts-due-to-cyhy-scanning-against-one-of-our-agency-vpn-systems)
* [Why are we being hit with so much traffic?](#why-are-we-being-hit-with-so-much-traffic)
* [What IP addresses do we send you?](#what-ip-addresses-do-we-send-you)
* [Can the testing be scheduled for a particular time-period?](#can-the-testing-be-scheduled-for-a-particular-time-period)
* [What do you define as a "host"?](#what-do-you-define-as-a-host)
* [Why is my report blank?](#why-is-my-report-blank)
* [I would like this domain removed from my HTTPS Report.](#i-would-like-this-domain-removed-from-my-https-report)
* [Why are there some hosts not showing up on the report?](#why-are-there-some-hosts-not-showing-up-on-the-report)
* [I am concerned with seeing one of our public host addresses being identified on the geo-location map as being in the state of Kansas. Would it be possible to tell me which IP address is responding from that location?](#i-am-concerned-with-seeing-one-of-our-public-host-addresses-being-identified-on-the-geo-location-map-as-being-in-the-state-of-kansas-would-it-be-possible-to-tell-me-which-ip-address-is-responding-from-that-location)
* [Can you share the raw .nessus file for the Cyber Hygiene reports?](#can-you-share-the-raw-nessus-file-for-the-cyber-hygiene-reports)
* [Can you please provide us with a CVE number for the vulnerability that was detected in our latest report?](#can-you-please-provide-us-with-a-cve-number-for-the-vulnerability-that-was-detected-in-our-latest-report)
* [Why is the vulnerability severity in our Cyber Hygiene report different from the severity listed on the Nessus plugin website?](#why-is-the-vulnerability-severity-in-our-cyber-hygiene-report-different-from-the-severity-listed-on-the-nessus-plugin-website)
* [I see vulnerability scanning is now coming from AWS, not your 64 network as previously specified, why?](#i-see-vulnerability-scanning-is-now-coming-from-aws-not-your-64-network-as-previously-specified-why)
* [How should I handle your scanning traffic? Should I whitelist your source IPs especially since you are scanning from AWS?](#how-should-i-handle-your-scanning-traffic-should-i-whitelist-your-source-ips-especially-since-you-are-scanning-from-aws)
* [Details about Third Party Authorization.](#details-about-third-party-authorization)
* [Can you rescan us?](#can-you-rescan-us)
* [Does *domain* need an SPF/DMARC record?](#does-domain-need-an-spfdmarc-record)
* [Why aren't you scanning for DKIM?](#why-arent-you-scanning-for-dkim)
* [More Trustworthy Email Information:](#more-trustworthy-email-information)
* [Why aren't all subdomain details provided?](#why-arent-all-subdomain-details-provided)
* [What are email authentication technologies, and what do they do?](#what-are-email-authentication-technologies-and-what-do-they-do)
* [What does the Trustworthy Email report tell me?](#what-does-the-trustworthy-email-report-tell-me)
* [What should my organization do?](#what-should-my-organization-do)
* [How do I implement email authentication?](#how-do-i-implement-email-authentication)
* [What should I do with domains that don't send mail?](#what-should-i-do-with-domains-that-dont-send-mail)
* [Can email authentication hinder my organization's ability to deliver email?](#can-email-authentication-hinder-my-organizations-ability-to-deliver-email)
* [What is the logic behind determining BOD 18-01 Email Security Compliance?](#what-is-the-logic-behind-determining-bod-18-01-email-security-compliance)

#### What is the basic process of the Cyber Hygiene Vulnerability Scanning program?
NCATS scans for and reports on vulnerabilities that are detectable from outside your organization's network. One major purpose of Cyber Hygiene is proactive identification of vulnerabilities directly accessible for exploitation by an external party from the Internet. The idea is that we find and report on things from a perspective similar to that of an attacker. This perspective enables us to better gauge risk and exposure and inform urgency of response to threats and vulnerabilities.

During Cyber Hygiene scanning we use two tools: Nmap and Nessus Tenable. Nmap helps us to detect Internet Protocol (IP) addresses that have at least one open port or listening service, which we define as 'hosts'. We then vulnerability scan the IPs we've identified as 'hosts' persistently at a frequency determined by the severity level of the vulnerabilities detected on the host. IPs that are not found to be hosts are labeled as 'dark space' and will be rescanned 90 days later to check for changes.

The vulnerability findings we detect on your hosts as well as other pertinent information (such as the scope we are currently scanning for your organization) are included in a PDF report that we send out weekly, typically on Mondays. Within the PDF, you will find summary information and charts as well as more detailed, filterable spreadsheet attachments.

Any change requests to modify scope, technical POCs, to whom we distribute your reports, or false positive assertions should be sent to NCATS@hq.dhs.gov. That is also the address to send any questions you may have regarding the report, its findings, or anything else we can potentially help with about the Cyber Hygiene program.

#### We would like to add recipients to the reports distro list, how can we add them?
If you intend to have your report sent to more than one person or group inside your organization, we request that you set up a distribution list within your organization.  This allows you, as the customer, to manage the list and add/remove people as necessary.  If you'll be the only recipient, we'll just mail reports directly to you.

#### When does the Cyber Hygiene Vulnerability scan start?
Once we have all of the necessary information, we can add your organization as a new stakeholder within our database and initiate the scans no sooner than your preferred start date. You'll be able to tell that scanning has started once you see traffic from our source IPs (available at https://rules.ncats.cyber.dhs.gov/cyhy).

#### How does DHS protect the confidentiality of the report?
The data of the report is encrypted from the time it is delivered from the scanner to the report generator. The data resides in the NCATS lab, which is a special enclave that falls under the NCATS data storage and handling guidelines.

#### What information does DHS disclose about the participants of the program?  Would our organization be publicly identified as a participant?
The Department of Homeland Security (DHS) does not disclose the participants outside of the Department. For leadership situational awareness, Cyber Hygiene scanning and testing activities are always reported across the NCCIC. Your organization would NOT be publicly identified in a report. DHS's National Cybersecurity and Communications Integration Center (NCCIC) is authorized by statute to share cybersecurity information and provide cybersecurity technical assistance, risk management support, and incident response capabilities to both federal and non-federal entities (including private companies) upon the entity's request. Our Cyber Hygiene scanning services relate to these authorities. Our work with non-federal entities in this arena is purely voluntary, the NCCIC is not a regulator, and the National Cybersecurity Protection Act of 2014 states that no private entity is obligated by these authorities to request or receive technical assistance or implement any DHS recommendations (6 U.S.C. 148 note).

#### Who/What entities have access to the findings of the reports?
DHS and more specifically the National Cybersecurity and Communications Integration Center (NCCIC) has access to the findings of the Cyber Hygiene findings.

#### How does DHS anonymize the data collected for use in supplemental reports?
At the end of the year, DHS creates an anonymized report that shows high level statistics and findings for purposes of trending analysis only.

#### On page two in the Cyber Hygiene agreement you mention 'You accept that your Agency bears the risk to its systems and networks described above.' Can you help me understand your definition of this line? If the scan is non-intrusive, then what risks would? Can we ammend this section?
Cyber Hygiene is intended to be non-intrusive, but network scanning always carries some level of risk. It's possible our scans could cause degradation to your network availability, making otherwise performant applications appear latent. It's possible that we could bring down a scanning target. It's possible that a scan could trigger and exploit a vulnerability, instead of simply detecting its presence. We've carefully tuned our scans, and can tune further per stakeholder, so that those things don't happen. Ultimately, modification of the agreement the subject to the approval of our general counsel team.

#### Are there any baseline statistics available that show of the average number of vulnerabilities per organization / host and the average days to remediate?  
Due to the many variables in the size and structure of the organizations we scan, we do not yet provide performance or detection averages.

#### Can we change the language on the NCATS legal agreements?
Our legal agreements were carefully written by the DHS Office of General Council (OGC) and approved by DHS management. While change requests are not normally accepted, you may email your change requests to NCATS@hq.dhs.gov and we will pass your requests on to our OGC team.

#### Can NCATS sign a Non-Disclosure Agreement (NDA)?
No. DHS OGC does not allow NCATS team members to sign Non-Discolousure Agreements (NDAs) as federal employees already have statutory nondisclosure obligations under the Trade Secrets Act, 18 U.S. Code 1905. Regarding the contractors who work with DHS, all contractors are required to sign a NDA with DHS covering our work prior to starting on our contracts (DHS Form 1100-06 [08-04]).

#### Why are there more Mitigated Vulnerabilities than Detected Vulnerabilities in a single year?
Detected Vulnerabilities are carried over from year-to-year, so the number of vulnerabilities mitigated in a year can be greater than the number of vulnerabilities detected in that year.

#### What does CIDR notation mean?
CIDR notation is a simpler way to express a range of IP addresses. For example, if you are providing a range of 10.0.0.0 - 10.0.0.255 you can provide it in CIDR notation which would be 10.0.0.0/24. The number after the slash is the bit mask for the network. It tells you how many bits are the same for each IP on the subnet. There are free open-source tools that can help you convert IPv4 Conversion to CIDR.

#### Are my reports subject to FOIA requests?
There are a number of FOIA exemptions that could be applicable.' In general, CS&C will not disclose any information that is exempt from disclosure under FOIA consistent with 5 U.S.C. ' 552(b), including but not limited to Exemption (b)(3) as specifically exempt from disclosure by statute, Exemption (b)(4) as trade secrets and commercial or financial information that is privileged or confidential and Exemption (b)(7)(A)-(F) as records or information compiled for law enforcement purposes. CS&C makes determinations regarding FOIA requests on a case by case basis consistent with its obligations under FOIA, DHS FOIA regulations, and its own internal guidance. Any determinations regarding specific FOIA exemptions will be made at the time that the responsive records are processed. When applicable, CS&C will provide the submitter notifications and opportunity for the Entity who submitted the information to DHS originally to object to disclosure as required by 6 C.F.R. ' 5.7 (a)-(j).?

#### Can I have a copy of our  counter signed ROE?
Thank you for your email. Due to the number of ROE's NCATS receives, our branch director sits down once every two weeks to sign all ROE's that are in his queue. After they are signed, there is still some processing that must happen before they are finally filed. When the ROE completes the full process they are then provided to the entity.

#### I would like to understand the SecureDNS Validation report error correction process.
Reports are only sent out when a domain is not fully compliant. We can conduct further analysis with both DNSSEC Analyzer and DNSviz, and both presently show the domain appears compliant. Our scans should be considered a snapshot in time. Note that we do not control or have administrative privileges on the domains that we scan (that would be dotgov.gov); we are only enabled to scan and give you the report of the current status of your agency's registered domains.

#### DNSSEC address conflict canned language.
It's our intent to merge the DNSSEC report into the Cyber Hygiene report by the end of the quarter. What this means operationally is that a single report will be delivered to each individual agency distro list.

#### Can we report a potential false positive?
Thank you for notifying NCATS of the potential false positive. The Cyber Hygiene (CyHy) team has the ability to mark the result as a false positive. Please go to the Attachment section of your Cyber Hygiene report and fill out the False Positive form attached. 'If you need to attach additional evidence of your analysis, please send in an email attachment (word, txt, or excel are preferred). 'The CyHy team will review the analysis upon receipt. 'You may still see the IP on the report but it will be in the False Positive findings. However, if the'continue to see the vulnerability on the following report, please email NCATS@hq.dhs.gov.

#### Will you add our private certificate authority in your root store?/ Trust Issues.
NCATS/Cyber Hygiene'does not accept private certificate authorities (CA) for submission into our root store. This is a deliberate decision in order to support the HTTPS-only mandate (M-15-13). Our scanner uses the Mozilla root store, which contains unambiguously-public certificate authorities

M-15-13 applies to all federal sites and services that are publicly reachable over HTTP/HTTPS,not simply those intended for the public's use. Using a federally-issued certificate is a decision your agency could choose to make, butyou should understand why this may or may not be a good idea. We previously manually trusted the Federal Common Policy CA, but removed it from our scanner's root store in September 2016 to support correct implementation of the policy.

You can use our scanning tool,pshtt, to determine compliance-- when 'Domain Supports HTTPS', 'Domain Enforces HTTPS', and 'Domain Uses Strong HSTS' are all ""True"", that domain is M-15-13 compliant.

#### Why would a vulnerability appear in one scan and not another?
The reason we hope for is that you've remediated the problem, but it could be that our scans are blocked by a firewall, our scanning has triggered an IPS, or network conditions are hazardous to the life of the packets we've sent (i.e., "the Internet happens"). However, because we have no idea which of these is the case, the only way we can validate that a vulnerability has actually been resolved is by checking whether it is undetectable for a period of time, which we've set to 90 days. If a vulnerability appears by our scans to be flapping (detectable, then not; repeat ad infinitum), it wouldn't be correct to say each new appearance is day 1 in the life of the vulnerability. This is how the BOD Scorecard can suddenly be reporting a vulnerability as 30+ days old when no prior reports showed it: a vulnerability was present at a point in time (within the last 90 days), but not on any 'most recent scan' before a given report except the present one.
'
It is worth noting that all vulnerabilities that are found in the prior report but not in the current one are in Appendix C 'Resolved Vulnerabilities'. Though listed as 'Resolved', we encourage recipients of our reports to validate the status of the vulnerabilities we report in Appendix C against their change control register to ensure that a vulnerability has actually been remediated and is not simply unresponsive to our scans.

#### Certificate Authorities (CA).
We do not accept private certificate authorities (CA) for submission into our root store. This is a deliberate decision in order to support the HTTPS-only mandate (M-15-13). Our scanner uses the Mozilla root store, which contains unambiguously-public certificate authorities. M-15-13 applies to all federal sites and services that are publicly reachable over HTTP/HTTPS, not simply those intended for the public's use. Using a federally-issued certificate is a decision your agency could choose to make, but you should understand why this may or may not be a good idea. We previously manually trusted the Federal Common Policy CA, but removed it from our scanner's root store in September 2016 to support correct implementation of the policy. If you decide to use a private root on the sites in question, we will be mark them as false positives once they otherwise comply with M-15-13. You can use our scanning tool, pshtt, to determine compliance-- when 'Domain Supports HTTPS', 'Domain Enforces HTTPS', and 'Domain Uses Strong HSTS' are all ""True"", that domain is M-15-13 compliant.

It is correct that the Federal Common Policy CA, the FPKI trust anchor, is not included in our scanning root store and will not be re-added, so just reissuing certs that chain to the FCPCA won't resolve these vulnerabilities in Cyber Hygiene. However, there are a few things you should understand:
* All Federal operated domains are within scope for M-15-13, which requires HTTPS + HSTS by Dec. 31, 2016. M-15-13 applies to all web sites and services, regardless of whether they are in practice only used internally.
* M-15-13 has no restrictions over what certificates authorities must be used'but certificate authorities are implicated by the use of HSTS because HSTS disables the ability for users to click through certificate warnings. All users without the State AD Root CA in their trust store (or the FCPCA, if a FCPCA-chaining cert was used) will get errors on this site.
* The compliance guide at https.cio.gov hits on next steps very effectively, so I'm going to just quote it: 'In practice, to deploy HSTS while using federally issued certificates, an agency will likely need to separate its web services by hostname, based on their expected audience: Federally issued certificates may be practical for web services whose users can be consistently expected to trust the issuing federal certificate authority (CA). Users whose devices do not trust the issuing CA will experience a connection failure and be unable to use the web service. Federally issued certificates will not be practical for web services whose users may not always be expected to trust the issuing federal certificate authority. These web services will likely require the use of a certificate from a publicly trusted (commercial) CA.
* Basically, if this is a site that will be used solely by those for whom State controls their operating system's root store (i.e., you can 'consistently expect' the users will trust the issuing federal CA), then set an HSTS header that meets the M-15-13 requirement (max-age=31536000) and we will mark this as a false positive. If this is a site that State is providing to the public, even to users for whom you are not managing the trust store setting an HSTS header/complying with M-15-13 will be a challenge and State should use a publicly trusted certificate, like the CyHy report recommends.

#### M-15-01 Semi-annual Data Request.
In the 'M-15-01 Semi-annual Data Request' email, we stated 'This request encompasses all agency information systems-- those used or operated by an agency or by a contractor of an agency or other organization on behalf of an agency.' The language 'used or operated by an agency or by a contractor of an agency, or other organization on behalf of an agency' is taken directly from FISMA. This language is used multiple times when the act uses the word 'information system' to make clear that it does not matter whether the system is government owned and operated or whether there is another arrangement. In the language of FISMA, a government system is a government system no matter who is responsible for care and feeding.

#### M-15-01.

M-15-01 also says agencies shall 'provide DHS, on a semiannual basis, with a complete list of all internet accessible addresses and systems including static IP addresses for external websites, servers and other access points and domain name service names for dynamically provisioned systems' and shall 'Provide DHS with names of vendors who manage, host, or provide security for internet accessible systems, including external websites and servers, and ensure that those vendors have provided any necessary authorizations for DHS'scanning of agency systems'. We don't have a particular need here for the names of the vendors, but it seems clear that there wouldn't be a requirement to ensure the vendor has 'authorized DHS scanning of agency systems' unless we were actually going to scan them. Taken together, we understand these two clauses to allow us to scan your external service providers-- though of course we anticipate that each agency will seek to arbitrate a clear authorization with their service providers.
'
In summary, we assert that we do have the authority to scan agency information systems, whether they are hosted by an agency directly or by a service provider. To date, we have not knowingly scanned a third-party system without an agency first ensuring the service provider is apprised of the scans, however. If you believe we are scanning your third-parties without authorization, we request that you immediately notify us which IPs we need to remove.

#### We have noticed scanning activity coming from 64.69.57.0/24 and or AWS. Can you confirm this traffic?
This is DHS authorized testing via the NCATS Cyber Hygiene program. The scanning takes place per OMB M-15-01 and the Binding Operational Directive (BOD)'15-01 issued by the DHS Secretary and OMB. The authority for the BOD is given under the FISMA Modernization Act of 2014.
'
All of NCATS scanning traffic originates from the 64.69.57.0/24 network and IPs listed athttps://rules.ncats.cyber.dhs.gov.
'
Feel free to reach out directly to NCATS@hq.dhs.gov and copy'_________ (Tech'POC'on file)'with any questions/concerns regarding our vulnerability scanning.

#### Can you scan domains/AWS (Dynamic IP addresses/Cloud-hosted resources)?
The NCATS/Cyber Hygiene team does not have the capability to scan Dynamic IP addresses or Cloud-hosted resources. This is a capability that the team is working on developing for the future.

#### Do you know when you will be able to scan IPv6 space?
The NCATS team is currently developing ways to scan IPv6 space. We will inform our customers when we have fully developed our capability.

#### I am seeing fluctuations in host counts, why is that?
Host count can fluctuate for the following reasons:
1) Your IP space is significantly large enough that we are unable to complete a full rescan of all of your hosts in between weekly reports.
2) After the initial scan of your entire IP space, we found some hosts to be ""non-responsive"" (e.g., our scans are blocked by host or network filters, the device is down for maintenance, packets are dropped or lost en route, etc.). All ""non-responsive"" hosts are marked for re-scan in 90 days. Upon rescan, host count may jump as we detect new live hosts that were previously dark.'

The intent of CyHy is to find vulnerabilities, not count hosts, and our metrics should not be relied upon as a verified host count of your organization. The weekly host count should be taken as an estimate. If, however, there are no or extremely low host counts reported when there are known active hosts, it is possible that the CyHy scans are being blocked.

#### OS MISIDENTIFICATION and NMAP
OS identification is a function of Nmap, one of the tools we use in scanning. An attempt is made to detect the operating system by evaluating how a system responds compared to known responders.
'
If Nmap is wrong and you'd be willing to help out the security ecosystem, we'd encourage you to check out https://nmap.org/book/osdetect-unidentified.html#osdetect-wrong, where instructions are given how to collect an OS fingerprint and then submit them to the tool's development team.
'

(We'd love to hear back from you if you have success doing this! Your contributions to the tool will get incorporated into Nmap, and we generally stay current with the latest versions.)

#### NCATS/CyHy Authority To Operate
DHS's National Cybersecurity and Communications Integration Center (NCCIC) is authorized by statute to share cybersecurity information and provide cybersecurity technical assistance, risk management support, and incident response capabilities to both federal and non-federal entities (including private companies) upon the entity's request. 'Our Cyber Hygiene scanning services relate to these authorities. 'Our work with non-Federal entities in this arena is purely voluntary, the NCCIC is not a regulator, and the National Cybersecurity Protection Act of 2014 states that no private entity is obligated by these authorities to request or receive technical assistance or implement any DHS recommendations.'6 U.S. Code ' 148


#### Are there any risks associated with network scanning?
Cyber Hygiene is intended to be non-intrusive, but network scanning always carries some level of risk. It's possible our scans could cause degradation to your network availability, making otherwise performant applications appear latent. It's possible (though unlikely) that we could bring down a scanning target. It's possible that a scan could trigger and exploit a vulnerability, instead of simply detecting its presence.'Since our scanning is persistent, there is a possibility that it may impact daily operations. We've carefully tuned our scans, but we can tune further per stakeholder so that those things don't happen. You have the option to create scan windows and adjust IP address scanning concurrency. Customers who elect for scan windows normally like us to scan outside of business hours in their time zone (7 PM ' 6 AM, 7 days a week).'If you wish to modify scanning concurrency, most customers elect to cut the rate in half and see how performance changes.

#### How long does the scanning usually take?
The total scan time depends on:
1) the number of addresses provided
2) the number of active hosts detected
3) the number of hosts with vulnerabilities.

We test in stages: first to look for active hosts (i.e. are any services running in the top 30 ports?), then ' if services are detected'to look for services over a larger number of ports, and then to test all active hosts for known vulnerabilities.

After the initial scan is complete, we then re-scan periodically based on the level of vulnerability severity detected. Hosts with no detected services we classify as 'dark space' and don't rescan for another ~90 days. Active hosts with no vulnerabilities are rescanned once every 7 days. Hosts with vulnerabilities are scanned according to the following schedule:
* Critical - 12 hours
* High - 24 hours
* Medium - 4 days
* Low - 6 days

This is all to say that your scan time is dependent on what we find. Could be a few minutes, could be an hour or more.'

#### Why can't you scan domains?
The Cyber Hygiene vulnerability scanning service is currently unable to perform domain based scans because of the challenge dynamically assigned IP addresses pose to our vulnerablity tracking process. We are working to add the capability to automatically migrate a host's vulnerability history in our database as the host's IP changes, but do not yet have a timeframe for completion. Once added, however, we will be able to both scan by domain and by IP address.

#### I am receiving reports about service impacts due to CyHy scanning against one of our Agency VPN systems.
Service impacts from our scans are not something we regularly hear about from our stakeholders, but something we clearly want to avoid. If you believe our scans are impacting your organization's services, we can-- a) reduce the number of IP addresses we scan concurrently, b) schedule defined scanning windows at off-peak times, or c) both.

#### Why are we being hit with so much traffic?
That is normal web-scanning activity. Our primary scanning tool currently has 940 plugins in the "Web Servers" family alone and another 4000 or so in the "CGI abuses" families that we run. There is a lot of web activity that will occur in order to run all of those scans, especially on the initial scan when we are mapping the entire IP space and scanning all discovered, active hosts for our whole set of known vulnerabilities. After initialization, scan intensity will decrease and 'each host will at maximum receive two scan sessions per day (for hosts with critical vulnerabilities). As you mitigate vulnerabilities, you should see our overall scan volume decrease, since we scan hosts less-frequently if they have less-severe vulnerabilities. While we have tuned our scans to be as unobtrusive as possible, we do understand our scans can be heavy on some networks. 'If you believe our scans are impacting your organization's services, we can-- a) reduce the number of IP addresses we scan concurrently, b) schedule defined scanning windows at off-peak times, or c) both.'

#### What IP addresses do we send you?
Section II (pg. 8) of the M-15-01 says agencies 'shall'Provide DHS, on a semiannual basis, with a complete list of all internet accessible addresses and systems, including static IP addresses for external websites, servers and other access points and domain name service names for dynamically provisioned systems'. Basically, give us all public IP ranges and domain names (including subdomains) for your agency. The entire block of addresses will be scanned initially; any IPs that appear dark to us (either because there is no active service at the address, or we're blocked, etc.) will be rescanned after 90 days. Those addresses that have = 1 service running are scanned at least once per week, with increased frequency for each grade (Low, Medium, High, Critical) vulnerability.

#### Can the testing be scheduled for a particular time-period?
You can provide us a date and time when you would like to have the initial scan started no earlier than. After the initial scan, the default configuration is for persistent scanning that is allowed to occur anytime (noting that in the worst case of critical vulnerabilities on every active host, you will at maximum see see two scan sessions per day per host). The persistent scanner is optimized to not weigh down the network or cause service impacts. The technical team can, however, work with you to monitor the activity and if your team needs to adjust the time or scan frequency (or modify the IP scanning concurrency) we can work with you to make those changes.

#### What do you define as a "host"?
The cyber hygiene reports may display a smaller number of "Hosts" than previously in the "Cyber Hygiene Report Card High Level Findings" at the top of page 4. In some cases, the number of hosts could be significantly less than in the past. This is due to a change in what we are considering to be a host. Previously, any device that responded to our scan with a TCP acknowledgement, reset or ICMP echo was considered a host, even devices where no open ports were detected. In the interest of more accurate reporting, we are now considering a host to be a device with at least one open port detected. For the purposes of Cyber Hygiene, we believe this updated definition of a host will be of greater value than the previous definition because it only includes devices that respond and are accessible in a more meaningful way.

#### Why is my report blank?
Thank you for reaching out. A blank report typically indicates a firewall/IPS blocked our scanner's traffic and prevented us from identifying hosts. If your report is showing 0 hosts, can you please confirm that our source IPs (listed athttps://rules.ncats.cyber.dhs.gov/all.txt) are not blocked*? Please also check the "scope.csv" attached within your most recent Cyber Hygiene report'to ensure that we are scanning the correct IP space.'The attachment can be found by clicking the arrow along the left side of the PDF to expand the navigation menu, clicking the paper clip icon, and then double clicking the attachment you wish to view.

#### I would like this domain removed from my HTTPS Report.
Agencies can make requests for IPs to be added/removed, but we do not remove domain names, second level domains, or sub-domains. If these domains are still registered at GSA's DotGov, you will want to reach out to the people at DotGov (registrar@dotgov.gov) to remove these domains. Once they are removed, we should be able to detect that they are no longer live.
'
'

#### Why are there some hosts not showing up on the report?
Host count can fluctuate for the following reasons:
1) Your IP space is significantly large enough that we are unable to complete a full rescan of all of your hosts in between weekly reports.
2) After the initial scan of your entire IP space, we found some hosts to be ""non-responsive"" (e.g., our scans are blocked by host or network filters, the device is down for maintenance, packets are dropped or lost en route, etc.). All ""non-responsive"" hosts are marked for re-scan in 90 days. Upon rescan, host count may jump as we detect new live hosts that were previously dark.

The intent of CyHy is to find vulnerabilities, not count hosts, and our metrics should not be relied upon as a verified host count of your organization. The weekly host count should be taken as an estimate. If, however, there are no or extremely low host counts reported when there are known active hosts, it is possible that the CyHy scans are being blocked

#### I am concerned with seeing one of our public host addresses being identified on the geo-location map as being in the state of Kansas. Would it be possible to tell me which IP address is responding from that location?
Hosts that show up in Kansas are usually reserved when the geolocation database' we pull data from does not recognize an actual location and defaults to Kansas.

#### Can you share the raw .nessus file for the Cyber Hygiene reports?
We are not able to share the raw .nessus file given the way we conduct our scans. All IP addresses across all Cyber Hygiene'subscribers are put into a scanning queue that is prioritized by 1) first scan (new organizations) and then 2) vulnerability severity. The set up means we are scanning multiple different organizations at once and cannot provide a raw .nessus file for an individual organization. To develop the final report that you do receive, we parse information from the group file and put them into the csv files that is then attached to your report.

#### Can you please provide us with a CVE number for the vulnerability that was detected in our latest report?

That information is contained in the findings.csv attachment in Appendix G of your report. If no CVE is listed then the Nessus Plugin ID should be used to gather further specifics. We use a Tenable Nessus scanner to source our vulnerability information and not all Nessus plugins have an associated CVE or may have have multiple CVEs.

#### Why is the vulnerability severity in our Cyber Hygiene report different from the severity listed on the Nessus plugin website?
The source of the confusion is how we prioritize scoring sources. Our scanner goes through a long list of Nessus plugins to check for the presence of a vulnerability. When one is discovered, we first check if that vulnerability is listed in the National Vulnerability Database (NVD) using a CVE identifier (if present) to determine what severity level the National Institute of Standards and Technology (NIST) has marked the vulnerability as. If the NVD does not have the vulnerability listed (or no CVE is listed), then we default to the Nessus rating. Where the NVD and Nessus both have a score but they're different, we prioritize the government source (NVD).

#### I see vulnerability scanning is now coming from AWS, not your 64 network as previously specified, why?
We are now scanning from AWS to increase the resilience and scalability of our scanning service. You can see a list of the current Ips that we are using to scan by going to:  https://rules.ncats.cyber.dhs.gov

#### How should I handle your scanning traffic? Should I whitelist your source IPs especially since you are scanning from AWS?

One major purpose of Cyber Hygiene is proactive identificationofvulnerabilities directly accessible for exploitation by an external party from the Internet.' This perspective enables us to better gauge risk and exposure and inform urgency of response to threats and vulnerabilities.'
'
We request that you do not provide us preferential treatment or atypical network access, as it would negatively impact the accuracy of our findings.' However, because our scanning is focused on identifying exposed vulnerabilities prior to their exploitation, and due to timing and urgency considerations, we make no attempts at stealth, which may sometimes trigger IPS capabilities that an attacker using more conservative tactics might not.' Please remove any network blocks should this occur.

So that you can distinguish our scans from random Internet noise, we publish our scanning addresses athttps://rules.ncats.cyber.dhs.gov/all.txt. This allows you to properly triage and respond to alerts generated by your SIEM. To reduce alerts and conserve analyst resources, it may be prudent to configure your SIEM sensors to not generate alerts on traffic from our published addresses. These addresses may change without prior notice, so we recommend regular monitoring of this file.'Additionally, we request that you inform third parties acting on your behalf of the legitimacy of our scanning activities and direct them to not block our scanning addresses, promptly remove them from any sort of blocking should it occur, and not report our addresses as malicious/abusive.

#### Details about Third Party Authorization.
In order to scan a department/agency, we require an authorization. However, when an agency has IPs that are managed by a third party (which is likely a frequent occurrence), we do not require an authorization. Departments and agencies should communicate with their third parties that they will be scanned and provide us will relevant IPs-- and the'department/agency might want/need to have something written between themselves and their third parties-- but when agencies pass us IPs, we can operate under the presumption that we are authorized to scan them (i.e., we don't need their authorization, and we don't need to archive such an authorization we might receive).

#### Can you rescan us?
Unfortunately, we are not currently able to generate ad-hoc reports for a single organization. Our weekly reporting tool (run all at once for every organization) does the parsing to give us the findings.csv you see in your report on Mondays. We recommend running your own scans on the IPs in between our weekly report delivery if you think you've mitigated the vulnerabilities and want to double check their status; you'll likely get better insight too since your scanners are likely whitelisted for your environment.
**add this for Trustymail**
You can use `trustymail`, our open source scanner to check your work (https://cyber.dhs.gov/resources/). The `Trustymail` tool is Python code that can run in developer environments; it is not a web based tool.

#### Does *domain* need an SPF/DMARC record?
Per BOD 18-01, one of the requirements before January 15, 2018 is to "configure all second-level domains to have valid SPF/DMARC records." If the domain is a second-level domain, then according to BOD 18-01, it is required to have valid SPF and DMARC records.'

#### Why aren't you scanning for DKIM?
DKIM is an effective tool that we recommend deploying on mail-sending hosts. While DKIM information is placed in an organization's public DNS, querying it out first requires a 'selector', which would need to be obtained from you prior to scanning. While this coordination could be done, we would then be detecting something that we already know exists.

#### More Trustworthy Email Information:
https://cyber.dhs.gov/bod/18-01/

#### Why aren't all subdomain details provided?
We do not show a subdomain in that table if they meet ANY of the following conditions:

'	Their parent (second-level) domain has a valid DMARC record (since that covers the subdomain as well)
'	The subdomain does NOT support SMTP  

For your report, all of the subdomains that support SMTP are covered by a second-level domain with a valid DMARC record, and none of those subdomains have their own DMARC record, therefore none of those subdomains are being displayed.


#### "What are email authentication technologies, and what do they do?"
Email authentication technologies enable the recipient of a email to have reasonable confidence that a message that purports to be from a given domain is or genuine or not.
SPF and DKIM (Sender Policy Framework and DomainKeys Identified Mail, respectively) both involve placing records in the organization's DNS database (as TXT records) so that a recipient can check those records when an email is received. SPF records detail the canonical source(s) (IP addresses, or a domain to find those IP addresses) authorized to send email on behalf of a domain. DKIM involves the cryptographic signing of individual email messages. When a DKIM-signed email is received, the recipient uses the public key posted in the DNS (at a location detailed in the DKIM Signature) to verify authenticity. In effect, both these techniques allow a sending domain to 'watermark' emails from their domain, making spoofed emails easier to detect.
'

#### What does the Trustworthy Email report tell me?
This report answers the question, 'Which of my second-level .gov domains use SPF and DMARC?', and attempts to guide you through why that matters and what should be done about it.''This report does not (and cannot) represent whether your organization uses email authentication results as a meaningful indicator for delivering mail within your enterprise.'For more recommendations and guidelines for enhancing trust in email, please go to: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-177.pdf'

#### What should my organization do?
Carefully review SP 800-177, section 4, particularly the write up on DMARC (4.6). For all second-level .gov domains and all mail-sending hosts generally, make a plan to implement SPF, DKIM(mail-senders only), and DMARC, with a goal of setting 'p=reject' on all second-level .gov domains.This guidance applies to all hosts that use non-.gov top-level domains, though presently this report only tracks .gov domains.

#### How do I implement email authentication?
DMARC was developed to enable cautious deployment. While the standard has three policy states (none, quarantine, and reject), it also has a pct, or percent, option that a domain owner can use to tell recipients what volume of messages should have the policy applied. When pct is left unspecified, the default value of 100% is used.



When implementing email authentication for a domain for the first time, a sending domain owner is advised to first publish a DMARC [resource record] with a 'none' policy before deploying SPF or DKIM. This allows the sending domain owner to immediately receive reports indicating the volume of email being sent that purports to be from their domain. These reports can be used in crafting an email authentication policy that reduces the risk of errors.

A DMARC record that follows this recommendation, as set on _dmarc.example.gov, looks like this: 'v=DMARC1; p=none; rua=reports@example.gov;'

Google has a valuable help page that includes recommendations for systematically getting to 'p=reject', see Recommendations for ramping up DMARC use.""

For more details on implementing email authentation and compliance guide, please visit: https://cyber.dhs.gov/bod/18-01/


####  What should I do with domains that don't send mail?
Properly set, DMARC policies at a base domain ('example.gov') can act as a wildcard, covering subdomains generally (including non-mail-sending domains), while still allowing for different settings on specific mail-sending hosts ('project.example.gov'). With DMARC 'p=reject', it is not necessary to specify SPF 'null records' on every active domain in the zone, though doing so is not harmful.



####  Can email authentication hinder my organization's ability to deliver email?
Yes. Your organization should thoughtfully deploy these technologies, weighing your specific mission requirements.''In particular, deploying DKIM and DMARC without care can impact your organization's ability to deliver some types of mail:
'''''''''DKIM is known to cause problems for mailing lists that use older listserv software. This is because some mailing list software modifies parts of the email or email headers, which invalidates DKIM. Updating the software is often the easiest solution.
'''''''''The challenges around 'indirect email flows' are currently being worked through in the Internet Engineering Task Force via a new standard called ARC, Authenticated Receive Chain. See the internet draft and the ARC website.
'''''''''A DMARC policy of p=reject tells recipients to drop mail that does not match the specified SPF and DKIM policies. While this has no impact on domains that don't send mail, it will cause delivery failure when there is a policy mismatch; indeed, that is its purpose!'

#### What is the logic behind determining BOD 18-01 Email Security Compliance?
The following is taken from the BOD 18-01 Email Compliant section on the Trustworthy Email Report (with added logic):

Whether a hostname meets all of the following criteria for being compliant with BOD 18-01 for email security:
      ' Uses STARTTLS on all SMTP servers (or has no SMTP servers)
            o Where ('Domain is Base Domain' = TRUE OR 'Domain Supports SMTP' = TRUE) AND          ('Live' = TRUE) AND ('Supports STARTTLS' = TRUE OR ('MX Record = TRUE' AND 'Domain Supports SMTP' = FALSE) OR 'MX Record = FALSE')
      ' Has a valid SPF record
            o Where ('Domain is Base Domain' = TRUE OR 'Domain Supports SMTP' = TRUE) AND ('Live' = TRUE) AND ('VALID SPF' = TRUE)
      ' Has a valid DMARC record with 'p=reject'
            o Where ('Live' = TRUE) AND ('Valid DMARC Record on Base Domain' = TRUE) AND ('DMARC Policy' = 'reject')
      ' Has a valid DMARC record with 'rua=mailto:reports@dmarc.cyber.dhs.gov'
            o Where ('Live' = TRUE) AND ('Valid DMARC Record on Base Domain' = TRUE) AND ('DMARC Aggregate Report URIs' CONTAINS 'mailto:reports@dmarc.cyber.dhs.gov')
      ' SSLv2, SSLv3 and 3DES, RC4 ciphers are not supported on all SMTP servers (or has no SMTP servers)
            o Where ('Domain is Base Domain' = TRUE OR 'Domain Supports SMTP' = TRUE) AND ('Live' = TRUE) AND ('Domain Supports Weak Crypto' = FALSE)
