**# Log4j vulnerability (CVE-2021-44228)**
A zero-day arbitrary code execution vulnerability in Log4j
On December 9, 2021, a zero-day arbitrary code execution vulnerability in Log4j 2 was reported and given the descriptor "Log4Shell".
It has been characterized as "the single biggest, most critical vulnerability of the last decade

**What you should know:**
Apache Log4j2 <=2.14.1 JNDI features used in configuration, log messages, and parameters do not protect against attacker controlled LDAP and other JNDI related endpoints. An attacker who can control log messages or log message parameters can execute arbitrary code loaded from LDAP servers when message lookup substitution is enabled. From log4j 2.15.0, this behavior has been disabled by default. 
In previous releases (>2.10) this behavior can be mitigated by setting system property "log4j2.formatMsgNoLookups" to “true” or by removing the JndiLookup class from the classpath (example: zip -q -d log4j-core-*.jar org/apache/logging/log4j/core/lookup/JndiLookup.class). 
Java 8u121 (see https://www.oracle.com/java/technologies/javase/8u121-relnotes.html) protects against remote code execution by defaulting "com.sun.jndi.rmi.object.trustURLCodebase" and "com.sun.jndi.cosnaming.object.trustURLCodebase" to "false".


**Impact**
Logging untrusted or user controlled data with a vulnerable version of Log4J may result in Remote Code Execution (RCE) against your application. This includes untrusted data included in logged errors such as exception traces, authentication failures, and other unexpected vectors of user controlled input.

**Affected versions**
Any Log4J version prior to v2.15.0 is affected to this specific issue.

The v1 branch of Log4J which is considered End Of Life (EOL) is vulnerable to other RCE vectors so the recommendation is to still update to 2.15.0 where possible.

**Remediation Advice**
This issue was remediated in Log4J v2.15.0. The Apache Logging Services team provides the following mitigation advice:

In previous releases (>=2.10) this behavior can be mitigated by setting system property "log4j2.formatMsgNoLookups" to “true” or by removing the JndiLookup class from the classpath (example: zip -q -d log4j-core-*.jar org/apache/logging/log4j/core/lookup/JndiLookup.class).

You can manually check for use of affected versions of Log4J by searching your project repository for Log4J use, which is often in a pom.xml file.

Where possible, upgrade to Log4J version 2.15.0. If you are using Log4J v1 there is a migration guide available.

Please note that Log4J v1 is End Of Life (EOL) and will not receive patches for this issue. Log4J v1 is also vulnerable to other RCE vectors and we recommend you migrate to Log4J 2.15.0 where possible.

If upgrading is not possible, then ensure the -Dlog4j2.formatMsgNoLookups=true system property is set on both client- and server-side components.

**References**
https://nvd.nist.gov/vuln/detail/CVE-2021-44228

https://github.com/tangxiaofeng7/apache-log4j-poc

https://logging.apache.org/log4j/2.x/changes-report.html#a2.15.0

https://logging.apache.org/log4j/2.x/manual/lookups.html#JndiLookup

https://issues.apache.org/jira/browse/LOG4J2-3198

https://issues.apache.org/jira/browse/LOG4J2-3201

https://logging.apache.org/log4j/2.x/manual/migration.html

https://logging.apache.org/log4j/2.x/security.html

https://security.netapp.com/advisory/ntap-20211210-0007/

https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-apache-log4j-qRuKNEbd

http://packetstormsecurity.com/files/165225/Apache-Log4j2-2.14.1-Remote-Code-Execution.html

http://www.openwall.com/lists/oss-security/2021/12/10/1

http://www.openwall.com/lists/oss-security/2021/12/10/2

http://www.openwall.com/lists/oss-security/2021/12/10/3


**Good Luck (Elazar Biro)**
