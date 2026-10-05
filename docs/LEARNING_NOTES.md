PHASE 6 - MITRE ATT\&CK MAPPING



What I learned:



MITRE ATT\&CK describes adversary behaviors.



Tactic:

Why the attacker performs an action.



Technique:

How the attacker performs the action.



Sub-technique:

A more specific implementation of a technique.





Example 1:



25 Failed Login Attempts



↓



Credential Access



↓



T1110 - Brute Force





Example 2:



PowerShell Execution



↓



Execution



↓



T1059.001 - PowerShell





Important Principles:



1\. MITRE mapping is not a malicious verdict.



2\. Mapping must be supported by evidence.



3\. Do not map more specific sub-techniques

&#x20;  unless evidence supports them.



4\. No evidence means no mapping.



5\. MITRE mapping should be deterministic

&#x20;  before involving the LLM.





\## Phase 8 - Gemini AI Investigation



Provider:



Google Gemini





Architecture:



Security Alert

↓

Threat Intelligence

↓

MITRE ATT\&CK

↓

Risk Engine

↓

Evidence Package

↓

Gemini

↓

AI Investigation





Gemini Responsibilities:



\- Explain collected evidence

\- Generate investigation summary

\- Produce findings

\- Provide evidence-backed verdict

\- Recommend analyst actions





Gemini Does NOT:



\- Create threat intelligence

\- Decide MITRE mappings

\- Calculate deterministic risk

\- Execute remediation

\- Fabricate missing evidence





Structured Output:



Verdict

Confidence

Summary

Findings

Recommended Actions





Core Principle:



Evidence First

↓

AI Explanation Second

↓

Human Decision Last

