Over time, as old DoD Root CAs expire and new ones are released, it will be necessary to update [dodcerts.sls](https://github.com/plus3it/ash-windows-formula/blob/master/ash-windows/stig/dodcerts.sls) to incorporate the new DoD CA guidance.

Process to update `dodcerts.sls`:
- Obtain new Windows SCAP content from [DoD Cyber Exchange ](https://public.cyber.mil/stigs/scap/) and incorporate the new content in the `disa` folder of the [scap-formula](https://github.com/plus3it/scap-formula/tree/master/scap/content/guides/disa) project

- Generate a SCAP scan and determine if the report indicates any DoD CA-related findings

- If DoD CA findings exist, there will be a `Fix Text` section providing information on how to resolve the finding.  For Windows, it involves downloading the latest version of the InstallRoot Windows installer.  InstallRoot can be obtained from the public [DoD Cyber Exchange PKI/PKE](https://public.cyber.mil/pki-pke/tools-configuration-files/) website.

- Download the desired Windows installer and apply it to the system

- Re-run the SCAP scan to generate a new report.  The new report should indicate the DoD CA findings have been resolved.  For each DoD CA finding resolved, there will be a `Test` section indicating the results of the check.  The result should indicate `true`.  The `Collected Item/State Result` field should contain the registry information that can now be used to update `dodcert.sls`


