Windows login banners are implmented via registry-keys. Specifically the keys:

* `MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\LegalNoticeCaption`: The line presented before the banner-text. The default value implemented through the ash-windows-formula project is, "US Department of Defense Warning Statement"
* `MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\LegalNoticeText`. This is the (multi-) paragraph login-banner text. See the project-files:
    * [ash-windows/stig/Windows_11/stig.yml](ash-windows/stig/Windows_11/stig.yml)
    * [ash-windows/stig/Windows_2022Server_MS/stig.yml](ash-windows/stig/Windows_2022Server_MS/stig.yml)[^1]
    * [ash-windows/stig/Windows_2022Server_DC/stig.yml](ash-windows/stig/Windows_2022Server_DC/stig.yml)[^1]

    For illustrative content.

While the project-readme's [configuration](https://github.com/plus3it/ash-windows-formula#configuration) section provides general guidance for setting custom registry entries, that guidance may not be adequately illustrative of how it applies to login-banners. Further, the content in the previously-noted YAML files may not work correctly under current versions of Windows. The following is meant to be a more-illustrative summary of how the pillar-content should be constructed.

```yaml
ash-windows:
  lookup:
    custom_policies:
      - name: CustomBannerTitle
        policy_type: regpol
        key: MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\LegalNoticeCaption
        value: |-
          <CAPTION_TEXT>
        vtype: REG_SZ
      - name: CustomBannerText
        policy_type: regpol
        key: MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\LegalNoticeText
        value: |-
          <BANNER_TEXT>
        vtype: REG_SZ
```

* `vtype`: While the previously-noted files use a `vtype` value of `SZ` for the `MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\LegalNoticeCaption` registry-key and a `vtype` value of `MULTISZ` for the `MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\LegalNoticeText`, it is currently recommended to use a `vtype` value of `REG_SZ` for both.
* `value`: While the `value` parameter _can_ be specified a simple string-value, this can prove problematic depending on the text that needs to be passed. In particular, if the text needs to contain special characters (the `*` character is known to cause problems), the rendering of the data can break when using simple key-value specification-style. It is better to use a content-block specification-style.

To illustrate with text that can trigger problems with simple, key-value specification-style, the following shows using content-block specification-style:

```yaml
ash-windows:
  lookup:
    custom_policies:
      - name: CustomBannerTitle
        policy_type: regpol
        key: MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\LegalNoticeCaption
        value: |-
          **WARNING**WARNING**WARNING**WARNING**
        vtype: REG_SZ
      - name: CustomBannerText
        policy_type: regpol
        key: MACHINE\Software\Microsoft\Windows\CurrentVersion\Policies\System\LegalNoticeText
        value: |-
          You are accessing a U.S. Government information system, which includes:

          1) this computer,
          2) this computer network,
          3) all Government-furnished computers connected to this network, and
          4) all Government-furnished devices and storage media attached to this network or to a computer on this network.

          You understand and consent to the following:

          - You may access this information system for authorized use only;
          - Unauthorized use of the system is prohibited and subject to criminal and civil penalties;
          - You have no reasonable expectation of privacy regarding any communication or data transiting or stored on this information system at any time and for any lawful Government purpose, the Government may monitor, intercept, audit, and search and seize any communication or data transiting or stored on this information system; and any communications or data transiting or stored on this information system may be disclosed or used for any lawful Government purpose.

          This information system may contain Controlled Unclassified Information (CUI) that is subject to safeguarding or dissemination controls in accordance with law, regulation, or Government-wide policy. Accessing and using this system indicates your understanding of this warning
        vtype: REG_SZ
```

The above custom content will result in a login screen that looks like:
<img src="/docs/images/ash-windows-CustomBanner-USGciv.png">

[^1]:The `.../Windows_2022Server_*/stig.yml` files produce a login banner as shown <a href="docs/images/ash-windows-DefaultBanner-DoD.png">here</a>.
