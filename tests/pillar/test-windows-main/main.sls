#Settings configured in pillar will override default settings specified in map.jinja
ash-windows:
  lookup: {}
    # logdir: C:\Ash\logs
    # role: MemberServer
    # custom_policies:
    #  - policy_type: regpol
    #    key: HKLM\Software\Salt\Foo
    #    value: 1
    #    vtype: REG_DWORD
    #  - policy_type: regpol
    #    key: HKLM\Software\Salt\Bar
    #    value: testing
    #    vtype: REG_SZ
    #  - policy_type: secedit
    #    name: NewAdministratorName
    #    value: superadmin
