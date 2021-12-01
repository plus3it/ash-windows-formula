{%- from tpldir ~ '/map.jinja' import cis with context %}

Apply CIS 1.3.0 Local Group Policy Objects:
  ash_lgpo.present:
    - policies: {{ cis.cis_policies | yaml }}

Apply CIS 1.3.0 Audit policy:
  file.managed:
    - name: {{ cis.win_audit_file_name }}
    - source: {{ cis.audit_file_source }}
    - makedirs: True
    - require:
      - ash_lgpo: Apply CIS 1.3.0 Local Group Policy Objects
  cmd.run:
    - name: auditpol /clear /y && auditpol /restore /file:"{{ cis.win_audit_file_name }}"
    - require:
      - file: Apply CIS 1.3.0 Audit policy
