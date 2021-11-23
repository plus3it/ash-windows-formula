{%- from tpldir ~ '/map.jinja' import cis with context %}

Apply CIS 1.1.0 Local Group Policy Objects:
  ash_lgpo.present:
    - policies: {{ cis.cis_policies | yaml }}
