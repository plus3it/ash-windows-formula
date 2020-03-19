{%- from tpldir ~ '/map.jinja' import custom,local_policies with context %}

Apply Custom Local Group Policy Objects:
  ash_lgpo.present:
    - policies: {{ custom.custom_policies | yaml }}
