{%- from tpldir ~ '/map.jinja' import mss with context %}

Manage MSS ADMX:
  file.managed:
    - name: {{ mss.admx_name }}
    - source: {{ mss.admx_source }}

Manage MSS ADML:
  file.managed:
    - name: {{ mss.adml_name }}
    - source: {{ mss.adml_source }}
