{% from "ash-windows/map.jinja" import ash with context %}

{% if salt['cmd.run']('$($PSVersionTable.CLRVersion.Major) -ge 4', shell='powershell') == 'True' %}
#Install and Apply EMET Settings
Emet:
  pkg:
    - installed
    - version: {{ ash.emet_version }}

EMET.admx:
  file:
    - managed
    - name: {{ ash.emet_admx_name }}
    - source: {{ ash.emet_admx_source }}
    - require:
      - pkg: Emet

EMET.adml:
  file:
    - managed
    - name: {{ ash.emet_adml_name }}
    - source: {{ ash.emet_adml_source }}
    - require:
      - pkg: Emet
{% endif %}
