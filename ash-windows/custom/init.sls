{%- from tpldir ~ '/map.jinja' import custom,local_policies with context %}

include:
  - ash-windows.tools

Create Custom Log Directory:
  file.directory:
    - name: {{ custom.logdir }}
    - makedirs: True

Apply Custom Local Group Policy Objects:
  lgpo.present:
    - policies: {{ custom.custom_policies }}
    - logfile: {{ custom.logdir }}\custom-policies.log
    - errorfile: {{ custom.logdir }}\custom-policies.err
    - require:
      - file: Create Custom Log Directory
