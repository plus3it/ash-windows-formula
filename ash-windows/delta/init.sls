{% from tpldir ~ '/map.jinja' import delta with context %}

include:
  - ash-windows.tools

Create Delta Log Directory:
  file.directory:
    - name: {{ delta.logdir }}
    - makedirs: True

Apply Delta Local Group Policy Objects:
  lgpo.present:
    - policies: {{ delta.delta_policies | yaml }}
    - logfile: {{ delta.logdir }}\delta-policies.log
    - errorfile: {{ delta.logdir }}\delta-policies.err
    - require:
      - file: Create Delta Log Directory
