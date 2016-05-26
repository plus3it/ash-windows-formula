{% from tpldir ~ '/map.jinja' import iavm with context %}

include:
  - ash-windows.tools

Create IAVM Log Directory:
  file.directory:
    - name: {{ iavm.logdir }}
    - makedirs: True

Apply IAVM Local Group Policy Objects:
  lgpo.present:
    - policies: {{ iavm.iavm_policies }}
    - logfile: {{ iavm.logdir }}\iavm-policies.log
    - errorfile: {{ iavm.logdir }}\iavm-policies.err
    - require:
      - file: Create IAVM Log Directory
