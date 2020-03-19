{% from tpldir ~ '/map.jinja' import iavm with context %}

Apply IAVM Local Group Policy Objects:
  ash_lgpo.present:
    - policies: {{ iavm.iavm_policies | yaml }}
