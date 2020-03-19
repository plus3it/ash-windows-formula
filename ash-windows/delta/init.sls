{% from tpldir ~ '/map.jinja' import delta with context %}

Apply Delta Local Group Policy Objects:
  ash_lgpo.present:
    - policies: {{ delta.delta_policies | yaml }}
