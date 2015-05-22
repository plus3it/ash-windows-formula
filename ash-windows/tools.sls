{% from "ash-windows/map.jinja" import ash with context %}

ApplyLGPODelta:
  file.managed:
    - name: {{ ash.apply_lgpo_filename }}
    - source: {{ ash.apply_lgpo_source }}
    - source_hash: {{ ash.apply_lgpo_source_hash }}
    - makedirs: True
