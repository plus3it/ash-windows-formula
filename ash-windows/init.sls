#!py

def run():
    config = {}
    config['Print Available ash-windows Baselines'] = {
        'test.show_notification' : [ {
            'text': 'Available ash-windows baselines include:\n'
                    '    ash-windows.sct\n'
                    '    ash-windows.stig\n'
                    '    ash-windows.delta\n'
                    '       -and-\n'
                    '    ash-windows.custom\n'
                    'See https://github.com/plus3it/ash-windows-formula for more details.'
        } ]
    }
    return config
