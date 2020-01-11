#!/usr/bin/env python
# flake8: noqa
import chardet
import sys
import yaml


REG_CODE_MAP = {
    '1': 'SZ',
    '2': 'EXSZ',
    '3': 'BINARY',
    '4': 'DWORD',
    '7': 'MULTISZ'
}
REG_MODES = ('DELETE', 'DELETEALLVALUES', 'CREATEKEY')
REG_HIVES = ('USER', 'COMPUTER')
REG_TYPES = ('DWORD', 'SZ', 'EXSZ')


def _convert_regpol(src):
    policies = []
    policy_type = 'regpol'
    ignore_lines = (' ', ';')
    index = 0
    while index < len(src):
        policy = {}
        if src[index] == '':
            index += 1
            continue
        if src[index].startswith(ignore_lines):
            index += 1
            continue
        if src[index].upper() in REG_HIVES:
            # `index` is the hive
            # `index+1` is the key path
            # `index+2` is the registry "value" object
            # `index+3` is the action, or vtype:data
            try:
                policy['policy_type'] = policy_type
                policy['key'] = '\\'.join([
                    src[index],
                    src[index+1],
                    src[index+2]])
                if src[index+3] in REG_MODES:
                    policy['action'] = src[index+3]
                else:
                    policy['vtype'] = src[index+3].split(':')[0]
                    policy['value'] = src[index+3].split(':')[1]
                policies.append(policy)
            except IndexError as exc:
                raise SystemError('Whoops. Malformed policy in src_file? '
                                  'Error at lines #{0}-{1}. Exception: {2}'
                                  .format(index+1, index+4), exc)
            index += 4
        else:
            raise SystemError('Policy must begin with a "Configuration" line '
                              'of "User" or "Computer". Received "{0}" at '
                              'line #{1}'
                              .format(src[index], index+1))
    return policies


def _convert_secedit(src):
    policies = []
    ignore_lines = ('[', ';', '"', 'UNICODE', 'SIGNATURE', 'REVISION')
    for index, line in enumerate(src):
        policy = {}
        if line == '':
            continue
        if line.upper().startswith(ignore_lines):
            continue
        if '\\' in line and line.startswith('MACHINE'):
            # Registry setting
            policy_type = 'regpol'
            policy['policy_type'] = policy_type
            policy['key'] = line.split('=')[0].strip()
            policy['vtype'] = REG_CODE_MAP[line.split('=')[1].split(',')[0].strip()]
            policy['value'] = ''.join(line.split('=')[1].split(',')[1:]).strip().strip('"')
            if not policy['vtype'].upper() in REG_TYPES:
                print('Line #{0}, registry type not supported by apply_lgpo_delta: {1}'
                      .format(index+1, line))
                continue
            policies.append(policy)
        else:
            # Secedit setting
            policy_type = 'secedit'
            policy['policy_type'] = policy_type
            policy['name'] = line.split('=')[0].strip()
            policy['value'] = line.split('=')[1].strip()
            policies.append(policy)
    return policies


def main(src_file, dst_file, **kwargs):
    policies = []

    with open(src_file, mode='rb') as f:
        raw = f.read()
    
    encoding = chardet.detect(raw)['encoding']
    src = raw.decode(encoding).splitlines()

    if '[Unicode]' in src:
        policies = _convert_secedit(src)
    else:
        policies = _convert_regpol(src)

    with open(dst_file, mode='w') as dh_:
        yaml.safe_dump(policies, dh_, default_flow_style=False)


if __name__ == "__main__":
    kwargs = dict(x.split('=', 1) for x in sys.argv[1:])
    main(**kwargs)
