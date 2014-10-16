import fnmatch


def filter_by(lookup_table, match):
    for key in lookup_table.keys():
        if fnmatch.fnmatch(match, key):
            return lookup_table[key]
    return None
