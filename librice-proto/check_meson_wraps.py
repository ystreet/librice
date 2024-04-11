#!/usr/bin/env python3

import os, subprocess
import pathlib, configparser

def parse_cargo_tree_line(line):
    components = line.split()
    # FIXME doesn't support more than single digit depths
    depth = int(components[0][0])
    name = components[0][1:]
    version = components[1][1:]
    features = []
    if len(components) > 2 and components[2][0] != '(':
        features = components[2].split(',')
    print(depth, name, version, features)
    return (name, version, features)

CRATES_URL_TEMPL = "https://crates.io/api/v1/crates/{name}/{version}/download"

def main():
    crates_features = subprocess.run(["cargo", "tree", "-f", "{p} {f}", "-p", "librice-proto", "-e", "normal", "--prefix", "depth"], capture_output=True, check=True, text=True).stdout
    crates = {}
    for line in crates_features.splitlines():
        (name, version, features) = parse_cargo_tree_line(line)
        if name != 'librice-proto':
            if name in crates:
                assert(crates[name] == (version, features))
                continue
            crates[name] = (version, features)
            wrap_file = pathlib.Path('..') / 'librice-proto' / 'subprojects' / (name + '.wrap')
            with wrap_file.open(mode="r") as f:
                wrap = configparser.ConfigParser()
                wrap.read_file(f)
                name_version = name + '-' + version
                assert(wrap["wrap-file"]["directory"] == name_version)
                assert(wrap["wrap-file"]["source_url"] == CRATES_URL_TEMPL.format(name=name, version=version))
                assert(wrap["wrap-file"]["source_filename"] == name_version + '.tar.gz')
                assert(wrap["provide"]["dependency_names"] == name + '-rs')

if __name__ == "__main__":
    main()
