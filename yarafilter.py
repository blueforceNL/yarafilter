#!/usr/bin/python3

import sys
import getopt
import time
import os
import io
import shutil
from plyara import Plyara
from pathlib import Path


class YaraFilter(object):
    def __init__(self):
        self.base_dir = None
        self.output_dir = "./output"
        self.exclude_dir = None
        self.verbose = False
        self.parser = Plyara()
        self.hashes = set()
        self.hashdb = {}
        self.rule_names = set()
        self.ruledb = {}
        self.description = None
        self.author = None
        self.exclude_imports = []

    def start(self, argv):
        try:
            opts, args = getopt.getopt(argv, "hp:va:d:i:e:")
        except getopt.GetoptError:
            self.print_usage_info()
            sys.exit(2)
        for opt, arg in opts:
            if opt == '-h':
                self.print_usage_info()
                sys.exit()
            if opt in "-v":
                self.verbose = True;
            if opt in "-p":
                self.base_dir = arg
            if opt in "-e":
                self.exclude_dir = arg
            if opt in "-i":
                self.exclude_imports = arg.split(",")
            if opt in "-a":
                self.author = arg
            if opt in "-d":
                self.description = arg

        start_time = time.time()
        if not self.base_dir:
            self.print_usage_info()
            sys.exit()
        else:
            self.prepare_output_directory()
            if self.exclude_dir:
                self.exclude_yar_files(self.exclude_dir)
            # this is the main job
            self.index_yar_files(self.base_dir)

        stop_time = time.time()
        if self.verbose:
            print("\n")
            print("Processed and saved " + str(len(self.rule_names)) + " rules in "
                  + str(round(stop_time - start_time)) + " seconds.")
            print("The resulting set of yar files is in ./output/")

    def prepare_output_directory(self):
        if os.path.exists(self.output_dir):
            shutil.rmtree(self.output_dir)
        os.makedirs(self.output_dir)

    def index_yar_files(self, path):
        # We want to process yar files in alphabetical order. A file named "000_common_rules.yar" will likely contain
        # rules to should be processed before others and is named that way for a reason.
        entries = sorted(os.scandir(path), key=lambda e: e.name)
        for e in entries:
            if e.is_dir():
                # recursively dive into subdirectories first
                self.index_yar_files(e.path)
            elif e.name.endswith('.yar'):
                self.process_yar_file(e.path)

    def exclude_yar_files(self, path):
        for e in os.scandir(path):
            if e.is_dir():
                # recursively dive into subdirectories first
                self.exclude_yar_files(e.path)
            elif e.name.endswith('.yar'):
                self.exclude_yar_file(e.path)
        if self.verbose:
            print("Loaded " + str(len(self.hashes)) + " rules for exclusion from directory " + path)

    def read_yar_file(self, filename):
        if self.verbose:
            print("Reading " + filename)
        try:
            # Some files contain unicode but are opened as iso-8859-1 by Python.
            # This fix ("rb" + decode("utf-8")) prevents some of the UnicodeDecode errors
            with io.open(filename, 'rb') as f:
                data = f.read()
                # return self.parser.parse_string(data.decode("utf-8", errors='ignore'))
                return self.parser.parse_string(data.decode("utf-8"))
        except Exception as e:
            if self.verbose:
                print(e)
            print("Warning: " + filename + " has invalid unicode characters. This might result in loss of information."
                                           " You should verify the rules in the output file with the original.")
            try:
                return self.parser.parse_string(data.decode("utf-8", errors='ignore'))
            except Exception as e:
                if self.verbose:
                    print(e)
                print("Warning: " + filename + " could not be parsed. It will just be copied to the output. This"
                                               " means no rules from this file will be checked for duplicates and you"
                                               " might see duplicate identifier errors in your YARA tool. If so, rename"
                                               " those rules manually.")
                self.check_directory_exists(filename)
                shutil.copyfile(filename, self.output_dir + "/" + filename)
                return []

    def exclude_yar_file(self, filename):
        rules = self.read_yar_file(filename)
        for r in rules:
            rule_hash = Plyara().generate_logic_hash(r)
            self.hashes.add(rule_hash)

    def process_yar_file(self, filename):

        rules = self.read_yar_file(filename)
        if not rules:
            return

        # empty the ruleset and imports (we re-use the parser)
        self.parser.rules = []
        self.parser.imports = set()

        rebuild_yar_file = False
        keep_this_rule = False
        output = ''
        for r in rules:
            # check if we already have a rule that is functionally equivalent. If so, drop the duplicate.
            duplicate = self.check_duplicate_functionality(r, filename)
            if duplicate:
                rebuild_yar_file = True
                keep_this_rule = False

            elif self.pass_filter_check(r):
                # check for duplicate rule names. Loki will complain about these.
                rule_name = self.check_duplicate_identifier(r, filename)
                if rule_name:
                    r["rule_name"] = rule_name
                rebuild_yar_file = True
                keep_this_rule = True

            if keep_this_rule:
                output += Plyara().rebuild_yara_rule(r)

        if not rebuild_yar_file and rules:
            # copy the original file to output, but only if it contains rules (no index files with includes)
            self.check_directory_exists(filename)
            shutil.copyfile(filename, self.output_dir + "/" + filename)
        elif output:
            # store the filtered file, if there is anything left after filtering
            self.check_directory_exists(filename)
            with open(self.output_dir + "/" + filename, "w") as text_file:
                text_file.write(output)

    def pass_filter_check(self, r):
        if self.author or self.description:
            metadata = r.get("metadata")
            m = dict()
            [m.update(i) for i in metadata]

        if self.author and self.author.lower() not in m.get("author", "").lower():
            if self.verbose:
                print("Excluding rule with author " + r.get("author", ""))
            return False

        if self.description and self.description.lower() not in m.get("description").lower():
            if self.verbose:
                print("Excluding rule with description " + r.get("description", ""))
            return False

        if self.exclude_imports and any(i in self.exclude_imports for i in r.get("imports", [])):
            if self.verbose:
                print("Excluding rule with imports " + ",".join(r.get("imports", [])))
            return False

        return True

    def check_directory_exists(self, filename):
        directory = os.path.dirname(filename)
        Path(self.output_dir + "/" + directory).mkdir(parents=True, exist_ok=True)

    def check_duplicate_identifier(self, r, filename):
        rule_name = r.get("rule_name", "")

        if rule_name in self.rule_names:
            fixed_rule_name = self.fix_rule_name(rule_name, 1)
            if self.verbose:
                dup = self.ruledb[rule_name]
                print("Detected and renamed duplicate rule identifier:")
                print("\t" + r.get("rule_name", "") + " in " + filename)
                print("\t" + dup['name'] + " in " + dup['filename'] + " (renamed to " + fixed_rule_name + ")")
            self.rule_names.add(fixed_rule_name)
            self.ruledb[fixed_rule_name] = {"name": fixed_rule_name, "filename": filename}
            return fixed_rule_name
        else:
            self.rule_names.add(rule_name)
            self.ruledb[rule_name] = {"name": r.get("rule_name", ""), "filename": filename}
            return False

    def fix_rule_name(self, rule_name, i):
        new_rule_name = rule_name + "_" + str(i)
        if new_rule_name in self.rule_names:
            return self.fix_rule_name(rule_name, i+1)
        else:
            return new_rule_name

    def check_duplicate_functionality(self, r, filename):
        rule_hash = Plyara().generate_logic_hash(r)
        if rule_hash in self.hashes:
            if self.verbose:
                dup = self.hashdb[rule_hash]
                print("Detected and removed functionally duplicate rule: ")
                print("\t" + r.get("rule_name", "") + " in " + filename)
                print("\t" + dup['name'] + " in " + dup['filename'])
            return True
        else:
            self.hashes.add(rule_hash)
            self.hashdb[rule_hash] = {"name": r.get("rule_name", ""), "filename": filename}
            return False

    def print_usage_info(self):
        print("\n")
        print("  Yarafilter is a tool to filter and deduplicate a collection of YARA rules (.yar files)")
        print("  The tool is developed and maintained by BlueForce, the security team of the Dutch National Police.")
        print("  Please email any bugs or requests to b.van.schaik@politie.nl")
        print("\n")
        print("  Command line options:")
        print('  -p  dir \t\tRecursively process yar files from this directory')
        print('  -e  dir \t\tExclude all rules from yar files in this directory')
        print('  -a  "name" \t\tRule author must contain name (case insensitive)')
        print('  -d  "keyword" \tRule description must contain keyword (case insensitive)')
        print('  -i  androguard,re \tExclude all rules depending on this list of imports')
        print('  -v  \t\t\tVerbose')
        print("\n")
        print("  The filtered ruleset will be saved in the directory ./output/")
        print("\n")


if __name__ == "__main__":
    yf = YaraFilter()
    yf.start(sys.argv[1:])
