#!/usr/bin/env python
# 
# Name: gen_ossec_rootkit.py
#
# Purpose: generates an osquery compatible querypack to detect presence of 
#          linux rootkit files from the database of such files in ossec.
#         
# Invocation: ./gen_ossec_rootkit_qpack.py
#          Assumes that ossec rootkit db file, rootkit_files.txt, is colocated
#          in the current directory.
#          the rootkit_files.txt is found in src/rootcheck/db/ directory
#          in the ossec-hids repo on github 
#          (https://github.com/ossec/ossec-hids)
# 
# Output: Generates ossec-rootkit.conf file in the current directory. 
#
# Warning: Overwrites ossec-rootkit.conf file if one exists
# 
import json

def debug_print(x):
    print x

def split_line_into_file_and_name(raw_line):
    if raw_line[0] == '#':
        return -1
    return raw_line.find("!")

def normalize_file_name(raw_file_name):
    rootkit_file = raw_file_name.strip()
    if rootkit_file[0] == '*':
        debug_print("Ignoring file starting with wildcard: " + rootkit_file)
        return None
    if rootkit_file[0] != '/':
        rootkit_file = "/" + rootkit_file
    return rootkit_file

def normalize_rootkit_name(raw_name):
    rootkit_name = raw_name[0:raw_name.find(":")].strip()
    rootkit_name = rootkit_name.replace(" ", "_")
    rootkit_name = rootkit_name.replace("-", "_")
    rootkit_name = rootkit_name.lower()
    return rootkit_name

def generate_rootkit_queries(rootkit_files):
    rootkit_queries = {}
    for rootkit in rootkit_files:
        query = "select * from file where path in ("
        for file in rootkit_files[rootkit]:
            query = query + "'" + file + "', "
        query = query[0:-2]    # get rid of ", " after the last file name
        query = query + ");"
        rootkit_queries[rootkit] = {"query": query, 
                                    "interval" : "3600", 
                                    "platform" : "linux",
                                    "description" : rootkit, 
                                    "value" : "Artifacts used by this malware"}
    return rootkit_queries
            
def main():
    rootkit_files = {}
    with open('rootkit_files.txt', 'r') as fin:
        for line in fin:
            separator = split_line_into_file_and_name(line)
            if separator == -1:
                continue
            rootkit_file = normalize_file_name(line[0:separator])
            if rootkit_file is None:
                continue
            rootkit_name = normalize_rootkit_name(line[separator+1:])
            if rootkit_name in rootkit_files:
                rootkit_files[ rootkit_name ].append(rootkit_file)
            else:
                rootkit_files[ rootkit_name ] =  [rootkit_file]
    qpack = {"platform" : "linux",
             "version" : "1.4.5",
             "queries" : generate_rootkit_queries(rootkit_files)
            }
    fout = open('ossec-rootkit.conf', 'w')
    json.dump(qpack, fout, indent=2)
    fout.close()

if __name__=="__main__":
    main()


