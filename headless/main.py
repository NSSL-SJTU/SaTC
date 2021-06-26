#!/usr/bin/env python3
import argparse
import os
import shutil
import subprocess

parser = argparse.ArgumentParser(description="wrapper for headless ghidra scripts")
parser.add_argument('-g', '--ghidra-path', type=os.path.abspath, help='path to ghidra base, like ~/tools/ghidra_9.0_PUBLIC', required=True)
parser.add_argument('-b', '--binary', type=os.path.abspath, help='the binary executable', required=True)
parser.add_argument('-s', '--script', type=os.path.abspath, help='the script', required=True)
parser.add_argument('-d', '--project-dir', type=os.path.abspath, help='project directory, default for ./projects', default='projects')
parser.add_argument('-i', '--infile', type=os.path.abspath, help='input file for the script', required=True)
parser.add_argument('-o', '--outfile', type=os.path.abspath, help='out file for the script, default for stdout')
# parser.add_argument('--project-name', help='project name')
parser.add_argument('-r', '--reset', help='reset the project before analysis and script', action='store_true')
args = parser.parse_args()

if not os.path.isdir(args.project_dir):
    if os.path.exists(args.project_dir):
        os.unlink(args.project_dir)
    os.mkdir(args.project_dir)

ghidra = os.path.join(args.ghidra_path, 'support/analyzeHeadless')
project_name = args.binary.replace('/', '-')
rep_dir = os.path.join(args.project_dir, project_name + '.rep')
if args.reset:
    shutil.rmtree(rep_dir, True)

ghidra_args = [
    ghidra, args.project_dir, project_name,
    '-postscript', args.script, args.infile, args.outfile or '',
    '-scriptPath', os.path.dirname(args.script)
]
if os.path.exists(rep_dir):
    ghidra_args += ['-process', os.path.basename(args.binary)]
else:
    ghidra_args += ['-import', args.binary]

p = subprocess.Popen(ghidra_args)
exit(p.wait())
