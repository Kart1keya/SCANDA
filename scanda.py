import os
import re
import sys
import yara
import json
import shutil
import pdb
import hashlib
import pefile
import r2pipe
from json2html import *
from argparse import ArgumentParser
from collections import namedtuple
from graphityUtils import gimmeDatApiName, sha1hash, getAllAttributes, is_ascii, Hvalue, check_pe_header
from graphityOps import patternScan
import graphityFunc
from graphity import get_behaviors

from rich import parse_rich_header, err2str, pprint_header_ex

RE_EMBEDDED_FILE = r'0x([A-F0-9]+)\s+([0-9]+)\s+([^,:\(\.]+)'


class YaraScan():
    def __init__(self):
        self.yara_sig_matched = {}
        self.yara_idsig_matched = {}

    def yara_callback_desc(self, data):
        # print data
        if data['matches']:
            tag = ""
            if len(data['tags']) > 0:
                tag = data['tags'][0]
            if tag not in self.yara_sig_matched.keys():
                self.yara_sig_matched[tag] = {}
            if data['rule'] not in self.yara_sig_matched[tag].keys():
                self.yara_sig_matched[tag][data['rule']] = {}
                if 'description' in data['meta']:
                    self.yara_sig_matched[tag][data['rule']]['description'] = data['meta']['description']
                self.yara_sig_matched[tag][data['rule']]['indicators_matched'] = []
            for string in data['strings']:
                try:
                    if string[2].decode('windows-1252') not in self.yara_sig_matched[tag][data['rule']]['indicators_matched']:
                            self.yara_sig_matched[tag][data['rule']]['indicators_matched'].append(string[2].decode('windows-1252'))
                except:
                    continue
        yara.CALLBACK_CONTINUE

    def yara_callback(self, data):
        if data['matches']:
            tag = ""
            if len(data['tags']) > 0:
                tag = data['tags'][0]
            if tag not in self.yara_idsig_matched.keys():
                self.yara_idsig_matched[tag] = []
            if data['rule'] not in self.yara_idsig_matched[tag]:
                self.yara_idsig_matched[tag].append(data['rule'])
        yara.CALLBACK_CONTINUE


def disasm_file_ex(in_file, out_file):
    print("filepath:" + in_file)
    # change python working directory to radare2
    os.chdir("C:\\ProgramData\\radare2")
    R2PY = r2pipe.open(in_file)

    R2PY.cmd("e asm.lines = false")
    R2PY.cmd("e anal.autoname= false")
    R2PY.cmd("e anal.jmptbl = true")
    R2PY.cmd("e anal.hasnext = true")
    R2PY.cmd("e anal.bb.maxsize = 1M")

    # R2PY.cmd("e src.null = true")
    #R2PY.cmd("aaa")

    with open(out_file, "w") as out:
        # get embedded file information
        #file_info = R2PY.cmd("/m")
        #for line in file_info.split("\n"):
        #    line = line.lstrip().rstrip()
        #    if line:
        #        out.write(line + "\n")

        # file information
        pe_fileinfo = {}

        info_list = []
        file_info = R2PY.cmd("iI")
        for line in file_info.split("\n"):
            line = line.lstrip().rstrip()
            if line:
                info_list.append(line)
        pe_fileinfo["Header Information"] = info_list

        info_list = []
        rich = parse_rich_header(in_file)
        if rich['err'] < 0:
            pe_fileinfo["Rich Header"] = err2str(rich['err'])
        else:
            output = pprint_header_ex(rich)

            for line in output.split("\n"):
                line = line.lstrip().rstrip()
                if line:
                    info_list.append(line)
            pe_fileinfo["Rich Header"] = info_list

        # the section table from radare2
        info_list = []
        sections = R2PY.cmd("iS entropy,sha1")
        for line in sections.split("\n"):
            line = line.lstrip().rstrip()
            if line:
                info_list.append(line)
        pe_fileinfo["Section Information"] = info_list

        json_report = json.dumps(pe_fileinfo, sort_keys=True, indent=4)
        out.write(json_report.encode("utf-8"))
        R2PY.quit()
        return pe_fileinfo

        # get import information
        file_info = R2PY.cmd("ii")
        out.write("\n\n")
        for line in file_info.split("\n"):
            line = line.lstrip().rstrip()
            if line:
                out.write(line + "\n")

        # get export information
        file_info = R2PY.cmd("is")
        out.write("\n\n")
        for line in file_info.split("\n"):
            line = line.lstrip().rstrip()
            if line:
                out.write(line + "\n")

        # get strings information
        file_info = R2PY.cmd("izz")
        for line in file_info.split("\n"):
            line = line.lstrip().rstrip()
            if line:
                out.write(line + "\n")

        R2PY.quit()
#        # dump disasam of the file
#        codeSections = []
#
#       # regular expression to pick out the executable section(s)
#        execSection = re.compile("-..x")
#        instr_format = re.compile("(0x[0-9a-f]+)\s+([0-9a-f\.]+)\s+([^;]+)", re.IGNORECASE)
#
#        for line in sections.splitlines():
#            items = line.split()
#            if len(items) >= 9 and re.search(execSection, items[5]):
#                offset = int(items[1], 16)
#                psize = int(items[2])
#                start = int(items[3], 16)
#                end = start + int(items[4])
#                name = items[-1]
#
#                codeSections.append([start, end, psize, name])
#
#        for section in codeSections:
#            addr = section[0]#
#            while addr < section[1]:
#                cmd = "s." + str(hex(addr))
#                R2PY.cmd(cmd)
#                current_instruction = R2PY.cmdj("pdj 1")[0]
#                if 'bytes' in current_instruction and 'disasm' in current_instruction:
#                    out.write("{0:8}  {1:30}  {2:}\n".format(hex(addr), current_instruction['bytes'], current_instruction['disasm']))
#                    #out.write(str(current_instruction) + "\n")
#                if 'size' in current_instruction:
#                    addr = addr + current_instruction['size']
#                else:
#                    addr = addr + 1


def process_file(yara_scan, yara_rules, yara_id_rules, input_file, output_file):
    with open(input_file, 'rb') as f:
        file_data = f.read()

        json_data = {}
        yara_id_rules.match(data=file_data, callback=yara_scan.yara_callback, which_callbacks=yara.CALLBACK_MATCHES)
        json_data['File Type Information'] = yara_scan.yara_idsig_matched

        yara_rules.match(data=file_data, callback=yara_scan.yara_callback_desc, which_callbacks=yara.CALLBACK_MATCHES)
        json_data['Yara Matched'] = yara_scan.yara_sig_matched

        with open(output_file, 'w') as fw:
            json_report = json.dumps(json_data, sort_keys=True, indent=4)
            fw.write(json_report.encode('utf-8'))
        return json_data


def process_dir(src_dir, dst_dir):
    print("Processing: " + src_dir + " ...")

    yara_scan = YaraScan()
    yara_rules = yara.compile('./yara_sigs/index.yar')
    yara_idrules = yara.compile('./yara_sigs/index_id.yar')

    for root_dir, dirs, files in os.walk(src_dir):
        for filename in files:
            print(filename)
            file_info = {}
            src_file = os.path.join(root_dir, filename)
            sha1 = ""
            sha2 = ""
            md5 = ""
            file_size = 0
            try:
                pe = pefile.PE(src_file)

                with open(src_file, 'rb') as f:
                    contents = f.read()
                    file_size = len(contents)
                    sha1 = hashlib.sha1(contents).hexdigest()
                    sha2 = hashlib.sha256(contents).hexdigest()
                    # md5 accepts only chunks of 128*N bytes
                    md5_obj = hashlib.md5()
                    for i in range(0, len(contents), 8192):
                        md5_obj.update(contents[i:i + 8192])
                    md5 = md5_obj.hexdigest()
            except Exception as e:
                print("Skipping: " + src_file)
                print("Error: " + str(e))
                return

            file_info = {}
            basic_info = {}

            basic_info['md5'] = md5
            basic_info['sha1'] = sha1
            basic_info['sha2'] = sha2
            basic_info['file size'] = file_size

            ret_info = {}
            ret_info["Basic Information"] = basic_info
            file_info.update(ret_info)

            dst_file = os.path.join(dst_dir, filename) + ".static.json"
            ret_info = disasm_file_ex(src_file, dst_file)
            file_info.update(ret_info)

            dst_file = os.path.join(dst_dir, filename) + ".yara.json"
            # run yara rules on file
            ret_info = process_file(yara_scan, yara_rules, yara_idrules, src_file, dst_file)
            file_info.update(ret_info)

            dst_file = os.path.join(dst_dir, filename) + ".behav.json"
            ret_info = get_behaviors(src_file, dst_file)
            file_info.update(ret_info)

            html = json2html.convert(json=file_info)
            html = html.replace("<table border=\"1\">",
                                "<table border=\"2\" bordercolor=\"blue\" class=\"table table-condensed\">", 100)

            dst_file =  os.path.join(dst_dir, filename) + ".html"
            with open(dst_file, "w") as out:
                out.write(
                    "<link rel=\"stylesheet\" href=\"https://maxcdn.bootstrapcdn.com/bootstrap/3.3.7/css/bootstrap.min.css\">")
                #html = html.encode('ascii', 'ignore').decode('ascii')
                out.write(html)




def html_report(dir_path, dst_file):
    json_data = {}
    for root_dir, dirs, files in os.walk(dir_path):
        for filename in files:
            if filename.find(".json"):
                src_file = os.path.join(root_dir, filename)
                print(src_file)
                with open(src_file) as f:
                    info = json.load(f)
                    json_data.update(info)

    html = json2html.convert(json=json_data)
    html = html.replace("<table border=\"1\">",
                        "<table border=\"2\" bordercolor=\"blue\" class=\"table table-condensed\">", 100)

    with open(dst_file, "w") as out:
        out.write(
            "<link rel=\"stylesheet\" href=\"https://maxcdn.bootstrapcdn.com/bootstrap/3.3.7/css/bootstrap.min.css\">")
        #html = html.encode('ascii', 'ignore').decode('ascii')
        out.write(html)


if __name__ == '__main__':
    # parse command line arguments
    usage = "usage: %prog [options] arg1 arg2"

    parser = ArgumentParser()
    parser.add_argument("-d", "--deactivatecache", action="store_true",
                        help="Deactivate caching of graphs, for debugging of graph generation")
    parser.add_argument("-b", "--behavior", action="store_true", help="Scan for behaviors listed in graphityFunc.py")

    parser.add_argument('-i', '--input', action="store", dest="input_dir", help="Input directory name")
    parser.add_argument('-o', '--output', action="store", dest="output_dir", help="Output directory name")

    args = parser.parse_args()

    if args.input_dir is not None and os.path.isdir(args.input_dir) and args.output_dir is not None \
            and os.path.isdir(args.output_dir):
        process_dir(args.input_dir, args.output_dir)
    else:
        parser.print_help()