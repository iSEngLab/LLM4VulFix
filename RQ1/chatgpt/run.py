# -*- coding: utf-8 -*-
import re
import time

import openai
import csv
from itertools import islice
import os
from os import listdir

import pandas as pd
import tqdm
from tqdm.contrib import tzip

openai.api_key = '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'
base_prompt = '''There are several vulnerabilities in the following program. Please try to fix these vulnerabilities, and return the complete code in the form of a markdown code block\n\n'''
tag_prompt = '''There are several vulnerabilities in the following program. In this program, <S2SV_ModStart> represents where the vulnerability starts, and <S2SV_ModEnd> represents the place where the vulnerability ends. Please try to fix these vulnerabilities, and return the complete code without the above two special tags to me in the form of a markdown code block\n\n'''
multi_base_prompt = '''There are several vulnerabilities in the following program. Please try to fix these vulnerabilities, and return the complete code in the form of a markdown code block. Give me 5 possible fixed code\n\n'''
multi_tag_prompt = '''There are several vulnerabilities in the following program. In this program, <S2SV_ModStart> represents where the vulnerability starts, and <S2SV_ModEnd> represents the place where the vulnerability ends. Please try to fix these vulnerabilities, and return the complete code without the above two special tags to me in the form of a markdown code block. Give me 5 possible fixed code\n\n'''

def getdata(bug_path, fix_path):
    f1 = open(bug_path, 'r', encoding='utf-8')
    f2 = open(fix_path, 'r', encoding='utf-8')
    bugs = f1.readlines()
    fixes = f2.readlines()
    bugfix_pair = [[b, f] for b, f in zip(bugs, fixes)]
    bugfix_pair = sorted(bugfix_pair, key=lambda x: len(x[0]))
    source = []
    target = []
    for bf in bugfix_pair:
        source.append(bf[0])
        target.append(bf[1])
    df = pd.DataFrame()
    df['source'] = source
    df['target'] = target
    df.to_csv("cve_fixes_chat.csv", encoding='utf-8')


def getdatawithtag(path):
    df = pd.read_csv(path, encoding='utf-8')
    bugs = df['orisource'].tolist()
    fixes = df['target'].tolist()
    bugfix_pair = [[b, f] for b, f in zip(bugs, fixes)]
    bugfix_pair = sorted(bugfix_pair, key=lambda x: len(x[0]))
    source = []
    target = []
    for bf in bugfix_pair:
        source.append(re.sub(r"CWE-\d+", "", bf[0]).replace("<S2SV_blank>", ''))
        target.append(bf[1])
    df = pd.DataFrame()
    df['source'] = source
    df['target'] = target
    df.to_csv("cve_fixes_chat_tag.csv", encoding='utf-8')


def get_fix_from_gpt(query):
    success = False
    while not success:
        try:
            completion = openai.ChatCompletion.create(
                model="gpt-3.5-turbo",
                messages=[
                    {"role": "user", "content": query}
                ]
            )
            success = True
        except Exception as e:
            print(e)
            continue
    response = completion['choices'][0]['message']['content']
    flag = False
    fixes = []
    fix_code = ''
    for res_line in response.split('\n'):
        if not flag:
            if res_line.startswith('```'):
                flag = True
            continue
        else:
            if res_line.startswith('```'):
                flag = False
                fixes.append(fix_code)
                fix_code = ''
                continue
            fix_code += res_line
            fix_code += '\n'
    return fixes


def run(datapath, start_idx=0, length=1697, epoch=0, prompt=base_prompt, name="base"):
    df = pd.read_csv(datapath, encoding='utf-8')
    source = df['source']
    target = df['target']
    accu = []
    f3 = open("./results/{}_res_{}_{}_{}.txt".format(name, start_idx, length, epoch), 'a', encoding='utf-8')
    bugfix_pair = [[s, t] for s, t in zip(source, target)]
    for pair in tqdm.tqdm(bugfix_pair[start_idx:start_idx + length]):
        b = pair[0]
        f = pair[1]
        f3.write("source:\n")
        f3.write(b + '\n')
        f3.write("target:\n")
        f3.write(f + '\n')
        query = prompt + b
        outputs = get_fix_from_gpt(query)
        flag = False
        f3.write("outputs:\n")
        for output in outputs:
            f3.write(output + "\n")
            f3.write("-"*20+"\n")
            if re.sub(r'\s+', '', f) == re.sub(r'\s+', '', output):
                flag = True
        if flag:
            accu.append(1)
            f3.write("match:1\n")
        else:
            accu.append(0)
            f3.write("match:0\n")
    print(round(sum(accu) / len(accu), 4))


if __name__ == '__main__':
    # getdata("buggy_methods_test.txt", 'fixed_methods_test.txt')
    # getdatawithtag("cve_fixes_test_gpt.csv")
    # for i in range(5):
    #     run("cve_fixes_chat.csv", prompt=base_prompt, length=20, epoch=i, name="base")
    # for i in range(5):
    #     run("cve_fixes_chat_tag.csv", prompt=tag_prompt, length=20, epoch=i, name="tag")
    run("cve_fixes_chat.csv", prompt=multi_base_prompt, length=20, name="base")
    run("cve_fixes_chat_tag.csv", prompt=multi_tag_prompt, length=20, name="tag")
