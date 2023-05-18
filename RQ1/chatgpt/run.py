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

openai.api_key = ''
base_prompt = '''There are several vulnerabilities in the following program. Please try to fix these vulnerabilities, and return the complete code in the form of a markdown code block\n\n'''
tag_prompt = '''There are several vulnerabilities in the following program. In this program, <S2SV_ModStart> represents where the vulnerability starts, and <S2SV_ModEnd> represents the place where the vulnerability ends. Please try to fix these vulnerabilities, and return the complete code without the above two special tags to me in the form of a markdown code block\n\n'''
multi_base_prompt = '''There are several vulnerabilities in the following program. Please try to fix these vulnerabilities, and return the complete code in the form of a markdown code block. Give me 5 possible fixed code\n\n'''
multi_tag_prompt = '''There are several vulnerabilities in the following program. In this program, <S2SV_ModStart> represents where the vulnerability starts, and <S2SV_ModEnd> represents the place where the vulnerability ends. Please try to fix these vulnerabilities, and return the complete code without the above two special tags to me in the form of a markdown code block. Give me 10 possible fixed code\n\n'''
new_multi_tag_prompt = '''You are an automated vulnerability repair tools. The following contains some vulnerable lines (identified by <S2SV_StartBug> and <S2SV_EndBug> tags). Please provide ten possible correct code. Please separate the ten pieces of code into different code blocks in markdown format\n'''


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


def extract_code_blocks(markdown):
    code_blocks = re.findall(r'```[a-zA-Z]*\n([\s\S]*?)\n```', markdown)
    return code_blocks


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
    fixes = extract_code_blocks(response)
    return fixes


def run(datapath, start_idx=0, length=1697, epoch=0, prompt=base_prompt, name="base"):
    df = pd.read_csv(datapath, encoding='utf-8')
    source = df['source']
    target = df['target']
    accu = []
    f3 = open("./results/{}_res_{}_{}_{}.txt".format(name, start_idx, length, epoch), 'a', encoding='utf-8')
    bugfix_pair = [[s, t] for s, t in zip(source, target)]
    directory = './results/run{}'.format(name)
    if not os.path.exists(directory):
        os.makedirs(directory)
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
            f3.write("-" * 20 + "\n")
            if re.sub(r'\s+', '', f) == re.sub(r'\s+', '', output):
                flag = True
        if flag:
            accu.append(1)
            f3.write("match:1\n")
        else:
            accu.append(0)
            f3.write("match:0\n")
    print(round(sum(accu) / len(accu), 4))


def get_fix_from_gpt_compensate(query, path):
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
    f = open(path, 'w')
    f.write(response)
    f.close()
    fixes = extract_code_blocks(response)
    return fixes

def get_source(target_path):
    f = open(target_path, 'r')
    targets = f.read().splitlines()
    sources = []
    df = pd.read_csv("cve_fixes_chat_tag.csv", encoding='utf-8')
    full_source = df['source'].tolist()
    full_target = df['target'].tolist()
    for i in range(len(full_target)):
        t = full_target[i].strip()
        if t in targets:
            sources.append(full_source[i])
    sources = [s.strip() for s in sources]
    f2 = open("null_source.txt", 'w')
    for s in sources:
        f2.write(s + "\n")
    f2.close()
def compensate(date):
    f1 = open("null_source.txt",'r')
    f2 = open("null_target.txt",'r')
    sources = f1.readlines()
    targets = f2.readlines()
    directory = './results/compensate{}'.format(date)
    if not os.path.exists(directory):
        os.makedirs(directory)
    f3 = open("./results/compensate.txt",'a',encoding='utf-8')
    accu = []
    for i in tqdm.tqdm(range(len(sources))):
        b = sources[i]
        f = targets[i]
        path = directory+"/{}.txt".format(i)
        f3.write("source:\n")
        f3.write(b + '\n')
        f3.write("target:\n")
        f3.write(f + '\n')
        query = new_multi_tag_prompt + b
        outputs = get_fix_from_gpt_compensate(query,path)
        flag = False
        f3.write("outputs:\n")
        for output in outputs:
            f3.write(output + "\n")
            f3.write("-" * 20 + "\n")
            if re.sub(r'\s+', '', f) == re.sub(r'\s+', '', output):
                flag = True
        if flag:
            accu.append(1)
            f3.write("match:1\n")
        else:
            accu.append(0)
            f3.write("match:0\n")
    f3.close()
    print(round(sum(accu) / len(accu), 4))

def extractCompensate():
    f_res = open("./results/compensate.txt",'a',encoding='utf-8')
    for i in range(58):
        f_c_single = open("./results/compensate0518/{}.txt".format(i),'r',encoding='utf-8')
        content = f_c_single.read()
        outputs = []
        if "```" in content:
            content.replace("```c","```")
            outputs += extract_code_blocks(content)
            continue



if __name__ == '__main__':
    # getdata("buggy_methods_test.txt", 'fixed_methods_test.txt')
    # getdatawithtag("cve_fixes_test_gpt.csv")
    # for i in range(5):
    #     run("cve_fixes_chat.csv", prompt=base_prompt, length=20, epoch=i, name="base")
    # for i in range(5):
    #     run("cve_fixes_chat_tag.csv", prompt=tag_prompt, length=20, epoch=i, name="tag")
    # run("cve_fixes_chat.csv", prompt=multi_base_prompt, length=20, name="base")
    run("cve_fixes_chat_tag.csv", prompt=new_multi_tag_prompt, length=100, name="newtag")
    # compensate("0518_2")
