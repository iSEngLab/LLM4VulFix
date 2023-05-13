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
base_prompt = '''There are several vulnerabilities in the following program. In this program, <S2SV_ModStart> represents where the vulnerability starts, and <S2SV_ModEnd> represents the place where the vulnerability ends. Please try to fix these vulnerabilities, and return the complete code without the above two special tags to me in the form of a markdown code block\n\n'''


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
    fix_code = ''
    for res_line in response.split('\n'):
        if not flag:
            if res_line.startswith('```'):
                flag = True
            continue
        else:
            if res_line.startswith('```'):
                break
            fix_code += res_line
            fix_code += '\n'
    return fix_code


def run(buggy_path, fixed_path, start_idx=0, length=1697):
    f1 = open(buggy_path, 'r', encoding='utf-8')
    f2 = open(fixed_path, 'r', encoding='utf-8')
    bugs = f1.readlines()
    fixes = f2.readlines()
    bugfix_pair = [[b,f] for b,f in zip(bugs,fixes)]
    bugfix_pair = sorted(bugfix_pair, key=lambda x: len(x[0]))
    accu = []
    f3 = open("./results/temres.txt", 'a', encoding='utf-8')
    inputs = []
    outputs = []
    targets = []
    count = 0
    for pair in tqdm.tqdm(bugfix_pair):
        b = pair[0].replace("<S2SV_blank>",'')
        f = pair[1]
        try:
            query = base_prompt + b
            output = get_fix_from_gpt(query)
            inputs.append(b)
            outputs.append(output)
            targets.append(f)
            f3.write(output+"\n")
            f3.write("-"*20 + "\n")
            f = re.sub(r'\s+', '', f)
            output = re.sub(r'\s+', '', output)
            print(output)
            if f == output:
                accu.append(1)
                print(1)
            else:
                accu.append(0)
                print(0)
            print(round(sum(accu) / len(accu), 4))
            print("-" * 20)
            count+=1
        except Exception:
            print("Running out of money! Have run {} programs".format(count))
            break
    df = pd.DataFrame()
    df['inputs'] = inputs
    df['outputs'] = outputs
    df['targets'] = targets
    df['acuuracy'] = accu
    df.to_csv("./results/result_{}_{}.csv".format(start_idx,length),encoding='utf-8')

def runwithtag(buggy_path, fixed_path, start_idx=0, length=1697,epoch=0):
    df = pd.read_csv(buggy_path,encoding='utf-8')
    f2 = open(fixed_path, 'r', encoding='utf-8')
    bugs = df['source'].tolist()
    fixes = f2.readlines()
    bugfix_pair = [[b,f] for b,f in zip(bugs,fixes)]
    bugfix_pair = sorted(bugfix_pair, key=lambda x: len(x[0]))
    accu = []
    f3 = open("./results/tag_temres_{}_{}_{}.txt".format(start_idx,length,epoch), 'a', encoding='utf-8')
    inputs = []
    outputs = []
    targets = []
    count = 0
    for pair in tqdm.tqdm(bugfix_pair[start_idx:start_idx+length]):
        b = pair[0]
        f = pair[1]
        try:
            query = base_prompt + b
            output = get_fix_from_gpt(query)
            inputs.append(b)
            outputs.append(output)
            targets.append(f)
            f3.write(output+"\n")
            f3.write("-"*20 + "\n")
            f = re.sub(r'\s+', '', f)
            output = re.sub(r'\s+', '', output)
            print(output)
            if f == output:
                accu.append(1)
                print(1)
            else:
                accu.append(0)
                print(0)
            print(round(sum(accu) / len(accu), 4))
            print("-" * 20)
            count+=1
        except Exception:
            print("Running out of money! Have run {} programs".format(count))
            break
    df = pd.DataFrame()
    df['inputs'] = inputs
    df['outputs'] = outputs
    df['targets'] = targets
    df['acuuracy'] = accu
    df.to_csv("./results/tag_result_{}_{}_{}.csv".format(start_idx,length,epoch),encoding='utf-8')
if __name__ == '__main__':
    for i in range(5):
        runwithtag("cve_fixes_test_chat.csv","fixed_methods_test.txt",start_idx=0,length=20,epoch=i)
    # df = pd.read_csv("cve_fixes_test.csv",encoding='utf-8')
    # source = df['source'].tolist()
    # source = [re.sub(r"CWE-\d+", "", b).replace("<S2SV_blank>",'')for b in source]
    # df['source'] = source
    # df.to_csv('cve_fixes_test_dealt.csv',encoding='utf-8')
    # run("cve_fixes_test.csv", "fixed_methods_test.txt", start_idx=0, length=800)
    # runwithtag("cve_fixes_test.csv", "fixed_methods_test.txt", start_idx=0, length=20)
    # start_time = time.time()
#     buggy_code = '''int main ( int argc , char * * argv ) { int fmtid ; int id ; char * infile ; jas_stream_t * instream ; jas_image_t * image ; int width ; int height ; int depth ; int numcmpts ; int verbose ; <S2SV_StartBug> char * fmtname ; <S2SV_EndBug> if ( jas_init ( ) ) { abort ( ) ; } cmdname = argv [ 0 ] ; infile = 0 ; verbose = 0 ; <S2SV_StartBug> while ( ( id = jas_getopt ( argc , argv , opts ) ) >= 0 ) { <S2SV_EndBug> switch ( id ) { case OPT_VERBOSE : verbose = 1 ; break ; case OPT_VERSION : printf ( "%s\\n" , JAS_VERSION ) ; exit ( EXIT_SUCCESS ) ; break ; <S2SV_StartBug> case OPT_INFILE : <S2SV_EndBug> infile = jas_optarg ; break ; case OPT_HELP : default : usage ( ) ; break ; } } <S2SV_StartBug> if ( infile ) { <S2SV_EndBug> if ( ! ( instream = jas_stream_fopen ( infile , "rb" ) ) ) { fprintf ( stderr , "cannot<S2SV_blank>open<S2SV_blank>input<S2SV_blank>image<S2SV_blank>file<S2SV_blank>%s\\n" , infile ) ; exit ( EXIT_FAILURE ) ; } } else { if ( ! ( instream = jas_stream_fdopen ( 0 , "rb" ) ) ) { fprintf ( stderr , "cannot<S2SV_blank>open<S2SV_blank>standard<S2SV_blank>input\\n" ) ; exit ( EXIT_FAILURE ) ; } } if ( ( fmtid = jas_image_getfmt ( instream ) ) < 0 ) { fprintf ( stderr , "unknown<S2SV_blank>image<S2SV_blank>format\\n" ) ; } <S2SV_StartBug> if ( ! ( image = jas_image_decode ( instream , fmtid , 0 ) ) ) { <S2SV_EndBug> fprintf ( stderr , "cannot<S2SV_blank>load<S2SV_blank>image\\n" ) ; return EXIT_FAILURE ; } jas_stream_close ( instream ) ; numcmpts = jas_image_numcmpts ( image ) ; width = jas_image_cmptwidth ( image , 0 ) ; height = jas_image_cmptheight ( image , 0 ) ; depth = jas_image_cmptprec ( image , 0 ) ; if ( ! ( fmtname = jas_image_fmttostr ( fmtid ) ) ) { abort ( ) ; } printf ( "%s<S2SV_blank>%d<S2SV_blank>%d<S2SV_blank>%d<S2SV_blank>%d<S2SV_blank>%ld\\n" , fmtname , numcmpts , width , height , depth , ( long ) jas_image_rawsize ( image ) ) ; jas_image_destroy ( image ) ; jas_image_clearfmts ( ) ; return EXIT_SUCCESS ; }
# '''.replace("<S2SV_blank>",'')
#     print(buggy_code)
    # query = base_prompt+buggy_code
    # print(get_fix_from_gpt(query))
    # end_time = time.time()
    # run_time = end_time - start_time
    # print(run_time)

