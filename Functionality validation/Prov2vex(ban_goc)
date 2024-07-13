import pyvex
import archinfo
import re
import hashlib
import os
import shutil
import angr
from analyse import *
from threading import Thread
import threading
import time
import numpy as np

# this function to get all variable of one statement and it's type (define or reference)
def get_var_in_stmt(stmt):
    res=[]
    # regular expression pattern to match temporary variables
    pattern = r't\d+'
    variables = re.findall(pattern, stmt)
    if stmt[:2]=='if':
        res.append([variables[0],'ref'])
        return res
    if len(variables)==0:
        return []
    eql=stmt.index('=')
    for var in variables:
        if stmt.index(var)<eql:
            res.append([var,'def'])
        else:
            res.append([var,'ref'])
    return res

# this function detect a statement ca be propagation or not
def dectect_which_statement_can_be_propagation(stmt):
    vars=get_var_in_stmt(stmt)
    if len(stmt)<10 and len(vars)==2 and vars[0][1]=='def' and vars[1][1]=='ref':
        return True
    return False

# implement copy propagation in a block
def copy_propagation(block):
    ACP={}
    res=[]
    for i in range(len(block)):
        #print("block: ", block[i])
        stmt=block[i]
        vars=get_var_in_stmt(stmt)[::-1]
        #print("vars:", vars)
        for var in vars:
            #print(var)
            if var[1]=='ref' and var[0] in ACP.keys():
                #print("replace", var[0],ACP[var[0]])
                stmt=stmt.replace(var[0],ACP[var[0]])
                #print("stmt: ", stmt)
            if var[1]=='def' and var[0] in ACP.keys():
                #print("dell",ACP[var[0]])
                del ACP[var[0]]
        if dectect_which_statement_can_be_propagation(stmt)==True:
            vars=get_var_in_stmt(stmt)
            ACP[vars[0][0]]=vars[1][0]
            #print("ACP:",ACP)
        res.append(stmt)
        #print("----------------------")
    return res

# implement dead code elimination in a block
def dead_code_elimination(block):
    res=[]
    for i in range(len(block)):
        if dectect_which_statement_can_be_propagation(block[i])==False:
            res.append(block[i])
    return res
# this function return reference variable in a statement in basic block
def reference(stmt):
    res=[]
    vars=get_var_in_stmt(stmt)
    for var in vars:
        if var[1]=='ref':
            res.append(var[0])
    return res

# this function return define variable in a statement in basic block
def define(stmt):
    res=[]
    vars=get_var_in_stmt(stmt)
    for var in vars:
        if var[1]=='def':
            res.append(var[0])
    return res

# this function return intersection of 2 list of variables
def intersect(vars1,vars2):
    for var in vars1:
        if var in vars2:
            return True
    return False


# this function return union of 2 list of variables
def union(vars1,vars2):
    res=[]
    for var in vars1:
        res.append(var)
    for var in vars2:
        res.append(var)
    return res

# implement algorithm to parse a basic block to list of strand
def parse_bb_to_strand(block):
    S=[]
    uncovered=list(range(len(block)))
    #print(uncovered)
    while len(uncovered)>0:
        last=uncovered.pop()
        strand=[block[last]]
        used=reference(block[last])
        for i in range(last-1,-1,-1):
            #print(f" i: {i}")
            #print(f"block:  {block[i]}")
            needed=intersect(used,define(block[i]))
            #print(f"define: {define(block[i])}")
            if needed==True:
                #print("found")
                strand.append(block[i])
                used= union(reference(block[i]),used)
                #print(f"used: {used}")
                #print(f" i: {uncovered}")
                try:
                    uncovered.remove(i)
                except:
                    continue
                #print(f" i: {uncovered}")
        S.append(strand)
    return S


# this funtion normalize a basic block, rename all temporary variables in descending chronological order
def normalize(block):

    mapping={}
    pattern = r't\d+'
    all_stmt="\n".join(block)
    if get_var_in_stmt(all_stmt)==[]:
        return block
    #print(all_stmt)
    variables = re.findall(pattern, all_stmt)
    variables = list(dict.fromkeys(variables))

    for i in range(len(variables)):
        mapping[variables[i]]='t'+str(i)
    #print(mapping)
    def new_replace(match):
        return mapping[match.group(0)]

    pattern = re.compile('|'.join(map(re.escape, mapping.keys())))
    result = pattern.sub(new_replace, all_stmt)
    #print("---------------------")

    #print("---------------------")
    #print(result)
    return result

# this function return vector from a list of strand
def extract_vector_from_strand(liststrand):
    vector=[0]*2**10
    for strand in liststrand:
        value=int(hashlib.md5(str(strand).encode()).hexdigest(),16)%2**10
        vector[value]+=1
    return vector

def Process(file_name):
    proj = angr.Project(file_name, auto_load_libs=False)
    cfg = proj.analyses.CFG()
    blocks = cfg.nodes()

    result_str = ""

    for block in blocks:
        bl = proj.factory.block(block.addr)
        for stmt in bl.vex.statements:
            if not isinstance(stmt, pyvex.IRStmt.IMark):
                result_str += str(stmt) + '\n'
        result_str += "------\n"

    data = result_str.split("------\n")
    STRAND = []

    for info in data:
        block = info.split("\n")[:-1]
        if not block:
            continue
        block = copy_propagation(block)
        block = dead_code_elimination(block)
        block = normalize(block)
        strand = parse_bb_to_strand(block)
        STRAND += strand

    vector = extract_vector_from_strand(STRAND)
    return vector

folder_path = '/content/gdrive/MyDrive/DACN/BinKit_dataset/daq'
output_folder = '/content/gdrive/MyDrive/DACN/vector/daq'

# Lấy danh sách các tệp trong thư mục
files = os.listdir(folder_path)

for file_name in files:
    # Xử lý tệp thực thi ở đây
    input_file = os.path.join(folder_path, file_name)

    # Kiểm tra xem tệp output đã tồn tại hay chưa
    output_file_name = file_name + '.txt'
    output_file_path = os.path.join(output_folder, output_file_name)

    if not os.path.exists(output_file_path):
        v = Process(input_file)

        # Ghi kết quả vào file text
        with open(output_file_path, 'w') as output_file:
            output_file.write(str(v))

        print(f"Kết quả đã được lưu trong file: {output_file_name}")
    else:
        print(f"Tệp {output_file_name} đã tồn tại. Bỏ qua.")
