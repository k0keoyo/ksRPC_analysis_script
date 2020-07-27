import idc
import idaapi
import idautils
import sys

idc.Wait()
filename = idaapi.get_root_filename
path = os.getcwd()
rootfunc = []
rootpath = []
depth = 0
m_rootpath = ""
dstfunc = ""
def findroot(TargetFunc):
    global rootpath
    global rootfunc
    global m_rootpath
    global depth
    global dstfunc
    depth += 1
    if(depth >= 10):
        rootfunc.append(TargetFunc)
        rootpath.append("It's difficult to reverse because depth is too deep!!Try: " + TargetFunc)
        return 
    for xref in idautils.XrefsTo(idc.LocByName(TargetFunc)):
        if(idc.GetFunctionName(xref.frm) == ""):#if root function
            for storcheck in idautils.XrefsTo(idc.LocByName(TargetFunc)):
                if(storcheck.type == 17):#not root function
                    return
            if m_rootpath not in rootpath:
                if(depth > 7):
                    m_rootpath = dstfunc + "<--" + TargetFunc
                rootfunc.append(idc.GetFunctionName(xref.to))
                rootpath.append(m_rootpath)
            return
        else :
            g_rootpath = m_rootpath
            m_rootpath +=  "<--" + idc.GetFunctionName(xref.frm)
            findroot(idc.GetFunctionName(xref.frm))
            depth -= 1
            m_rootpath = g_rootpath   

f = open(path+"\..\..\TargetList.txt","r")
r = open(path+"\IDA-AnalyzeResult.txt","w")
lines = f.readlines()
for line in lines:
    depth = 0
    line = line.strip("\n")
    targetFunc = line
    m_rootpath = targetFunc
    dstfunc = targetFunc
    findroot(targetFunc)
for i in range(len(rootfunc)):
    r.write("["+rootfunc[i]+"]////////"+rootpath[i] + "\n")
f.close()
r.close()
idc.Exit(0)
    
        
    
