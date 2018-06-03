#!/use/bin/python




# graphic element TODO remove it?
sizeDrawLine = 100

'''
used for create eq distances between columns in table in the terminal
'''
def printWithSpace(strs, space):
    dis = space
    if len(strs) > dis:
        return strs[0:dis] + "|"
    else:
        return strs + " "*(dis - len(strs)) + "|"
    

