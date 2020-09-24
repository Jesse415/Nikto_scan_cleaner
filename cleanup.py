
import sys
import fnmatch

def set_flag(strs):
    subs = 'Target IP:'
    host = 'Target Hostname:'
    anti = 'anti-clickjacking'
    xss = 'X-XSS-Protection'
    cgi = 'No CGI'

    #print(strs)
    sbus = [i for i in strs if subs in i]
    if sbus:
        print(sbus)
    else:
        print("0")

    tsoh = [i for i in strs if host in i]
    if tsoh:
        print(tsoh)
    else:
        print("0")

    itna = [i for i in strs if anti in i]
    if itna:
        print(itna)
    else:
        print("0")

    ssx = [i for i in strs if xss in i]
    if ssx:
        print(ssx)
    else:
        print("0")

    igc = [i for i in strs if cgi in i]
    if igc:
        print(igc)
    else:
        print("0")






               #     tmp = strs[line + 1] + ","
               #     output.write(tmp)
               # if strs[line] == 'Hostname:':
               #   tmp = strs[line + 1] + ","
               #   output.write(tmp)
               #   #print(strs[line + 1], end=",")
               # if strs[line] == 'anti-clickjacking':
               #   tmp = "1,"
               #   output.write(tmp)
               #   #print("1", end=',')
               # if strs[line] == 'X-XSS-Protection':
               #   tmp = "1\n"
               #   output.write(tmp)
               # if strs[line] == 'All':
               #     tmp = "1/n"
               #     output.write(tmp)



def filter_line(g):

    path="CLEAN.csv"
    output=open(path, 'w')
    output.write('IP' + ',' + 'Hostname' + ',' + 'Anti-clickjacking' + ',' + 'X-XSS-Protection' + '\n')

    for row in range(len(g)):
        set_flag(g[row])
        #print(row, g[row], end="\n")
#        for col in range(len(g[row])):
#            set_flag(g[row][col])
        #    strs=g[row][col].split()
        #    for line in range(len(strs)):
        #        print(strs[line])

def create_graph(lists):
    pattern = '- Nikto*'
    graph = []
    count = -2

    # Make an array for Each Nikto Scan with each
    # array variable being a new line
    for row in range(len(lists)):
        # Match the Line with Nikto to start new array
        if fnmatch.fnmatch(lists[row], pattern):
            count += 1
            graph.append([])
            graph[count].append(lists[row])
        else:
            graph[count].append(lists[row])

# Print  out all the lines in each array to confirm output
#    for row in range(len(graph)):
#        print(graph[row])

    filter_line(graph)

def main():
    items = []
    array_lines = []

    try:
        #f=open("testInput.txt", "r")
        with open('testInput.txt') as f:
            # Read in Everyline
            for line in f:
                items.append(line)

    finally:
        f.close()

    create_graph(items)

if __name__ == "__main__":
    main()

