import sys
import fnmatch

def filter_line(g):
    no = 'No web server found'
    subs = 'Target IP:'
    host = 'Target Hostname:'

    # Flags to look for and mark
    anti = 'anti-clickjacking'
    xss = 'X-XSS-Protection'
    cgi = 'No CGI'
    vrwj = 'valid response with junk' # May cause false positives
    allow = 'Allowed HTTP Methods'

    path="CLEAN.csv"
    output=open(path, 'w')
    output.write('IP' + ',' + 'Hostname' + ',' + 'Anti-clickjacking' + ',' + 'X-XSS-Protection' + ',' +
                 'No CGI Directories found' + ',' + 'valid response with junk HTTP' + ',' +
                 'Allowed HTTP Methods' + '\n')

    # Each "row" is equal to one Nikto scan
    # If Nikto failed row will be < 3
    for row in range(len(g)):
        if len(g[row])>3:
            strs = g[row]
            flags = ['0','0','0','0','0']   # Reset flags after every scan
            for scan in range(len(strs)):
                if subs in strs[scan]:
                    tmp = strs[scan].split()[3] + ','
                    output.write(tmp)
                elif host in strs[scan]:
                    tmp = strs[scan].split()[3]
                    output.write(tmp)
                elif no in strs[scan]:
                    break
            # Set flags to 1 for every mark
            if [i for i in strs if anti in i]:
                flags[0] = '1'
            if [i for i in strs if xss in i]:
                flags[1] = '1'
            if [i for i in strs if cgi in i]:
                flags[2] = '1'
            if [i for i in strs if vrwj in i]:
                flags[3] = '1'
            if [i for i in strs if allow in i]:
                flags[4] = '1'

            # If the scan Failed or no web server found, skip write to file
            if no not in strs[scan]:
                for flag in range(len(flags)):
                    output.write(',' + str(flags[flag]))
                output.write('\n')

    output.close()

def create_graph(lists):
    pattern = '- Nikto*'
    graph = []
    count = -1

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
    header = ('IP,Hostname,Anti-clickjacking,X-XSS-Protection\n')

    try:
        #f=open("testInput.txt", "r")
        with open('testInput.txt') as f:
            # Read in Everyline
            for line in f:
                items.append(line.replace('\n',''))

    finally:
        f.close()

    create_graph(items)

if __name__ == "__main__":
    main()

