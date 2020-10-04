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
    waf = 'which may suggest a WAF'
    shell = 'shellshock'
    osv637 = 'OSVDB-637'
    osv578 = 'OSVDB-578'

    path = input("Enter desired .csv file name: ")
    path = (path + '.csv')
    output=open(path, 'w')
    output.write('IP' + ',' + 'Hostname' + ',' + 'Anti-clickjacking' + ',' + 'X-XSS-Protection' + ',' +
                 'No CGI Directories found' + ',' + 'valid response with junk HTTP' + ',' +
                 'Allowed HTTP Methods' + ',' + 'which may suggest a WAF' + ',' + 'shellshock' + ',' +
                 'OSVDB-637' + ',' + 'OSVDB-578' + '\n')

    # Each "row" is equal to one Nikto scan
    # If Nikto failed row will be < 3
    for row in range(len(g)):
        if len(g[row])>3:
            strs = g[row]
            flags = ['0','0','0','0','0','0','0','0','0']   # Reset flags after every scan
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
            if [i for i in strs if waf in i]:
                flags[5] = '1'
            if [i for i in strs if shell in i]:
                flags[6] = '1'
            if [i for i in strs if osv637 in i]:
                flags[7] = '1'
            if [i for i in strs if osv578 in i]:
                flags[8] = '1'

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
    print(' _______  .__ __      __             _________                      _________ .__\n'
          ' \      \ |__|  | ___/  |_  ____    /   _____/ ____  _____    ____   \_   ___ \|  |   ____  _____    ____   ___________\n'
          ' /   |   \|  |  |/ /\   __\/  _ \   \_____  \_/ ___\ \__  \  /    \  /    \  \/|  | _/ __ \ \__  \  /    \_/ __ \_  __ \ \n'
          '/    |    \  |    <  |  | (  <_> )  /        \  \___  / __ \|   |  \ \     \___|  |_\  ___/  / __ \|   |  \  ___/|  | \/\n'
          '\____|__  /__|__|_ \ |__|  \____/  /_______  /\___  //____  /___|  /  \______  /____/\___  >/____  /___|  /\___  >__|\n'
          '        \/        \/                       \/     \/      \/     \/          \/          \/      \/     \/     \/       \n')
    items = []
    array_lines = []
    header = ('IP,Hostname,Anti-clickjacking,X-XSS-Protection\n')

    print ("Note: Make sure first line in file starts with '- Nikto'.")
    file_name = input("Please enter file name: ")

    try:
        #f=open("all_nikto_outputs.txt", "r")
        with open(file_name) as f:
            # Read in Everyline
            for line in f:
                items.append(line.replace('\n',''))

    finally:
        f.close()

    create_graph(items)

if __name__ == "__main__":
    main()

