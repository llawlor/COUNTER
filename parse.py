from optparse import OptionParser
import re
import time, datetime
import operator
import socket
from struct import unpack

# match this pattern when analyzing urls
pattern_allowed = re.compile(r'.*')

# disallow this pattern when analyzing urls
pattern_denied = re.compile(r'DISALLOWED_REGEX')

# break the log line up into named parts
parts = [
    r'(?P<host>\S+)',                   # host ip address
    r'\S+',                             # (unused)
    r'(?P<user>\S+)',                   # user
    r'\[(?P<raw_time>.+)\]',            # raw time stamp
    r'"(?P<verb>\S+)',                  # http verb
    r'(?P<request>\S+)',                # requested url
    r'(?P<http>.+)"',                   # http version
    r'(?P<status>[0-9]+)',              # status
    r'(?P<size>\S+)',                   # size (careful, can be '-')
    r'"(?P<referer>.*)"',               # referer
    r'"(?P<agent>.*)"',                 # user agent
]
pattern = re.compile(r'\s+'.join(parts)+r'\s*\Z')

# iterate through each line of the file
def readLines(input_path, output_path, verbose, stdout):
    input_file = open(input_path, 'r')
    output_file = None
    if not stdout:
        if not output_path:
            output_path = input_path + '.counter'
            if verbose:
                output_path += '.verbose'
        output_file = open(output_path, 'w')
    institution_list = get_institutions()
    raw_list = []

    # add lines to raw list
    for line in input_file:
        parsed_line = inspect(line, institution_list)
        if parsed_line:
            raw_list.append(parsed_line)

    # sort list by host and then by time
    sorted_list = sorted(raw_list, key=operator.itemgetter('host', 'time'))

    # prune the list by removing double-clicked items
    fix_double_clicks(sorted_list)

    # sort again by institution id
    sorted_list = sorted(sorted_list, key=operator.itemgetter('institution_id', 'time'))

    # print output file name
    if output_file:
        print('Output file: ' + output_path)
 
    # render output based on verbose flag
    if verbose:
        for item in sorted_list:
            output = str(item['institution_id']) + ' ' + item['host'] + ' ' + item['raw_time'] + ' ' + item['request']
            # send output to file or stdout
            write_output(output_file, output)
    # group items and add counts
    else:
        # list to handle counts
        grouped_list = []

        # print the headers
        header = 'institution_id year month day count'
        if output_file:
            output_file.write(header + '\n')
        else:
            print(header)

        # add items to grouped list
        for item in sorted_list:
            output = str(item['institution_id']) + ' ' + item['time'].strftime('%Y %m %d')
            group_add(grouped_list, output)

        # output grouped list
        for item in grouped_list:
            write_output(output_file, item)

# add an item to the proper group and increase the count
def group_add(grouped_list, item):
    grouped_list_length = len(grouped_list)
    group_exists = False

    # iterate through the grouped list, looking for a match
    for i in xrange(0, grouped_list_length):
        if grouped_list[i].startswith(item):
            # get the last number since that is the count
            count = int(grouped_list[i].replace(item + ' ', ''))
            # increase the count
            grouped_list[i] = item + ' ' + str(count+1)
            group_exists = True
            break

    # if the group doesn't exist, add it
    if not group_exists:
        grouped_list.append(item + ' 1')

# sends output to correct location
def write_output(output_file, line):
    # send output to file or stdout
    if output_file:
        output_file.write(line + '\n')
    else:
        print(line)

# remove items if double clicks are detected
def fix_double_clicks(sorted_list):
    sorted_list_length = len(sorted_list)
    pop_count = 0

    # for each item in the list
    for i in range(0, sorted_list_length):
        current_index = i - pop_count

        # if we are still in the bounds of the list
        if current_index < sorted_list_length - pop_count - 1:

            # if hosts and requests match, and time is within 10 seconds of the previous time, remove the line
            if sorted_list[current_index]['host'] == sorted_list[current_index+1]['host'] and sorted_list[current_index]['request'] == sorted_list[current_index+1]['request'] and sorted_list[current_index]['time'] > sorted_list[current_index+1]['time'] - datetime.timedelta(seconds=10):
                sorted_list.pop(current_index)
                pop_count += 1

        else:
            break

# create dictionary of institutions
def get_institutions():
    file = open('institution_list.txt', 'r')
    institution_list = []

    # break the institution data up into named parts
    institution_pattern = re.compile(r'(?P<institution_id>\d+)\s(?P<ip_start>\S+)\s(?P<ip_end>\S+)')

    # add lines to institution list
    for line in file:
        matches = institution_pattern.match(line)
        if matches:
            result = matches.groupdict()
            institution_list.append({'institution_id': result['institution_id'], 'ip_start': ip_encode(result['ip_start']), 'ip_end': ip_encode(result['ip_end']),})

    return institution_list

# turn the line into a dictionary
def inspect(line, institution_list):
    matches = pattern.match(line)

    # if the log line matches the apache log file pattern
    if matches:
        result = matches.groupdict()

        # if the article should be counted
        if valid_count(result):
            result['institution_id'] = check_institution(ip_encode(result['host']), institution_list)

            # if the log line is from an institution
            if result['institution_id'] > 0:
                tt = time.strptime(result['raw_time'][:-6], "%d/%b/%Y:%H:%M:%S")
                tt = list(tt[:6]) + [ 0, Timezone(result['raw_time'][-5:]) ]
                result['time'] = datetime.datetime(*tt)
                # save memory by only returning the results we need
                slim_result = {'host': result['host'], 'time': datetime.datetime(*tt), 'institution_id': result['institution_id'],
                    'request': result['request'], 'raw_time': result['raw_time']}

                # return a result if we got to here
                return slim_result

# checks if log line is from an institution
def check_institution(ip_address, institution_list):
    institution_id = 0
    # for each institution in the list
    for i in institution_list:
        # if the log line's ip address is within the institution's ip range
        if ip_address >= i['ip_start'] and ip_address <= i['ip_end']:
            institution_id = int(i['institution_id'])
            break
    return institution_id

# check if the article should be counted
def valid_count(result):
    is_counted = False

    # if a valid GET request and the specified patterns match
    if result['verb'] == 'GET' and (result['status'] == '200' or result['status'] == '304'):
        if pattern_allowed.match(result['request']):
            if not pattern_denied.search(result['request']):
                is_counted = True
    return is_counted

# convert the apache log file time to a python time object
class Timezone(datetime.tzinfo):
    def __init__(self, name="+0000"):
        self.name = name
        seconds = int(name[:-2])*3600+int(name[-2:])*60
        self.offset = datetime.timedelta(seconds=seconds)

    def utcoffset(self, dt):
        return self.offset

    def dst(self, dt):
        return None

    def tzname(self, dt):
        return self.name

# encode ip address as an unsigned long integer, useful for comparison within ranges
def ip_encode(ip_address):
    return unpack("!L", socket.inet_aton(ip_address))[0]

# run the parser
def main():
    p = OptionParser("usage: parse.py file\n\nNote: institution_list.txt (sql output of institution ip_addresses) must be present in same directory")
    p.add_option("-f", "--file", dest="output_path", help="write report to FILE", metavar="FILE")
    p.add_option("-v", "--verbose", action="store_true", dest="verbose", help="verbose mode", default=False)
    p.add_option("-s", "--stdout", action="store_true", dest="stdout", help="output to standard output (terminal)", default=False)
    (options, args) = p.parse_args()

    # if a file wasn't specified
    if len(args) < 1:
        p.error("must specify a file to parse")
    output_path = options.output_path if options.output_path else None
    input_path = args[0]
    readLines(input_path, output_path, options.verbose, options.stdout)

if __name__ == '__main__':
    main()