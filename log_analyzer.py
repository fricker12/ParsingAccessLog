import argparse
import re
import logging
from datetime import datetime
from collections import Counter

def extract_ip_addresses(log_file, N):
    logging.info('Extracting IP addresses...')
    """
    Extracts IP addresses from the log file.

    Args:
        log_file (str): Path to the log file.
        N (int): Number of most common IP addresses to return.

    Returns:
        tuple: Tuple containing the list of extracted IP addresses and a dictionary with IP addresses and their counts.
    """
    pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'  # Pattern to match IP addresses
    ip_addresses = []
    with open(log_file, 'r') as file:
        for line in file:
            matches = re.findall(pattern, line)
            ip_addresses.extend(matches)

            # Extracting log format data
            log_match = re.search(
                r'^([\d.]+) \(([\d.]+)\) (-) (-) \[(.+)\] "(.+)" (\d+) (\d+) (\d+) (\d+) "(.+)" "(.+)" "(.+)"',
                line
            )
            if log_match:
                log_format = '{} {} {} {} "{}" {} {} {} {} "{}" "{}" "{}"'.format(
                    log_match.group(1),
                    log_match.group(2),
                    log_match.group(3),
                    log_match.group(4),
                    log_match.group(5),
                    log_match.group(6),
                    log_match.group(7),
                    log_match.group(8),
                    log_match.group(9),
                    log_match.group(10),
                    log_match.group(11),
                    log_match.group(12),
                    log_match.group(13)
                )
                logging.info('Log Format: %s', log_format)

    ip_counts = Counter(ip_addresses)
    most_common = ip_counts.most_common(N)
    print(f"Most common IP addresses (top {N}):")
    for ip, count in most_common:
        print(f" ip: {ip} counts: {count}")
    return ip_addresses, most_common

def find_request_frequency(log_file, dT):
    logging.basicConfig(filename=log_file, level=logging.INFO, format='%(message)s')
    logging.info('Finding request frequency with interval %s minutes...', dT)
    
    pattern = r'\[(\d{2}/\w+/\d{4}:\d{2}:\d{2}:\d{2})'
    request_frequency = {}
    
    with open(log_file, 'r') as file:
        for line in file:
            match = re.search(pattern, line)
            if match:
                timestamp = match.group(1)
                interval = datetime.strptime(timestamp, '%d/%b/%Y:%H:%M:%S').replace(second=0, microsecond=0)
                interval_key = interval.strftime('%d/%b/%Y:%H:%M:%S')
                request_frequency[interval_key] = request_frequency.get(interval_key, 0) + 1
                log_line = f'{line.strip()} "{interval_key}"'
                logging.info(log_line)

    return request_frequency

def extract_user_agents(log_file, N):
    user_agents = {}
    user_agent_pattern = r'("[^"]+")\s+"[^"]+"$'  # Регулярное выражение для извлечения User-Agent

    with open(log_file, 'r') as file:
        for line in file:
            user_agent_match = re.search(user_agent_pattern, line)
            if user_agent_match:
                user_agent = user_agent_match.group(1)
                if user_agent in user_agents:
                    user_agents[user_agent] += 1
                else:
                    user_agents[user_agent] = 1
    
    sorted_user_agents = sorted(user_agents.items(), key=lambda x: x[1], reverse=True)
    
    for user_agent, count in sorted_user_agents[:N]:
        print(f"{user_agent}: {count}")
    return sorted_user_agents[:N]

def find_status_code_stats(log_file, dT):
    logging.info(f'Finding status code statistics with interval {dT} minutes...')
    """
    Finds the statistics of status codes in time intervals of dT minutes.

    Args:
        log_file (str): Path to the log file.
        dT (int): Time interval in minutes.

    Returns:
        dict: Dictionary containing the statistics of status codes in each interval.
    """
    pattern = r'\[(\d{2}/\w+/\d{4}:\d{2}:\d{2}:\d{2})'
    status_code_stats = {}
    with open(log_file, 'r') as file:
        for line in file:
            match = re.search(pattern, line)
            if match:
                timestamp = match.group(1)
                interval = timestamp[:14] + '00:00'
                status_code = re.findall(r'\s(\d{3})\s', line)[0]
                if interval in status_code_stats:
                    status_code_stats[interval][status_code] = status_code_stats[interval].get(status_code, 0) + 1
                else:
                    status_code_stats[interval] = {status_code: 1}
    return status_code_stats


def find_longest_or_shortest_requests(log_file, n, longest=True):
    if longest:
        logging.info(f'Finding {n} longest requests...')
    else:
        logging.info(f'Finding {n} shortest requests...')
    """
    Finds the N longest or shortest requests.

    Args:
        log_file (str): Path to the log file.
        n (int): Number of requests to return.
        longest (bool): If True, find longest requests; if False, find shortest requests.

    Returns:
        list: List of N longest or shortest requests.
    """
    pattern = r'\"(.*?)\"'
    requests = []
    with open(log_file, 'r') as file:
        for line in file:
            match = re.findall(pattern, line)
            if match:
                requests.append(match[0])
    sorted_requests = sorted(requests, key=lambda x: len(x), reverse=longest)
    return sorted_requests[:n]


def find_top_requests_by_slash(log_file, k, n):
    logging.info(f'Finding top {n} requests based on the {k}-th slash...')
    """
    Finds the top N requests based on the K-th slash in the request path.

    Args:
        log_file (str): Path to the log file.
        k (int): Position of the slash to consider (1-indexed).
        n (int): Number of requests to return.

    Returns:
        list: List of top N requests based on the K-th slash.
    """
    pattern = r'\"([^"]+)"'
    requests = []
    with open(log_file, 'r') as file:
        for line in file:
            match = re.findall(pattern, line)
            if match:
                request = match[0].split()
                if len(request) > 1:
                    path = request[1]
                    path_parts = path.split('/')
                    if len(path_parts) >= k:
                        requests.append('/'.join(path_parts[:k]))
    request_counts = {}
    for request in requests:
        request_counts[request] = request_counts.get(request, 0) + 1
    top_requests = sorted(request_counts.items(), key=lambda x: x[1], reverse=True)[:n]
    return top_requests


def count_requests_by_upstream(log_file):
    logging.info('Counting requests by upstream...')
    """
    Counts the number of requests per upstream (worker).

    Args:
        log_file (str): Path to the log file.

    Returns:
        dict: Dictionary containing the count of requests per upstream.
    """
    pattern = r'"([^"]+)"$'
    upstream_counts = {}
    with open(log_file, 'r') as file:
        for line in file:
            match = re.search(pattern, line)
            if match:
                upstream = match.group(1)
                upstream_counts[upstream] = upstream_counts.get(upstream, 0) + 1
    return upstream_counts


def extract_conversion_stats(log_file, domains, sort_by='domain'):
    logging.info(f'Extracting conversion statistics for domains: {domains}, sorted by: {sort_by}...')
    """
    Extracts conversion statistics based on specified domains.

    Args:
        log_file (str): Path to the log file.
        domains (list): List of domains to extract statistics for.
        sort_by (str): Attribute to sort the statistics by ('domain' or 'count').

    Returns:
        list: List of conversion statistics for the specified domains.
    """
    pattern = r'"([^"]+)"$'
    conversion_stats = {}
    with open(log_file, 'r') as file:
        for line in file:
            match = re.search(pattern, line)
            if match:
                url = match.group(1)
                for domain in domains:
                    if domain in url:
                        if domain in conversion_stats:
                            conversion_stats[domain] += 1
                        else:
                            conversion_stats[domain] = 1
    sorted_stats = sorted(conversion_stats.items(), key=lambda x: x[1], reverse=(sort_by == 'count'))
    return sorted_stats


def setup_arg_parser():
    parser = argparse.ArgumentParser(description='Log Analysis Tool')
    subparsers = parser.add_subparsers(dest='command')

    # Subparser for 'extract_ip' command
    extract_ip_parser = subparsers.add_parser('extract_ip', help='Extract IP addresses from the log file')
    extract_ip_parser.add_argument('log_file', type=str, help='Path to the log file')
    extract_ip_parser.add_argument('-n', type=int, default=10, help='Number of top IP addresses to return')

    # Subparser for 'find_freq' command
    find_freq_parser = subparsers.add_parser('find_freq', help='Find the frequency of requests in time intervals')
    find_freq_parser.add_argument('log_file', type=str, help='Path to the log file')
    find_freq_parser.add_argument('-dT', type=int, default=5, help='Time interval in minutes')

    # Subparser for 'extract_user_agents' command
    extract_user_agents_parser = subparsers.add_parser('extract_user_agents', help='Extract User Agents from the log file')
    extract_user_agents_parser.add_argument('log_file', type=str, help='Path to the log file')
    extract_user_agents_parser.add_argument('-n', type=int, default=10, help='Number of top IP addresses to return')

    # Subparser for 'find_status_code' command
    find_status_code_parser = subparsers.add_parser('find_status_code', help='Find the statistics of status codes in time intervals')
    find_status_code_parser.add_argument('log_file', type=str, help='Path to the log file')
    find_status_code_parser.add_argument('-dT', type=int, default=5, help='Time interval in minutes')

    # Subparser for 'find_longest_requests' command
    find_longest_requests_parser = subparsers.add_parser('find_longest_requests', help='Find the longest requests')
    find_longest_requests_parser.add_argument('log_file', type=str, help='Path to the log file')
    find_longest_requests_parser.add_argument('-n', type=int, default=10, help='Number of longest requests to return')

    # Subparser for 'find_shortest_requests' command
    find_shortest_requests_parser = subparsers.add_parser('find_shortest_requests', help='Find the shortest requests')
    find_shortest_requests_parser.add_argument('log_file', type=str, help='Path to the log file')
    find_shortest_requests_parser.add_argument('-n', type=int, default=10, help='Number of shortest requests to return')

    # Subparser for 'find_top_requests_by_slash' command
    find_top_requests_by_slash_parser = subparsers.add_parser('find_top_requests_by_slash', help='Find the top requests based on the K-th slash')
    find_top_requests_by_slash_parser.add_argument('log_file', type=str, help='Path to the log file')
    find_top_requests_by_slash_parser.add_argument('k', type=int, help='Position of the slash to consider (1-indexed)')
    find_top_requests_by_slash_parser.add_argument('-n', type=int, default=10, help='Number of top requests to return')

    # Subparser for 'count_requests_by_upstream' command
    count_requests_by_upstream_parser = subparsers.add_parser('count_requests_by_upstream', help='Count the number of requests per upstream')
    count_requests_by_upstream_parser.add_argument('log_file', type=str, help='Path to the log file')

    # Subparser for 'extract_conversion_stats' command
    extract_conversion_stats_parser = subparsers.add_parser('extract_conversion_stats', help='Extract conversion statistics based on specified domains')
    extract_conversion_stats_parser.add_argument('log_file', type=str, help='Path to the log file')
    extract_conversion_stats_parser.add_argument('domains', type=str, nargs='+', help='List of domains')
    extract_conversion_stats_parser.add_argument('-sort_by', type=str, default='domain', choices=['domain', 'count'],
                                                 help="Attribute to sort the statistics by ('domain' or 'count')")

    return parser


def main():
    parser = setup_arg_parser()
    args = parser.parse_args()
    
    #print(extract_user_agents_('access_log',5))

    logging.basicConfig(level=logging.INFO,
                        format='%(asctime)s - %(levelname)s - %(message)s',
                        datefmt='%Y-%m-%d %H:%M:%S')

    if args.command == 'extract_ip':
        ip_addresses, count_ip = extract_ip_addresses(args.log_file,args.n)
        #print(count_ip)
        with open('log_extraction.log', 'w') as log:
            log.write(f'IP addresses extracted from {args.log_file}: {ip_addresses}\n')
            for ip, count in count_ip:
                log.write(f' ip: {ip} counts: {count}\n')
    elif args.command == 'find_freq':
        request_frequency = find_request_frequency(args.log_file, args.dT)
        with open('log_extraction.log', 'a') as log:
            log.write(f'Frequency of requests in time intervals of {args.dT} minutes: {request_frequency}\n')

    elif args.command == 'extract_user_agents':
        user_agents = extract_user_agents(args.log_file,args.n)
        with open('log_extraction.log', 'w') as log:
            for user_agent, count in user_agents:
                log.write(f'User Agents extracted from {args.log_file}: {user_agent} count {count}\n')

    elif args.command == 'find_status_code':
        status_code_stats = find_status_code_stats(args.log_file, args.dT)
        print(status_code_stats)
        with open('log_extraction.log', 'a') as log:
            log.write(f'Statistics of status codes in time intervals of {args.dT} minutes: {status_code_stats}\n')

    elif args.command == 'find_longest_requests':
        longest_requests = find_longest_or_shortest_requests(args.log_file, args.n, longest=True)
        print(longest_requests)
        with open('log_extraction.log', 'a') as log:
            log.write(f'{args.n} longest requests: {longest_requests}\n')

    elif args.command == 'find_shortest_requests':
        shortest_requests = find_longest_or_shortest_requests(args.log_file, args.n, longest=False)
        print(shortest_requests)
        with open('log_extraction.log', 'a') as log:
            log.write(f'{args.n} shortest requests: {shortest_requests}\n')

    elif args.command == 'find_top_requests_by_slash':
        top_requests = find_top_requests_by_slash(args.log_file, args.k, args.n)
        print(top_requests)
        with open('log_extraction.log', 'a') as log:
            log.write(f'Top {args.n} requests based on the {args.k}-th slash: {top_requests}\n')

    elif args.command == 'count_requests_by_upstream':
        upstream_counts = count_requests_by_upstream(args.log_file)
        print(upstream_counts)
        with open('log_extraction.log', 'a') as log:
            log.write(f'Count of requests per upstream: {upstream_counts}\n')

    elif args.command == 'extract_conversion_stats':
        conversion_stats = extract_conversion_stats(args.log_file, args.domains, args.sort_by)
        print(conversion_stats)
        with open('log_extraction.log', 'a') as log:
            log.write(f'Conversion statistics for domains {args.domains}, sorted by {args.sort_by}: {conversion_stats}\n')

    else:
        parser.print_help()


if __name__ == '__main__':
    main()
