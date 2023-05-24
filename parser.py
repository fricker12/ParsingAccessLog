import argparse
import re
from collections import Counter

# Функция для чтения файла access.log и получения списка записей
def read_log_file(filename):
    with open(filename, 'r') as file:
        log_data = file.readlines()
    return log_data

# Команда 1: Собрать статистику по IP-адресам браузера, указать N самых частых
def command1(log_data, num):
    ip_addresses = [re.search(r'^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', line).group(1)
                    for line in log_data if re.search(r'^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', line)]
    ip_counter = Counter(ip_addresses)
    top_ips = ip_counter.most_common(num)
    for ip, count in top_ips:
        print(f'IP-адрес: {ip}, Частота: {count}')

# Команда 2: Найти частоту запросов в интервал времени dT (минут)
def command2(log_data, dT):
    time_pattern = r'\[([\w:/]+\s[+\-]\d{4})\]'
    timestamps = [re.search(time_pattern, line).group(1) for line in log_data if re.search(time_pattern, line)]
    timestamp_counter = Counter(timestamps)
    for timestamp, count in timestamp_counter.items():
        print(f'Временная метка: {timestamp}, Частота: {count}')

# Команда 3: Найти N наиболее частых User-Agent
def command3(log_data, num):
    user_agents = [re.search(r'"([^"]+)"$', line).group(1) for line in log_data if re.search(r'"([^"]+)"$', line)]
    user_agent_counter = Counter(user_agents)
    top_user_agents = user_agent_counter.most_common(num)
    for user_agent, count in top_user_agents:
        print(f'User-Agent: {user_agent}, Частота: {count}')

# Команда 4: Статистика статус статуса кода S (50x ошибок) в интервал времени dT (минут)
def command4(log_data, S, dT):
    time_pattern = r'\[([\w:/]+\s[+\-]\d{4})\]'
    status_pattern = rf'\"[^"]+\"\s({S}\d{{2}})\s'
    filtered_data = [line for line in log_data if re.search(status_pattern, line)]
    timestamps = [re.search(time_pattern, line).group(1) for line in filtered_data]
    timestamp_counter = Counter(timestamps)
    for timestamp, count in timestamp_counter.items():
        print(f'Временная метка: {timestamp}, Количество: {count}')

# Команда 5: Найти N самых длинных или кратчайших запросов
def command5(log_data, num, longest=True):
    request_lengths = [len(re.search(r'\"([A-Z]+)\s([^"]+)', line).group(0)) for line in log_data
                       if re.search(r'\"([A-Z]+)\s([^"]+)', line)]
    sorted_lengths = sorted(request_lengths, reverse=not longest)
    top_lengths = sorted_lengths[:num]
    for length in top_lengths:
        print(f'Длина запроса: {length}')

# Команда 6: N наиболее частых запросов к K-й косой черте
def command6(log_data, num, k):
    path_pattern = r'\"[A-Z]+\s((?:[^/\s]+/){' + str(k-1) + r'}[^/\s]+)'
    paths = [re.search(path_pattern, line).group(1) for line in log_data if re.search(path_pattern, line)]
    path_counter = Counter(paths)
    top_paths = path_counter.most_common(num)
    for path, count in top_paths:
        print(f'Запрос: {path}, Частота: {count}')

# Команда 7: Количество запросов по апстримам (workers)
def command7(log_data):
    worker_pattern = r'\"[^"]+\"\s[^"]+\s[^"]+\s[^"]+\s\"[^"]+\"\s\"[^"]+\"\s\"[^"]+\"\s\"[^"]+\"\s\"([^"]+)\"'
    workers = [re.search(worker_pattern, line).group(1) for line in log_data if re.search(worker_pattern, line)]
    worker_counter = Counter(workers)
    for worker, count in worker_counter.items():
        print(f'Worker: {worker}, Количество: {count}')

# Команда 8: Статистика конверсий по ссылкам
def command8(log_data, domains, sort_by):
    conversion_pattern = r'\"([^"]+)\"\s\d+\s\d+\s\d+\s\"[^"]+\"\s\"[^"]+\"\s\"[^"]+\"\s\"([^"]+)\"'
    conversions = [(re.search(conversion_pattern, line).group(1), re.search(conversion_pattern, line).group(2))
                   for line in log_data if re.search(conversion_pattern, line)]
    domain_counter = Counter()
    for link, domain in conversions:
        if domain in domains:
            domain_counter[domain] += 1
    sorted_domains = sorted(domain_counter.items(), key=lambda x: x[0] if sort_by == 'domain' else x[1], reverse=True)
    for domain, count in sorted_domains:
        print(f'Домен: {domain}, Количество переходов: {count}')

# Команда 9: Количество восходящих запросов (работников) в дT (минут)
def command9(log_data, dT):
    time_pattern = r'\[([\w:/]+\s[+\-]\d{4})\]'
    timestamps = [re.search(time_pattern, line).group(1) for line in log_data if re.search(time_pattern, line)]
    timestamp_counter = Counter(timestamps)
    for timestamp, count in timestamp_counter.items():
        print(f'Временная метка: {timestamp}, Количество запросов: {count}')

# Команда 10: Найти N временных периодов dT по которым выполнено наибольшее количество запросов
def command10(log_data, num, dT):
    time_pattern = r'\[([\w:/]+\s[+\-]\d{4})\]'
    timestamps = [re.search(time_pattern, line).group(1) for line in log_data if re.search(time_pattern, line)]
    sorted_timestamps = sorted(timestamps)
    period_counter = Counter()
    for i in range(len(sorted_timestamps) - dT + 1):
        period = sorted_timestamps[i:i+dT]
        period_counter[tuple(period)] += 1
    top_periods = period_counter.most_common(num)
    for period, count in top_periods:
        start_time = period[0]
        end_time = period[-1]
        print(f'Временной период: {start_time} - {end_time}, Количество запросов: {count}')

# Загрузка файла access.log
def load_log_file(file_path):
    with open(file_path, 'r') as file:
        log_data = file.readlines()
    return log_data

# Основная функция
def analyze_log_file(file_path, command, num=None, k=None, dT=None, domains=None, sort_by=None):
    log_data = load_log_file(file_path)
    if command == 1:
        command1(log_data, num)
    elif command == 2:
        command2(log_data, dT)
    elif command == 3:
        command3(log_data, num)
    elif command == 4:
        command4(log_data, dT)
    elif command == 5:
        command5(log_data, num)
    elif command == 6:
        command6(log_data, num, k)
    elif command == 7:
        command7(log_data)
    elif command == 8:
        command8(log_data, domains, sort_by)
    elif command == 9:
        command9(log_data, dT)
    elif command == 10:
        command10(log_data, num, dT)

# Пример использования:
analyze_log_file('access_log', command=1, num=5)
analyze_log_file('access_log', command=2, dT=60)
analyze_log_file('access_log', command=3, num=3)
analyze_log_file('access_log', command=4, dT=60)
analyze_log_file('access_log', command=5, num=3)
analyze_log_file('access_log', command=6, num=3, k=2)
analyze_log_file('access_log', command=7)
analyze_log_file('access_log', command=8, domains=['example.com', 'example.org'], sort_by='domain')
analyze_log_file('access_log', command=9, dT=30)
analyze_log_file('access_log', command=10, num=3, dT=2)
