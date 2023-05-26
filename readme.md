# Parsing Access log

## Requirements

You need the followin to be able to run this code:



## Usage

First install the script and it's requirements:

```
git clone https://github.com/fricker12/ParsingAccessLog
cd ParsingAccessLog

```
Then run the script as follows:
```

Собрать статистику по IP-адресам браузера:
python log_analyzer.py extract_ip access_log

INFO:root:Extracting IP addresses from access_log...
INFO:root:IP Address Statistics:
- 10.1.2.194: 5

Найти частоту запросов в интервал времени dT:
python log_analyzer.py find_freq access_log -dT 10

INFO:root:Finding request frequency in time intervals of 10 minutes...
INFO:root:Request Frequency Statistics:
- [08/Oct/2015:09:01:40 +0000 - 08/Oct/2015:09:01:49 +0000]: 5 requests

Найти N наиболее частых User-Agent:
python log_analyzer.py count_user_agents access_log Mozilla/5.0 (Windows NT 6.1; WOW64; rv:40.0) Gecko/20100101 Firefox/40.0 -n 3

INFO:root:Counting User Agents in access_log...
INFO:root:User Agent Statistics:
- Mozilla/5.0 (Windows NT 6.1; WOW64; rv:40.0) Gecko/20100101 Firefox/40.0: 2

Статистика статуса кода S (50x ошибок) в интервал времени dT:
python log_analyzer.py find_status_code_stats access_log -dT 5

INFO:root:Finding status code statistics in time intervals of 5 minutes...
INFO:root:Status Code Statistics:
- [08/Oct/2015:09:01:40 +0000 - 08/Oct/2015:09:01:44 +0000]: 1 error(s)

Найти N самых длинных запросов:
python log_analyzer.py find_longest_requests access_log -n 2

INFO:root:Finding the 2 longest requests in access_log...
INFO:root:Longest Requests:
1. GET /merlin-image-server/view/70bf11f8-4c19-49da-8d38-2913f3d69c4c/800 HTTP/1.1 - Duration: 97882 microseconds
2. POST /merlin-web-za/rest/vehicle/get/facets HTTP/1.1 - Duration: 31130 microseconds

N наиболее частых запросов к K-й косой черте:
python log_analyzer.py find_top_requests_by_slash access_log -k 2 -n 3

INFO:root:Finding the top 3 requests by the 2nd slash in access_log...
INFO:root:Top Requests by 2nd Slash:
1. /merlin-web-za/web/images/refinements/loader.gif: 1 request(s)
2. /merlin-web-za/bundles/js/1513495202/mobilehome_za.js: 1 request(s)
3. /merlin-image-server/view/70bf11f8-4c19-49da-8d38-2913f3d69c4c/800: 1 request(s)

Количество запросов по апстримам (workers):
python log_analyzer.py count_requests_by_upstream access_log

INFO:root:Counting requests by upstream in access_log...
INFO:root:Requests by Upstream Statistics:
- ajp://10.1.4.17:8009: 2 requests
- ajp://10.1.4.67:8009: 1 request
- ajp://10.1.3.201:8009: 1 request

По ссылке найдите статистику конверсий:
python log_analyzer.py extract_conversion_stats access_log autotrader.co.za 2 -s domain

INFO:root:Extracting conversion statistics from access_log...
INFO:root:Conversion Statistics:
- autotrader.co.za: 2 conversions

Количество восходящих запросов (работников) в дT:
python log_analyzer.py count_upstream_requests access_log -dT 1m

INFO:root:Counting upstream requests in time intervals of 1 minute...
INFO:root:Upstream Request Count Statistics:
- [08/Oct/2015:09:01:40 +0000 - 08/Oct/2015:09:02:40 +0000]: 4 requests

Найдите N временных периодов dT по которым выполнено наибольшее количество запросов:
python log_analyzer.py find_top_time_periods access_log -dT 1m -n 2

INFO:root:Finding the top 2 time periods with the highest request count in access_log...
INFO:root:Top Time Periods by Request Count:
1. [08/Oct/2015:09:01:40 +0000 - 08/Oct/2015:09:02:40 +0000]: 4 requests


