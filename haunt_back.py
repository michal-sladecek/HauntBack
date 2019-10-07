#!/usr/bin/python3

import argparse
import requests
import urllib
import json
import asyncio
from keywordtree import KeywordTree
import concurrent.futures
from colorama import Fore, Back, Style 


argparser = argparse.ArgumentParser(description='Parse archive.org for secrets about webpage')
argparser.add_argument('--url', help='Url to be searched for')
argparser.add_argument('--mimetype', help='Filtered mimetype')
argparser.add_argument('--original', help='Filtered url regex')
argparser.add_argument('--statuscode', help='Filtered statuscodes')
argparser.add_argument('--matchtype', help='prefix/domain')
argparser.add_argument('--date_from', help='date from yyyy')
argparser.add_argument('--date_to', help='date until yyyy')
argparser.add_argument('--action', help='secrets/urls')
digests = set()


args = argparser.parse_args()
root_url = args.url.rstrip('/')
mimetype = args.mimetype
original = args.original
statuscode = args.statuscode
matchtype = args.matchtype
date_from = args.date_from
date_to = args.date_to
prefix_url = "http://web.archive.org/cdx/search/cdx?url={}&output=json&collapse=digest&limit=1000&showResumeKey=true".format(root_url)
if mimetype != None:
  prefix_url += "&filter=mimetype:{}".format(mimetype)
if original != None:
  prefix_url += "&filter=original:{}".format(original)
if statuscode != None:
  prefix_url += "&filter=statuscode:{}".format(statuscode)
if matchtype != None:
  prefix_url += "&matchType=" + matchtype
else:
  prefix_url += "&matchType=domain"
if date_from != None:
  prefix_url += "&from="+date_from
if date_to != None:
  prefix_url += "&to="+date_to



class UrlInterestingness():
  digests = set()
  urls = []

  def url_similarity(self,u1, u2):
    u1_t = u1.split("/")
    u2_t = u2.split("/")
    similarity_metrics = 0.0
    for i in u1_t:
      for j in u2_t:
        if i==j:
         similarity_metrics += 1.0
    return similarity_metrics/max(len(u1_t), len(u2_t))

  def heuristics(self, timestamp_diff, url_diff, length_diff):
    if length_diff < 10 and timestamp_diff<2592000 and url_diff >0.8:
      return True
    return False

  def is_url_interesting(self, timestamp, original, mimetype, statuscode, digest, length):
    if digest in self.digests:
      return False
    else:
      for u in self.urls:
        if u[3] == statuscode and u[2] == mimetype:
          if self.heuristics(abs(timestamp-u[0]), self.url_similarity(u[1],original), abs(length-u[4])) == True:
            return False

      self.urls.append((timestamp, original, mimetype,statuscode,length))
      self.digests.add(digest)
      return True



async def gather_urls(queue, prefix_url, loop, executor):
  resumekey=""
  while True:
    main_request = await loop.run_in_executor(executor, requests.get,prefix_url+resumekey)
    parsed = json.loads(main_request.text)
    for i in range(1,len(parsed)-2):
      await queue.put(parsed[i])      
    if len(parsed) < 1003:
      print("gather_urls finished")
      await queue.put(None)
      break
    resumekey="&resumeKey="+parsed[-1][0]    
  

async def process_responses_urls(queue, loop, executor):
  printed = set()
  while True:
    item = await queue.get()
    if item is None:
      print("process_responses_urls finished")
      break
    if item[2] not in printed:
      print(item[2])
      printed.add(item[2])


async def gather_responses(queue, queue2,loop, executor):
  u = UrlInterestingness()  
  while True:
    item = await queue.get()
    if item is None:
      print("gather_responses finished")
      await queue2.put(None)
      break
    if u.is_url_interesting(int(item[1]), item[2], item[3], int(item[4]), item[5], int(item[6])):
      await queue2.put((item,loop.run_in_executor(executor, requests.get, "https://web.archive.org/web/{}if_/{}".format(item[1],item[2]))))

async def process_responses_secrets(queue, loop, executor):
  keywords = KeywordTree(case_insensitive=True)
  false_positives = ["secretofmaya", "Secret of Maya", "authResponse.accessToken","access_token:i","RedisCDXSource", "withCredentials", "SECRET_INTERNALS_DO_NOT_USE_OR_YOU_WILL_BE_FIRED", "preDispatch"]
  phase = 0
  for keyword in open("./wordlist.txt").readlines():
      keywords.add(keyword.rstrip())
  keywords.finalize()
  count = 0
  while True:
    item = await queue.get()
    if item is None:
      break
    request = await item[1]
    for match,pos in keywords.search_all(request.text):
      context = request.text[max(0,pos-100):min(len(request.text)-1,pos+len(match)+100)]
      ok = True
      for fp in false_positives:
        if fp in context:
          ok = False
          break
      if ok:
        print(Fore.GREEN + "https://web.archive.org/web/{}if_/{}".format(item[0][1],item[0][2]))
        print(Style.RESET_ALL)
        print(context)





with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
  loop = asyncio.get_event_loop()
  if args.action == 'secrets':
    queue = asyncio.Queue(loop=loop)
    queue2 = asyncio.Queue(loop=loop)
    producer_coro = gather_urls(queue, prefix_url, loop, executor)
    content_gather = gather_responses(queue, queue2, loop, executor)
    secrets_finder = process_responses_secrets(queue2, loop, executor)
    loop.run_until_complete(asyncio.gather(producer_coro, content_gather,secrets_finder))
  else:
    queue = asyncio.Queue(loop=loop)
    content_gather = process_responses_urls(queue,loop,executor)
    producer_coro = gather_urls(queue, prefix_url, loop, executor)
    loop.run_until_complete(asyncio.gather(producer_coro, content_gather))
  loop.close()