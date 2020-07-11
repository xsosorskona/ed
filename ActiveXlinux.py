try:
    from dhooks import Webhook
    import concurrent.futures
    import requests
    import autopy
    import time
    from termcolor import colored
    import multiprocessing as mp
    import os
    from colorama import init
    import sys
    import threading
    import re
    import time
    import socket 

except Exception as e:
    print(e)
    input("")

init()
print_lock = threading.Lock()
global rlogin
rlogin = requests.Session()
import multiprocessing as mp
color = ("red")
clear = lambda: os.system('cls')  # on Linux System
clear()
num_workers = mp.cpu_count()  
ban = ("""
               _   _          __   __ 
     /\       | | (_)         \ \ / / 
    /  \   ___| |_ ___   _____ \ V /  
   / /\ \ / __| __| \ \ / / _ \ > <   
  / ____ \ (__| |_| |\ V /  __// . \  
 /_/    \_\___|\__|_| \_/ \___/_/ \_\  
 
 
 """)
banner = colored(ban,color)

print(banner)
qa = (1)

def mainswap():
    global username
    global password1
    username = str(input("username:"))
    password1 = str(input("password:"))
    global rlogin

    url = "https://i.instagram.com/accounts/login/ajax/"
    loginuseragent = "Instagram 93.1.0.19.102 Android (21/5.0.2; 240dpi; 540x960; samsung; SM-G530H; fortuna3g; qcom; ar_AE; 154400379)"
    rlogin.headers = {'user-agent': loginuseragent}
    rlogin.headers.update({'Referer': 'https://i.instagram.com/'})
    sreq = rlogin.get("https://i.instagram.com")
    rlogin.headers.update({'X-CSRFToken': sreq.cookies['csrftoken']})
    data = {"username": username, "password": password1}
    loginreq = rlogin.post(url, data=data, allow_redirects=True)
    editcookie = sreq.cookies['csrftoken']
    headers = {
        "method": "post",
        "scheme": "https",
        "accept": "*/*",
        "authority": "www.instagram.com",
        "referer": "https://www.instagram.com/accounts/edit/",
        "x-requested-with": "XMLHttpRequest",
        "path": "/accounts/edit/",
        "content-type": "application/x-www-form-urlencoded",
        "x-csrftoken": editcookie,
        "user-agent": loginuseragent}
    rlogin.headers.update(headers)
    res = loginreq.json()
    if loginreq.text.find("userId") >= 0:
        #print(colored("Logged in\n ", "red")
        print(colored("Logged in","green"))
    elif loginreq.text.find("/challenge") >=0 :

        print(colored("Secured Found Input The Method and Number","red"))
        rlogin.headers.update({'X-CSRFToken': loginreq.cookies['csrftoken']})

        send_request = rlogin.get('https://instagram.com'+str(res['checkpoint_url'])).text
        regex_email = re.findall('"email":"(.*?)"',send_request)
        if regex_email:
            print(colored("""[+] Email  : """+str(regex_email)+""" [+]""","green"))
            email_or_number = int(1)
            #function Email This
            if email_or_number == 1:


                
                data_for_email = {
                            "choice":"1",
                            "enc_new_password1":"#PWD_INSTAGRAM_BROWSER:0:1587316725:",
                            "new_password1":"",
                            "enc_new_password2":"#PWD_INSTAGRAM_BROWSER:0:1587316725:",
                            "new_password2":""}
                send_to_email = rlogin.post('https://instagram.com'+str(res['checkpoint_url']),data=data_for_email)
                email_code = str(input("Code Secure of email : "))
                datae = {
                            "security_code":email_code,
                            "enc_new_password1":"#PWD_INSTAGRAM_BROWSER:0:1587316725:",
                            "new_password1":"",
                            "enc_new_password2":"#PWD_INSTAGRAM_BROWSER:0:1587316725:",
                            "new_password2":""}
                send_secure_email = rlogin.post('https://instagram.com'+str(res['checkpoint_url']),data=datae)
                print(send_secure_email)
            else:
                
            
                data_for_number = {
                        "choice":"0",
                        "enc_new_password1":"#PWD_INSTAGRAM_BROWSER:0:1587316725:",
                        "new_password1":"",
                        "enc_new_password2":"#PWD_INSTAGRAM_BROWSER:0:1587316725:",
                        "new_password2":""}
                send_to_number = rlogin.post('https://instagram.com'+str(res['checkpoint_url']),data=data_for_number)
                number_code = str(input("Code Secure of Number : "))
                datas = {
                        "security_code":number_code,
                        "enc_new_password1":"#PWD_INSTAGRAM_BROWSER:0:1587316725:",
                        "new_password1":"",
                        "enc_new_password2":"#PWD_INSTAGRAM_BROWSER:0:1587316725:",
                        "new_password2":""}
                send_secure_number = rlogin.post('https://instagram.com'+str(res['checkpoint_url']),data=datas).text
                check = re.findall('"errors":["(.*?)"]',send_secure_number)
                print(check)
                if "Please check the code we sent you and try again." in send_secure_number:
                        print("Successfully Code Secure [^.^] ")
                else:
                        print(" Wrong Secure Code , Try Again Later")
                #print(re.findall('"username": "(.*?)"',x))
                #print(re.findall('"email": "(.*?)"',x))


    else:
        print(colored("Wrong Credentials ","red"))


        mainswap()


mainswap()
get_data = rlogin.get("https://i.instagram.com/api/v1/accounts/current_user/?edit=true").json()
try:
    youremail = get_data["user"]["email"]
except:
    youremail = "qwef123132qwef+0123@gmail.com"
scan = requests.Session()
def scanner():
    user = username
    password = password1
    global scan

    url = "https://i.instagram.com/accounts/login/ajax/"
    loginuseragent = "Instagram 93.1.0.19.102 Android (21/5.0.2; 240dpi; 540x960; samsung; SM-G530H; fortuna3g; qcom; ar_AE; 154400379)"
    scan.headers = {'user-agent': loginuseragent}
    scan.headers.update({'Referer': 'https://i.instagram.com/'})
    sreq = scan.get("https://i.instagram.com")
    scan.headers.update({'X-CSRFToken': sreq.cookies['csrftoken']})
    data = {"username": user, "password": password}
    loginreq = scan.post(url, data=data, allow_redirects=True)
    editcookie = sreq.cookies['csrftoken']
    headers = {
        "method": "post",
        "scheme": "https",
        "accept": "*/*",
        "authority": "www.instagram.com",
        "referer": "https://www.instagram.com/accounts/edit/",
        "x-requested-with": "XMLHttpRequest",
        "path": "/accounts/edit/",
        "content-type": "application/x-www-form-urlencoded",
        "x-csrftoken": editcookie,
        "user-agent": loginuseragent}
    scan.headers.update(headers)
    res = loginreq.json()
    if loginreq.text.find("userId") >= 0:
        print(colored("Logged in","green"))
    elif loginreq.text.find("/challenge") >=0 :

        print(colored("Secured Found Input The Method and Number","red"))
        scan.headers.update({'X-CSRFToken': loginreq.cookies['csrftoken']})

        send_request = scan.get('https://instagram.com'+str(res['checkpoint_url'])).text
        regex_email = re.findall('"email":"(.*?)"',send_request)
        print(regex_email)
        regex_number = re.findall('"phone_number":"(.*?)"',send_request)
        print(regex_number)
        try:
            if res['two_factor_info']['obfuscated_phone_number']:

                print ("Your Number is "+str(res['two_factor_info']['obfuscated_phone_number']+" and We Send Secure Code"))
                send_user = usr
                request_number = scan.get("https://www.instagram.com/accounts/login/ajax/two_factor/").text
                if "text message" in request_number:
                        print("Yup IS text message")
                        data_secure_with_text = {
                                    "username":send_user,
                                    "identifier":res["two_factor_info"]["two_factor_identifier"]
                            }
                        request_number_with_text = scan.post("https://www.instagram.com/accounts/send_two_factor_login_sms/",data=data_secure_with_text).text
                        print(request_number_with_text)
                        input_number_secure_with_text = str(input("Enter Code Secure : "))
                        data_secure_withs_text = {
                            "username":send_user,
                            "verificationCode":input_number_secure_with_text,
                            "identifier":res["two_factor_info"]["two_factor_identifier"],
                            "queryParams":'{"next":"/"}'
                                    }
                        request_number_with_text = scan.post("https://www.instagram.com/accounts/login/ajax/two_factor/",data=data_secure_withs_text).text
                        print(5*"\n")
                        print(request_number_with_text)
            else:
                input_number_secure_without_text = str(input("Enter Code Secure : "))
                data_secure_without_text = {
                    "username":send_user,
                    "verificationCode":input_number_secure_without_text,
                    "identifier":res["two_factor_info"]["two_factor_identifier"],
                    "queryParams":'{"next":"/"}'
                            }
                request_number_without_text = scan.post("https://www.instagram.com/accounts/login/ajax/two_factor/",data=data_secure_without_text).text

                print(request_number_without_text)
        except Exception as er:
              raise er
        else:
            print("""Email Or number To Send Secure ?
                                            -1 [+] Email  : """+regex_email+""" [+]
                                            -2 [+] Number : """+regex_number+"""[+]
                                        """)
            email_or_number = str(input(":"))
            #function Email This
            if email_or_number == 1:


                
                data_for_email = {
                            "choice":"1",
                            "enc_new_password1":"#PWD_INSTAGRAM_BROWSER:0:1587316725:",
                            "new_password1":"",
                            "enc_new_password2":"#PWD_INSTAGRAM_BROWSER:0:1587316725:",
                            "new_password2":""}
                send_to_email = scan.post('https://instagram.com'+str(res['checkpoint_url']),data=data_for_email)
                email_code = str(input("Code Secure of email : "))
                datae = {
                            "security_code":email_code,
                            "enc_new_password1":"#PWD_INSTAGRAM_BROWSER:0:1587316725:",
                            "new_password1":"",
                            "enc_new_password2":"#PWD_INSTAGRAM_BROWSER:0:1587316725:",
                            "new_password2":""}
                send_secure_email = scan.post('https://instagram.com'+str(res['checkpoint_url']),data=datae)
                print(send_secure_email)
            else:
                
            
                data_for_number = {
                        "choice":"0",
                        "enc_new_password1":"#PWD_INSTAGRAM_BROWSER:0:1587316725:",
                        "new_password1":"",
                        "enc_new_password2":"#PWD_INSTAGRAM_BROWSER:0:1587316725:",
                        "new_password2":""}
                send_to_number = scan.post('https://instagram.com'+str(res['checkpoint_url']),data=data_for_number)
                number_code = str(input("Code Secure of Number : "))
                datas = {
                        "security_code":number_code,
                        "enc_new_password1":"#PWD_INSTAGRAM_BROWSER:0:1587316725:",
                        "new_password1":"",
                        "enc_new_password2":"#PWD_INSTAGRAM_BROWSER:0:1587316725:",
                        "new_password2":""}
                send_secure_number = scan.post('https://instagram.com'+str(res['checkpoint_url']),data=datas).text
                check = re.findall('"errors":["(.*?)"]',send_secure_number)
                print(check)
                if "Please check the code we sent you and try again." in send_secure_number:
                        print("Successfully Code Secure ")
                else:
                        print("Wrong Secure Code , Try Again Later")
                #print(re.findall('"username": "(.*?)"',x))
                #print(re.findall('"email": "(.*?)"',x))


    else:
        print(colored("Wrong Credentials ","red"))

        mainswap()

if qa==1:
    yourthreadsnumber = int(input("threads:"))
send = str(input("Target:"))
#send1 = str(input("Target2:"))
#send2 = str(input("Target3:"))

def load_url(url):
    global youremail
    global get_data
    global msg
    global title
    
        

    values = {

                        "username": str(url),
                        "chaining_enabled": "on",
                        "email": youremail
    }

    usr = str(url)
    url = "https://i.instagram.com/api/v1/feed/user/{}/username/".format(usr)##
    clear()
    print(banner)
    print(colored("Target:","white"),colored("{}".format(usr),"red"))
    print("Hunting:",colored("ON","red"))
    while 1:
        get_data = rlogin.post(url).content.__contains__('"items": [], "num_results": 0, "status": "ok"'.encode())
        
        if get_data:
            url = "https://i.instagram.com/api/v1/accounts/edit_profile/"
            s = rlogin.post(url, data=values)
            ssd = s.content.__contains__("is_private".encode())
            if ssd is True:
                with print_lock:

                    print("Successful Request {} ".format(usr))
                    print("  ")
                    
            else:
                print("Missed [{}]".format(s.content))
                input(" ")
            

        
 

def thbeat(url):
    global youremail
    global get_data
    global msg 
    global thbeat
    
        

    values = {

                        "username": str(url),
                        "chaining_enabled": "on",
                        "email": youremail
    }
    urlswap = "https://i.instagram.com/api/v1/accounts/edit_profile/"









    usr = str(url)


    url = "https://i.instagram.com/api/v1/feed/user/{}/username/".format(usr)##
    clear()
    print(banner)
    print(colored("Target:","white"),colored("{}".format(usr),"red"))

    #animation = "|/-\\"

    #for i in range(100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000999999999999999999999999999999999999999990):
     #time.sleep(0.1)
     #sys.stdout.write("\r" + format(usr) + " : " + animation[i % len(animation)])
    #sys.stdout.flush()
    #do something

    while 1:
        get_data = scan.post(url).content.__contains__('"items": [], "num_results": 0, "status": "ok"'.encode())
        if get_data:
            s = rlogin.post(urlswap, data=values)
            ssd = s.content.__contains__("is_private".encode())
            if ssd:
                clear()
                print(banner)
                print("         Successful Request {} ".format(usr))
                print(colored("                       Active X","green"))
                hook = Webhook("https://discordapp.com/api/webhooks/730141580198936578/FgUsT3XEjTLZeZZU8LQbrlzpQmKIAqe8Ffk_Sz6TQGLOJUeNS6DExZw2pFFJiI2rK9u5")
                data = ("Successful Request @{}".format(usr))
                hook.send(data)
                TOKEN = "1197097853:AAF-A9fOTZ8HE73BIuEMwHee-b8vHF2epSA" #@botfather
                TEXT = ("Successful Request @{}".format(usr))
                CHAT_ID = ("-1001259522684") 
                URL = f"https://api.telegram.org/bot{TOKEN}/sendMessage?chat_id={CHAT_ID}&text={TEXT}"
                dark = requests.get(URL) 
                print(" ")
                time.sleep(0.050)
            else:
                print("NEVER STOP [{}]".format(s.content))
                input(" ")
            

            
        
          
        






if qa==1:
    thredas = []
    for i in range(yourthreadsnumber+1):
        t = threading.Thread(target=load_url,args=(send,))
        t.daemon =True
        t.start()
        thredas.append(t)
    for i in thredas:
        i.join()
elif qa==2:
    scanner()
    with concurrent.futures.ThreadPoolExecutor(max_workers=num_workers) as executor:
        future_to_url = executor.submit(thbeat, send)
