# Network

### 이정민
<details>
  <summary> VMware 환경에서 NAT = Bridge + LAN Segment ? </summary>

  ## NAT
  
  **역할:** 내부 네트워크의 여러 기기가 하나의 공인 IP를 사용해 인터넷에 접근할 수 있도록 하는 **IP를 공유**한다.
  
  **주요 기능:**  
  - **주소 변환:** 내부의 사설 IP(예: 10.x.x.x)와 외부의 공인 IP(예: 203.0.113.x)를 상호 변환한다.
  - **포트 매핑:** 하나의 공인 IP를 여러 내부 기기가 공유할 수 있도록 각 연결마다 다른 포트 번호를 할당하여 구분한다.
  - **연결 추적 및 보안:** 각 연결의 상태를 NAT 테이블에 기록해 응답을 올바른 내부 기기로 전달하며 내부 네트워크 구조가 외부에 노출되지 않도록 보호한다.
  
  **예시:** 집의 Wi-Fi를 사용할 때 컴퓨터, 스마트폰 등이 각각 10.0.0.10, 10.0.0.11의 사설 IP를 사용하며 라우터는 하나의 공인 IP(예: 203.0.113.5)를 통해 외부와 통신한다. 각 기기의 연결은 포트 번호로 구분되어 관리한다.

  
  ## Bridge
  
  **역할:** 여러 LAN Segment를 Cable이나 Switch과 같은 물리적 장비나 vLAN 등의 논리적 설정을 통합해 모든 기기가 동일한 브로드캐스트 도메인을 공유하도록 한다.
  
  **주요 기능:**  
  - **데이터 전달:** 데이터 링크 계층에서 작동해 **MAC 주소**를 기반으로 데이터를 그대로 전달한다.
  - **네트워크 확장:** 각 Segment를 한 기기가 보낸 브로드캐스트 메시지가 도달할 수 있는 모든 기기들의 범위로 통합한다. 동일한 네트워크 내의 모든 기기가 같은 브로드캐스트 영역을 공유하게 함으로써 기기들 간의 통신이 원활하게 이루어지도록 지원한다.
  
  **예시:** 사무실 내 각 층의 네트워크를 Switch 또는 Bridge 장비로 연결하여 모든 기기가 동일한 네트워크 상에서 자유롭게 통신할 수 있도록 하는 경우

  
  ## LAN Segment(vSwitch 옵션)
  
  **역할:** 동일한 IP 대역과 브로드캐스트 영역을 공유하는 기기들의 집합으로 기본적인 네트워크 통신 환경을 제공한다.
  
  **주요 기능:**  
  - **고유 IP 할당:** 각 기기는 네트워크 내에서 충돌 없이 고유한 IP(예: 10.x.x.x)를 사용한다.
  - **기본 통신:** 같은 LAN Segment에 속한 기기들은 직접 통신하며 데이터를 주고받을 수 있다.
  
  **예시:** 가정 내 컴퓨터, 프린터 등 모두 **동일**한 10.x.x.x 대역을 사용하여 하나의 LAN을 구성, 서로 데이터를 교환하는 환경

  
  ## 그래서 NAT는 Bridge + LAN Segment인가?  
  NAT는 LAN Segment의 내부 통신, Bridge의 외부 연결과 유사한 기능을 제공하지만 LAN Segment와 Bridge를 결합한 것이 아닌 가상 라우터, 스위치, DHCP 서버가 통합된 별도의 가상 네트워크 인프라를 구성한다.
</details>

<details>
  <summary> Proxy 서버의 역할과 구성 방법: Forward Proxy, Reverse Proxy, RDS Proxy </summary>
  
## Proxy

  **프록시**는 클라이언트와 서버 간의 **중계자**로 클라이언트의 요청을 서버로 전달하고 서버의 응답을 클라이언트에 전달하는 역할을 한다.

## Forward Proxy
    
  **역할:**
	포워드 프록시는 클라이언트의 요청을 대신하여 서버로 전달하는 프록시이며 클라이언트는 직접 서버와 연결하지 않고 포워드 프록시를 통해 요청을 보내고 응답을 받는다.
 
  **주요 기능:** 
  - 클라이언트의 요청을 대신 처리한다.
  - **인터넷 필터링:** 특정 사이트의 접근을 제한한다.
  - **익명화:** 사용자의 IP를 숨겨서 익명으로 웹을 서핑한다.
  - **캐싱:** 자주 요청되는 데이터를 캐시하여 빠른 응답을 제공한다.

  **동작 흐름:**
  1. **클라이언트 요청:** 클라이언트가 웹 요청을 보낸다.
  2. **프록시 서버:** 요청은 포워드 프록시 서버로 전달되고 요청을 실제 웹 서버로 전달한다.
  3. **서버 응답:** 실제 서버에서 응답을 포워드 프록시 서버로 보낸다.
  4. **클라이언트 응답:** 포워드 프록시 서버가 응답을 클라이언트로 전달한다.

  **설정 (예: NGINX로 설정):**
```bash
sudo apt update && sudo apt install squid
sudo nano /etc/squid/squid.conf

wget http://nginx.org/download/nginx-1.18.0.tar.gz
tar -xzvf nginx-1.18.0.tar.gz

git clone https://github.com/chobits/ngx_http_proxy_connect_module.git # ngx_http_proxy_connect_module 모듈을 추가
```
```bash
server {
    listen 3128;  # 포트 3128에서 클라이언트 요청을 수신
    server_name localhost;  # 서버 이름을 'localhost'로 설정

    # 포워드 프록시에서 DNS를 처리하는 DNS 리졸버 설정
    resolver 8.8.8.8;  # 포워드 프록시 요청에 대해 DNS 질의를 처리할 DNS 서버를 구글의 8.8.8.8로 설정

    # 포워드 프록시 요청을 위한 CONNECT 메서드 처리
    proxy_connect;  # CONNECT HTTP 메서드를 사용하여 프록시 연결을 허용 (주로 HTTPS 연결에 사용)
    proxy_connect_allow         443 563;  # CONNECT 메서드가 연결할 수 있는 포트를 443(HTTPS), 563(SSL)으로 지정
    proxy_connect_connect_timeout 120s;  # 프록시 서버와의 연결 타임아웃을 120초로 설정
    proxy_connect_read_timeout 120s;  # 프록시 서버로부터 응답을 읽는 타임아웃을 120초로 설정
    proxy_connect_send_timeout 120s;  # 프록시 서버에 요청을 보내는 타임아웃을 120초로 설정

    location / {  # 기본 위치 설정, 모든 경로에 대해 프록시 설정을 적용
        proxy_set_header Host $host;  # 클라이언트의 호스트 헤더를 프록시 서버에 전달
        proxy_set_header X-Real-IP $remote_addr;  # 클라이언트의 실제 IP 주소를 X-Real-IP 헤더로 전달
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;  # X-Forwarded-For 헤더에 클라이언트 IP를 추가
        proxy_set_header X-Forwarded-Proto $scheme;  # 클라이언트 요청의 프로토콜(HTTP/HTTPS)을 X-Forwarded-Proto 헤더로 전달

        # 본문과 쿼리 문자열 전달을 활성화
        proxy_method $request_method;  # 클라이언트의 HTTP 요청 메서드를 그대로 사용하도록 설정
        proxy_set_body $request_body;  # 요청 본문을 프록시 서버에 전달
    }
}
```
```bash
cd /usr/local/nginx/sbin
sudo ./nginx
tail -f /usr/local/nginx/logs/access.log
```

  **예시:**
  - **익명 프록시:** 사용자가 직접 웹사이트에 접속하지 않고 프록시를 통해 접속하여 IP를 숨긴다.
  - **인터넷 필터링:** 특정 기업이나 학교에서 불필요한 웹사이트를 차단할 때 사용한다.

  **출처:** [Squid Forward Proxy](https://with-cloud.tistory.com/58)

## Reverse Proxy

  **역할:**
	리버스 프록시는 클라이언트가 요청하는 서버가 아닌 중간의 리버스 프록시 서버가 요청을 백엔드 서버로 전달하여 처리한다.

  **주요 기능:**
  - **로드 밸런싱:** 여러 서버로 요청을 분배하여 부하를 분산한다.
  - **보안 강화:** 실제 서버의 IP를 숨겨 보안을 향상한다.
  - **SSL 종료:** SSL 연결을 리버스 프록시 서버에서 처리하고 실제 서버는 암호화되지 않은 데이터만 처리한다.

  **동작 흐름:**
  1. **클라이언트 요청:** 클라이언트가 요청을 리버스 프록시 서버로 보낸다.
  2. **리버스 프록시:** 리버스 프록시 서버가 요청을 백엔드 서버로 전달한다.
  3. **백엔드 서버 응답:** 백엔드 서버에서 응답을 리버스 프록시 서버로 전달한다.
  4. **클라이언트 응답:** 리버스 프록시 서버가 응답을 클라이언트에게 전달한다.

  **설정 (예: NGINX로 설정):**
```bash
brew install nginx # Homebrew로 설치한 Nginx의 모든 파일은 /opt/homebrew 경로 아래에 위치한 파일들을 수정해야 한다.
sudo mkdir -p /opt/homebrew/etc/nginx/ssl # HTTPS를 활성화하기 위한 SSL 인증서 및 키 파일을 저장하는 용도

sudo openssl genpkey -algorithm RSA -out /opt/homebrew/etc/nginx/ssl/private.key # RSA 알고리즘을 사용하여 개인 키를 생성하고 /opt/homebrew/etc/nginx/ssl/private.key에 저장
sudo openssl req -new -key /opt/homebrew/etc/nginx/ssl/private.key -out /opt/homebrew/etc/nginx/ssl/csr.pem # 개인 키를 사용하여 CSR(Certificate Signing Request)을 생성하고 /opt/homebrew/etc/nginx/ssl/csr.pem에 저장
sudo openssl x509 -req -in /opt/homebrew/etc/nginx/ssl/csr.pem -signkey /opt/homebrew/etc/nginx/ssl/private.key -out /opt/homebrew/etc/nginx/ssl/selfsigned.crt # CSR을 사용하여 자체 서명된 SSL 인증서를 생성하고 /opt/homebrew/etc/nginx/ssl/selfsigned.crt에 저장
```
```bash
sudo vi /opt/homebrew/etc/nginx/nginx.conf # 각 서버 블록과 관련된 설정뿐만 아니라 리소스 관리, 로깅, 파일 포함 등의 설정
```
```bash
#user  nobody;  # nginx 프로세스가 사용할 사용자 이름
worker_processes  1;  # nginx가 사용할 워커 프로세스 수 설정 

#error_log  logs/error.log;  # 에러 로그 파일의 경로 
#error_log  logs/error.log  notice;  # 에러 로그 레벨을 'notice'로 설정 
#error_log  logs/error.log  info;  # 에러 로그 레벨을 'info'로 설정 

#pid        logs/nginx.pid;  # nginx 프로세스의 PID 파일 경로 설정

events {
    worker_connections  1024;  # 한 워커 프로세스가 처리할 수 있는 최대 연결 수 설정
}


http {
    include       mime.types;  # mime 유형을 설정하는 파일을 포함
    default_type  application/octet-stream;  # 기본 MIME 유형 설정

#   log_format  main  '$remote_addr - $remote_user [$time_local] "$request" '  # 로그 형식 설정
#                      '$status $body_bytes_sent "$http_referer" '  # 로그 형식의 일부로 요청 상태 및 바디 크기 포함
#                      '"$http_user_agent" "$http_x_forwarded_for"';  # 로그 형식의 일부로 사용자 에이전트 및 프록시 정보 포함

#   access_log  logs/access.log  main;  # 요청에 대한 접근 로그를 'access.log' 파일에 기록

    sendfile        on;  # 파일을 직접 전송하는 것을 활성화 
    keepalive_timeout  65;  # 연결 유지 시간 설정

#   gzip  on;  # Gzip 압축 활성화

    include servers/*;  # 'servers' 디렉토리 내의 설정 파일들을 포함
    include /opt/homebrew/etc/nginx/sites-enabled/*;  # 'sites-enabled' 디렉토리 내의 설정 파일들을 포함
}

```
```bash
sudo mkdir -p /opt/homebrew/etc/nginx/sites-available
sudo vi /opt/homebrew/etc/nginx/sites-available/default # 서버가 처리할 HTTP 및 HTTPS 요청에 대한 라우팅 및 리디렉션 등을 설정
```
```bash
# /opt/homebrew/etc/nginx/sites-available/default
server {
    listen 80;  # HTTP 요청을 받을 포트
    server_name localhost;  # 서버 이름

    # HTTP -> HTTPS 리디렉션
    location / {
        return 301 https://$host$request_uri;  # 모든 HTTP 요청을 HTTPS로 리디렉션
    }
}

server {
    listen 443 ssl;  # HTTPS 요청을 받을 포트와 SSL 활성화
    server_name localhost;  # 서버 이름

    ssl_certificate /opt/homebrew/etc/nginx/ssl/selfsigned.crt;  # SSL 인증서 경로
    ssl_certificate_key /opt/homebrew/etc/nginx/ssl/private.key;  # SSL 인증서 키 경로

    # SSL 설정
    ssl_protocols TLSv1.2 TLSv1.3;  # 지원하는 SSL/TLS 프로토콜 버전 
    ssl_prefer_server_ciphers on;  # 서버 측 암호화 우선 사용
    ssl_ciphers HIGH:!aNULL:!MD5;  # 사용할 암호화 알고리즘 지정 (HIGH 보안 등급 암호화만 허용, NULL 및 MD5 제외)

    # 요청에 대한 로깅
    access_log /var/log/nginx/frontend_access.log;  # HTTP 요청에 대한 접근 로그 파일 경로
    error_log /var/log/nginx/frontend_error.log;  # 오류 로그 파일 경로

    location / {  # 웹 애플리케이션의 루트 디렉토리로 들어오는 요청 처리
        # 프론트엔드로 들어오는 요청을 백엔드 서버로 전달
        proxy_pass http://localhost:8080;  # 요청을 실제 백엔드 서버로 전달
        proxy_set_header Host $host;  # 원본 요청의 호스트 헤더를 백엔드 서버로 전달
        proxy_set_header X-Real-IP $remote_addr;  # 클라이언트의 실제 IP 주소를 백엔드 서버로 전달
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;  # 프록시 체인을 통해 전달된 모든 IP를 백엔드 서버로 전달
        proxy_set_header X-Forwarded-Proto $scheme;  # 사용된 프로토콜(HTTP/HTTPS)을 백엔드 서버로 전달
    }
}
```
```bash
sudo ln -s /opt/homebrew/etc/nginx/sites-available/default /opt/homebrew/etc/nginx/sites-enabled/default
```
```bash
sudo mkdir -p /var/log/nginx
sudo nginx -t
sudo nginx -s reload
curl -I http://localhost
```
<img width="1110" alt="Image" src="https://github.com/user-attachments/assets/aa8038bd-8de9-452f-8bdc-201a17be2adc" />

  **예시:**
  - **웹 애플리케이션 로드 밸런싱:** 리버스 프록시를 사용하여 여러 웹 서버로 트래픽을 분배하고 서버 부하를 분산시킬 수 있다.
  - **API 서버 보호:** 클라이언트의 요청을 리버스 프록시 서버로 보내고 실제 API 서버는 보호된다.


## RDS Proxy

  **역할:**
	RDS 프록시는 애플리케이션과 RDS 간의 연결을 관리하고 성능을 최적화하는 프록시이다. 데이터베이스 연결 풀링 및 자동 장애 조치를 제공하며 연결 관리의 복잡성을 줄인다.

  **주요 기능:**
  - **연결 풀링:** 데이터베이스 연결을 효율적으로 관리하여 성능 최적화한다.
  - **자동 장애 조치:** 데이터베이스 장애 시 자동으로 다른 인스턴스로 연결을 전환한다.
  - **성능 최적화:** 연결 재사용과 풀링을 통해 애플리케이션의 성능을 높인다.

  **동작 흐름:**
  1. **애플리케이션 요청:** 애플리케이션은 데이터베이스 연결을 위해 RDS 프록시 서버에 요청을 보낸다.
  2. **RDS 프록시:** RDS 프록시가 데이터베이스 연결 풀을 관리하고 실제 RDS 인스턴스에 연결하여 데이터베이스 요청을 처리한다.
  3. **응답:** RDS 인스턴스에서 결과를 RDS 프록시로 전달한다.
  4. **애플리케이션 응답:** RDS 프록시가 결과를 애플리케이션에 전달한다.

  **설정 (AWS RDS 프록시 설정):**
  1. **AWS RDS 콘솔 접속:** AWS 관리 콘솔에서 RDS Proxy를 설정한다.
  2. **RDS 프록시 생성:**
	  - **VPC**, **Subnets**, **Security Groups** 를 설정한다.
    - **Target RDS instance** 를 지정한다.
  3. **데이터베이스 연결:** 애플리케이션에서 RDS 프록시 엔드포인트를 사용하여 데이터베이스에 연결한다.
	   
```bash
# 애플리케이션에서 RDS 프록시를 통해 데이터베이스 연결
mysql -h [rds-proxy-endpoint] -u [username] -p
```

  **예시:**
  - **웹 애플리케이션:** RDS 프록시를 사용하여 데이터베이스 연결을 관리하고 성능을 최적화한다.
  - **대규모 데이터베이스 서비스:** 데이터베이스 연결 수가 많을 경우 RDS 프록시를 사용해 연결을 풀링하고 효율적으로 처리한다.


## 요약
- **포워드 프록시**는 클라이언트의 요청을 대신 처리하며 **익명화**, **인터넷 필터링** 등에 사용된다.
- **리버스 프록시**는 클라이언트의 요청을 백엔드 서버로 전달하여 **로드 밸런싱**, **보안 강화** 등에 사용된다.
- **RDS 프록시**는 데이터베이스 연결을 관리하고 성능을 최적화하며 **연결 풀링**과 **자동 장애 조치**를 제공한다.
</details>


### 김동욱
<details>
  <summary> Subnet vs VLAN </summary>

  ## Subnet
  
  ### 정의
  - 네트워크를 논리적으로 분할한 단위로, 계층 3(네트워크 계층)에서 동작합니다.
  - 서브넷 마스크를 통해 IP 주소의 네트워크 ID와 호스트 ID를 구분합니다.
  
  ### 목적
  - 브로드캐스트 도메인 분리
    - 큰 네트워크를 작은 서브넷으로 나누어 불필요한 브로드캐스트 트래픽을 줄입니다.
  - 보안 및 관리 효율성
    - 다른 서브넷 간 통신은 라우터/방화벽을 거치게 해 접근 제어가 가능합니다.
  - IP 주소 효율적 할당
    - 필요한 호스트 수에 맞춰 서브넷 크기를 최적화합니다 (예: /24 → 254개 호스트, /30 → 2개 호스트).
  
  ### 예시
  네트워크: 192.168.1.0/24  
  서브넷 A: 192.168.1.0/26 (호스트 62개)  
  서브넷 B: 192.168.1.64/26 (호스트 62개)  
  
  ## VLAN
  
  ### 정의
  - 하나의 물리적 스위치를 여러 논리적 네트워크로 분할하는 기술로, 계층 2(데이터 링크 계층)에서 동작합니다.
  - 태그 기반(VLAN ID, 예: IEEE 802.1Q)으로 트래픽을 구분합니다.
  
  ### 목적
  - 브로드캐스트 도메인 분리
    - 서브넷과 유사하지만 L2 스위치에서 구현되므로 라우터 없이도 통신 격리가 가능합니다.
  - 물리적 배치와 무관한 그룹화
    - 다른 층/건물에 있는 기기를 하나의 VLAN으로 묶어 관리할 수 있습니다 (예: 재무부서 VLAN, 개발부서 VLAN).
  - 보안 강화
    - VLAN 간 통신은 L3 장비(라우터)를 거치도록 강제해 접근 제어를 적용할 수 있습니다.
   
  ### 예시
  VLAN 10: 영업부서 (포트 1-8)  
  VLAN 20: 개발부서 (포트 9-16)  
  
   ## Subnet과 VLAN의 기능이 중복되는데 둘 중 한가지만 써도 될까?
   A. 한가지만 사용해도 네트워크 분리는 가능하지만 같이 사용할 경우 아래와 같은 장점이 있음
   | 기능                 | 서브넷만 사용                          | VLAN + 서브넷 사용                          |
  |----------------------|---------------------------------------|--------------------------------------------|
  | 브로드캐스트 분리     | 서브넷 단위 (IP 기반)                 | VLAN 단위 (스위치 레벨에서 완전 분리)       |
  | L2 보안 제어         | 불가능                                | 가능 (포트 고정, MAC ACL 등)                |
  | 포트 기반 정책       | 어렵거나 복잡                         | 간단 (VLAN ID만 설정하면 끝)                |
  | 유연한 구성          | 물리적 위치 중요                      | 위치 무관, VLAN으로 논리적 묶기 가능         |
  | 공격 격리            | 라우터에 의존                         | 스위치 레벨에서 차단 가능                   |
</details>

<details>
  <summary> PC(호스트)에서 브라우저에 google.com을 입력하면 어떻게 될까? (네트워크 관점) </summary>

  ## 흐름도


[🖥️ 호스트 PC]
</br></br>
    ↓ (DNS 요청: www.google.com)
</br></br>
[🌐 로컬 DNS 리졸버] (8.8.8.8, 1.1.1.1 등)
</br></br>
    ↓ (재귀 요청 진행)
</br></br>
[🌎 루트 DNS 서버]
</br></br>
    ↓ (".com" TLD 서버 주소 반환)
</br></br>
[🗂️ TLD DNS 서버 (.com)]
</br></br>
    ↓ ("google.com" 권한 서버 주소 반환)
</br></br>
[🏢 구글 권한 DNS 서버]
</br></br>
    ↓ (www.google.com에 대한 최종 IP 주소 반환)
</br></br>
[🌐 로컬 DNS 리졸버]
</br></br>
    ↓ (호스트로 최종 IP 응답 전달)
</br></br>
[🖥️ 호스트 PC]
</br></br>
    ↓ (구글 서버로 실제 접속 시도)

 ## 각 노드(장비, 서버) 역할
| 노드 | 역할 설명 |
|:---|:---|
| 🖥️ **호스트 PC** | 사용자가 `www.google.com` 입력하는 기기. DNS 요청을 처음 발생시킴. |
| 🌐 **로컬 DNS 리졸버** | PC가 설정한 DNS 서버 (예: 8.8.8.8). 호스트 대신 IP를 찾아오는 재귀 질의를 담당. |
| 🌎 **루트 DNS 서버** | 도메인 이름 최상위 레벨(TLD, 예: .com, .net 등)을 알려주는 글로벌 최상위 DNS 서버. |
| 🗂️ **TLD DNS 서버 (.com)** | `.com` 도메인 관련 정보를 관리하는 서버. 예: `google.com`, `naver.com` 등. |
| 🏢 **구글 권한 DNS 서버** | `google.com` 도메인에 대한 최종 IP주소를 제공하는 구글 소유 DNS 서버. |
| 🌐 **로컬 DNS 리졸버 (응답)** | 최종 IP를 받아서 호스트 PC에 전달하고, 캐싱함(TTL 시간 동안 저장). |

## 요약

- 호스트는 IP주소를 알지 못해서, 로컬 DNS 리졸버에게 물어봄
- 로컬 리졸버는 답을 직접 알지 못하면 "루트 → TLD → 권한 DNS" 순서로 점점 깊게 들어감
- 권한 서버가 최종 답(IP주소)을 알려줌
- 최종 IP주소를 받은 후, 호스트는 TCP 연결을 해서 실제 통신을 시작함
  
</details>


### 임용진
<details>
  <summary> 네트워크 - 라우팅 프로토콜 vs 라우티드 프로토콜 </summary>

## 라우팅 프로토콜 (Routing Protocol)

- 라우터 간에 경로 정보를 교환하여 최적의 경로를 동적으로 결정하는 프로토콜
- 라우팅 테이블을 자동으로 생성/갱신
- 네트워크 구조 변화에 자동 대응

### 분류 방식

| 방식 | 설명 | 대표 프로토콜 |
|------|------|----------------|
| 거리 벡터 | 거리(홉 수) + 방향 | RIP, IGRP |
| 링크 상태 | 전체 구조 파악 후 최적 경로 계산 | OSPF, IS-IS |
| 경로 벡터 | 경로 벡터 정보(AS 정보 등) 기반 | BGP |

---

## 라우티드 프로토콜 (Routed Protocol)

- 실제 데이터를 목적지로 전달하는 프로토콜
- 라우팅 프로토콜이 만든 경로를 따라 사용자 데이터(IP 패킷 등)가 전달
- 라우터가 처리할 수 있는 트래픽의 종류를 의미하기도 한다.

### 대표 프로토콜

- IPv4, IPv6
- AppleTalk (구버전)
- IPX (Novell NetWare에서 사용)

---

## 라우팅 vs 라우티드 프로토콜 차이

| 구분 | 라우팅 프로토콜 | 라우티드 프로토콜 |
|------|------------------|--------------------|
| 역할 | 최적 경로를 결정 | 데이터를 전달 |
| 작동 주체 | 라우터 간 정보 교환 | 라우터가 패킷 전달 |
| 데이터 처리 | 라우팅 정보만 처리 | 사용자 데이터 처리 |
| 예시 | RIP, OSPF, EIGRP, BGP | IPv4, IPv6, IPX, AppleTalk |

---

## 정리

- 라우팅 프로토콜: 길 찾는 앱 (예: 구글 지도)
- 라우티드 프로토콜: 실제로 달리는 자동차 (예: 택시)
</details>

<details>
  <summary>마스터-슬레이브 구조란?</summary>

클라우드 인프라와 시스템 아키텍처를 다루는 엔지니어에게 있어, **마스터-슬레이브 구조**는 고성능·고가용성 시스템을 설계하는 데 핵심 개념 중 하나 
주로 **데이터베이스**, **메시지 큐**, **파일 시스템**, **캐시 시스템** 등 다양한 영역에서 활용

---

## 개요

마스터-슬레이브(Master-Slave) 구조는 중앙 제어 노드(Master)와 하위 종속 노드(Slave) 간의 명확한 역할 분담을 통해 시스템의 확장성과 신뢰성을 확보하는 방식

| 역할       | 기능 설명 |
|------------|------------|
| 마스터 노드 | 주요 연산(쓰기/제어)을 수행하고 슬레이브로 데이터 또는 명령을 전파 |
| 슬레이브 노드 | 마스터의 상태를 복제하거나 명령을 수신하여 일부 기능을 수행 (주로 읽기 연산) |

---

## 핵심 포인트

### 1. **부하 분산 (Load Balancing)**

- 읽기/쓰기 트래픽을 분리하여 **병목 현상 완화**
- 슬레이브 노드를 수평 확장(horizontal scaling)하여 **읽기 성능 극대화**
- 클라우드 환경에서는 **Auto Scaling Group**과 연계하여 슬레이브 확장 자동화 가능

### 2. **고가용성 (High Availability)**

- 마스터 장애 시 **슬레이브를 프로모션(Promotion)** 하여 서비스 지속 가능
- 클라우드에서는 **RDS Read Replica → Multi-AZ Failover**, 또는 **Heartbeat + VIP** 구성으로 장애 대응

### 3. **데이터 복제 및 일관성 (Replication & Consistency)**

- **비동기 복제**: 성능 우위, 데이터 지연 발생 가능
- **동기 복제**: 일관성 보장, 성능 부담
- 실시간 모니터링 및 `replication lag` 체크는 필수
- 예: `SHOW SLAVE STATUS` (MySQL 기준)

### 4. **운영 및 유지보수 용이성**

- 슬레이브 노드를 활용해 **백업 시 서비스 영향 최소화**
- 슬레이브에 대해 **보고서/분석 쿼리 분리** 가능
- 무중단 배포(Rolling Update) 전략과 결합 시 유용

---

## 클라우드 환경에서의 적용 예시

| 클라우드 | 서비스 이름 | 특성 |
|----------|--------------|------|
| AWS      | RDS Read Replica / Aurora Replicas | 자동 복제, 장애 전환 지원 |
| GCP      | Cloud SQL Read Replica | SLA 기반 고가용성 |
| Azure    | SQL Database Geo-Replication | 지리적 이중화, DR 대응 |

> 실제 서비스에서는 **리더-팔로워(Leader-Follower)** 또는 **Primary-Replica** 용어도 혼용되어 사용

</details>


### 김성휘
<details>
<summary>클라우드 내부망과 외부망</summary>

### 내부망

1.  정의 : 클라우드 서비스 제공자(나)가 제공하는 네트워크 안에서 같은 데이터 센터(공유기, 랜카드...) 또는 VPC(가상 사설망) 내의 자원끼리 통신하는 전용 네트워크
2. 특징
- 보안성 높음 : 외부 인터넷을 거치지 않기 때문에 패킷 노출 위험도 낮음
- 속도 안정적 : 인터넷을 우회하지 않고 클라우드 데이터센터 내부망을 사용하므로 지연이 낮고 속도가 빠름
- 과금 방식 : 내부 트래픽은 대부분 무료 또는 저렴한 과금
3. 주 용도
- 클라우드 서버 간 통신
- 스토리지와 인스턴스 간 통신
- 보안이 중요한 데이터 전송
- 시스템 간 API 호출


### 외부망
 
1. 정의 : 클라우드 자원(서버, 스토리지 등)이 인터넷을 통해 외부 사용자와 통신하는 네트워크
2. 특징 
- 접근성 뛰어남 : 인터넷이 연결된 곳이라면 어디든 접속 가능. 웹사이트, 모바일 앱, API등이 이 경로를 통해 서비스 제공
- 보안성 낮음 : 외부 인터넷을 통해 연결되므로, 해킹·DDoS 등 위험 노출이 큼. 보안 그룹, 방화벽, VPN, 암호화 등이 필수
- 속도 및 지연 다양 : 인터넷 환경, 지역, 네트워크 상태에 따라 속도가 달라짐
3. 주 용도
- 웹사이트, 앱 서비스 제공
- 외부 API 통신
- 사용자 요청 처리
- 파일 다운로드/업로드 서비스
</details>
<details>
<summary>로드밸런싱의 종류와 특징</summary>

  ### Round Robin

1. 동작 방식
>  1. 사용자가 서버에 요청을보냄
>  2. 로드밸런서는 준비된 서버 목록을 순서대로 돌며 요청을 배분
>  3. 마지막에 배분된 서버 다음 서버부터 다시 요청을 넘깁니다
>  4. 서버 수만큼 순환을 반복합니다.

2. 장점
> 1. 구현이 매우 간단함
> 2. 공평한 분배로 서버가 비슷한 성능일 때 효율적으로 작동
> 3. 별다른 계산 없이 <b>순차적 요청 분배</b>

3. 단점
> 1. 각 서버의 부하 상태를 고려하지 않음
> 2. 서버 처리 속도가 느릴수록 과부하 발생 가능
> 3. 가중치가 없는 순수한 Round Robin은 비균형을 초래할 수 있음

4. 한줄 요약
> 차례로 순환 배분하는 방식, 간단하지만 서버 부하를 고려하지 않으므로 상황에 따라 가중치를 주는 방식을 통해 개선 가능


  ### Weighted Round Robin

1. 동작 방식
>  RoundRobin과 다르게 서버마다 가중치를 설정해 서버의 성능이나 처리 능력에 맞춰 비율적으로 요청을 배분

2. 장점
> 1. 서버 성능을 고려해서 부하를 균형 있게 분배
> 2. 느린 서버는 적게, 빠른 서버는 많이 -> 리소스 낭비 방지 가능
> 3. 시스템 전체 성능이 고르게 유지됨

3. 단점
> 1. 가중치를 미리 정확히 설정해야 함(잘못된 설정은 오히려 부하 쏠림 현상 발생)
> 2. 서버 성능이 동적 변화할 경우 가중치가 고정되어 비효율
> 3. 일반 Round Robin 보다 구현이 복잡

4. 한줄 요약
>  서버 성능을 고려해 요청을 비례 분배한는 방식으로 공평성과 효율을 챙길 수 있지만, 조건에 따라 역효과가 일어날 수 있다

  ### Least Connection

1. 동작 방식
>  현재 연결된 요청이 가장 적은 서버에 새로운 요청을 할당하는 방식

2. 장점
> 1. 서버 부하가 실시간으로 반영, 연결이 적은 서버에만 요청을 주기 때문에 부하 분산이 자연스럽고 효율적
> 2. 서버 성능이 동일하지 않아도 부하 균형 유지 가능
> 3. 고정 가중치 없이도 자동 최적화 됨

3. 단점
> 1. 연결 수만 보고 판단 -> 요청 처리 시간은 고려하지 않음
> 2. 연결 해제가 늦은 경우 서버 상태를 완벽하게 반영하지 못함
> 3. 세션 지속성이 필요할 경우 복잡해질 수 있음

4. 한줄 요약
>  현재 연결 수가 가장 적은 서버에 요청을 배분하여, 부하를 실시간으로 고르게 유지하는 로드밸런싱 방식

  ###  IP Hash

1. 동작 방식
> 1. 클라이언트의 IP 주소를 해시함수로 변환합니다
> 2. 나온 해시 값에 따라 서버를 선택합니다.
> 3. 같은 IP는 항상 같은 서버로 요청을 보냅니다.

2. 장점
> 1. 같은 사용자가 항상 같은 서버에 배정되 세션 지속성 보장받음
> 2. IP만으로 서버를 결정해 구현 방법 간단
> 3. DB없이 고정 분배가 가능, 중앙 세션서버 필요없음

3. 단점
> 1. 일부 IP 대역이 몰리면 특정 서버 과부하
> 2. 서버 추가/삭제하면 해시 분포가 바뀌어 기존 연결이 다른 서버로 바뀌어 세션이 끊길 수 있음
> 3. 프록시 환경에서 IP가 같으면 여러 사용자가 같은 서버로 몰릴 위험

4. 한줄요약
> IP Hash는 클라이언트 IP를 해시 계산하여 특정 서버에 고정 분배하는 방식으로, 세션 유지에 유리하지만 서버 추가/삭제 시 분배 불균형이 생길 수 있다!

  ###  Response Time

1. 동작 방식
> 1. 로드밸런서는 서버들의 응답 속도를 주기적으로 체크합니다.
> 2. 사용자의 요청이 도착하면 최근 응답이 가장 빠른 서버로 요청을 보냅니다.

2. 장점
> 1. 실시간 서버 성능 반영 현재 가장 여유 있는 서버에 요청 전달
> 2. 부하 분산 최적화 바쁜 서버는 자동으로 요청이 줄고, 한가한 서버가 더 많은 요청을 받음
> 3. 특별한 설정 필요 없음 단순히 응답 속도를 기반으로 판단

3. 단점
> 1. 응답 시간은 네트워크 지연, 일시적 장애에 영향을 받아서 부정확할 수 있음
> 2. 실제로는 짧은 응답이 무거운 연산을 준비 중일 수도 있음
> 3. 지속적인 서버 상태 모니터링 필요

4. 한줄 요약
> 서버 응답 속도를 기준으로 가장 빠른 서버에 요청을 분배하는 방식, 실시간 부하에 민감하게 반응하지만 네트워크 상태나 측정 정확도에 영향을 받을 수 있다

  ### Failover

1. 동작 방식
> 1. 서버, 데이터베이스, 네트워크를 모니터링해서 정상 작동 중인지 확인
> 2. 서버가 다운되거나 응답 없을 때 미리 대기 해둔 서버로 서비스 트래픽이 자동 전환
> 3. 장애가 발생해도 정상 서비스처럼 동작

2. 장점
> 1. 장애가 발생해도 중단 없는 서비스
> 2. 다운 타임 최소화
> 3. 관리자가 없어도 자동 전환

3. 단점
> 1. 항상 대기 상태의 서버가 필요해 비용이 추가 발생
> 2. 전환 과정이 순간적이지 않음, 복구 시간 존재
> 3. 복잡한 환경 구성 필요

4. 한줄 요약
> 서버 장애 발생 시 자동으로 예비 서버로 전환하여, 서비스가 중단되지 않게 유지하는 고가용성(HA) 기술
</details>
