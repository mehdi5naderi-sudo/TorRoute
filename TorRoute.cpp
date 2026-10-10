#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <wininet.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <algorithm>
#include <atomic>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <thread>
#include <vector>
#pragma comment(lib,"ws2_32.lib")
#pragma comment(lib,"wininet.lib")
static const char* RULES="rules.txt"; static const char* CONFIG="config.txt"; static const char* PIDFILE="TorRoute.pid"; static const char* BACKUP="TorRoute.proxy.bak";
static std::atomic<bool> g_stop(false); static std::string g_listenHost="127.0.0.1",g_torHost="127.0.0.1"; static int g_listenPort=18080,g_torPort=9050;
static std::string trim(std::string s){while(!s.empty()&&isspace((unsigned char)s.front()))s.erase(s.begin());while(!s.empty()&&isspace((unsigned char)s.back()))s.pop_back();return s;}
static std::string lower(std::string s){std::transform(s.begin(),s.end(),s.begin(),[](unsigned char c){return(char)tolower(c);});return s;}
static std::string normalizeDomain(std::string s){s=lower(trim(s));if(s.rfind("http://",0)==0)s=s.substr(7);if(s.rfind("https://",0)==0)s=s.substr(8);while(!s.empty()&&s.back()=='/')s.pop_back();auto p=s.find('/');if(p!=std::string::npos)s=s.substr(0,p);return s;}
static bool readEndpoint(const std::string&s,std::string&h,int&p){auto x=s.rfind(':');if(x==std::string::npos)return false;h=trim(s.substr(0,x));p=atoi(s.substr(x+1).c_str());return !h.empty()&&p>0&&p<65536;}
static void loadConfig(){std::ifstream f(CONFIG);std::string l;while(std::getline(f,l)){l=trim(l);if(l.empty()||l[0]=='#')continue;auto p=l.find('=');if(p==std::string::npos)continue;auto k=lower(trim(l.substr(0,p))),v=trim(l.substr(p+1));if(k=="listen")readEndpoint(v,g_listenHost,g_listenPort);if(k=="tor")readEndpoint(v,g_torHost,g_torPort);}}
static std::vector<std::string> rules(){std::vector<std::string>r;std::ifstream f(RULES);std::string s;while(std::getline(f,s)){s=normalizeDomain(s);if(!s.empty()&&s[0]!='#')r.push_back(s);}return r;}
static bool matchRule(const std::string&host){std::string h=normalizeDomain(host);for(auto&r:rules()){if(r.rfind("*.",0)==0){auto b=r.substr(2);if(h==b||(h.size()>b.size()+1&&h.compare(h.size()-b.size(),b.size(),b)==0&&h[h.size()-b.size()-1]=='.'))return true;}else if(h==r)return true;}return false;}
static bool sendAll(SOCKET s,const char*p,int n){while(n>0){int k=send(s,p,n,0);if(k<=0)return false;p+=k;n-=k;}return true;}
static bool recvHeaders(SOCKET s,std::string&out){char b[8192];out.clear();for(int i=0;i<8;i++){int n=recv(s,b,sizeof(b),0);if(n<=0)break;out.append(b,n);if(out.find("\r\n\r\n")!=std::string::npos)break;if(out.size()>65536)break;}return !out.empty();}
static SOCKET tcpConnect(const std::string&host,int port){addrinfo h{},*r=nullptr;h.ai_socktype=SOCK_STREAM;h.ai_family=AF_UNSPEC;char ps[16];sprintf_s(ps,"%d",port);if(getaddrinfo(host.c_str(),ps,&h,&r)!=0)return INVALID_SOCKET;SOCKET s=INVALID_SOCKET;for(auto*p=r;p;p=p->ai_next){s=socket(p->ai_family,p->ai_socktype,p->ai_protocol);if(s==INVALID_SOCKET)continue;if(connect(s,p->ai_addr,(int)p->ai_addrlen)==0)break;closesocket(s);s=INVALID_SOCKET;}freeaddrinfo(r);return s;}
static bool socks5Connect(SOCKET s,const std::string&host,int port){unsigned char hello[]={5,1,0},rep[2];if(!sendAll(s,(char*)hello,3)||recv(s,(char*)rep,2,MSG_WAITALL)!=2||rep[1]!=0)return false;std::vector<unsigned char>q{5,1,0};in_addr a4{};in6_addr a6{};if(inet_pton(AF_INET,host.c_str(),&a4)==1){q.push_back(1);auto*p=(unsigned char*)&a4;q.insert(q.end(),p,p+4);}else if(inet_pton(AF_INET6,host.c_str(),&a6)==1){q.push_back(4);auto*p=(unsigned char*)&a6;q.insert(q.end(),p,p+16);}else{if(host.size()>255)return false;q.push_back(3);q.push_back((unsigned char)host.size());q.insert(q.end(),host.begin(),host.end());}unsigned short np=(unsigned short)port;q.push_back((unsigned char)(np>>8));q.push_back((unsigned char)np);if(!sendAll(s,(char*)q.data(),(int)q.size()))return false;unsigned char head[4];if(recv(s,(char*)head,4,MSG_WAITALL)!=4||head[1]!=0)return false;int n=head[3]==1?4:(head[3]==4?16:0);if(head[3]==3){unsigned char l;if(recv(s,(char*)&l,1,MSG_WAITALL)!=1)return false;n=l;}if(n){std::vector<char>x(n);if(recv(s,x.data(),n,MSG_WAITALL)!=n)return false;}char pb[2];return recv(s,pb,2,MSG_WAITALL)==2;}
static bool parseHostPort(const std::string&s,std::string&h,int&p){auto x=s.rfind(':');if(x==std::string::npos)return false;h=s.substr(0,x);p=atoi(s.substr(x+1).c_str());return !h.empty()&&p>0&&p<65536;}
static void relay(SOCKET a,SOCKET b){char buf[16384];while(!g_stop){fd_set r;FD_ZERO(&r);FD_SET(a,&r);FD_SET(b,&r);timeval tv{1,0};if(select(0,&r,nullptr,nullptr,&tv)<=0)continue;if(FD_ISSET(a,&r)){int n=recv(a,buf,sizeof(buf),0);if(n<=0)break;if(!sendAll(b,buf,n))break;}if(FD_ISSET(b,&r)){int n=recv(b,buf,sizeof(buf),0);if(n<=0)break;if(!sendAll(a,buf,n))break;}}}
static void handleClient(SOCKET c){std::string req;if(!recvHeaders(c,req)){closesocket(c);return;}auto e=req.find("\r\n");if(e==std::string::npos){closesocket(c);return;}std::string first=req.substr(0,e),method,target,ver;std::istringstream iss(first);iss>>method>>target>>ver;std::string host;int port=80;bool isConnect=lower(method)=="connect";if(isConnect){if(!parseHostPort(target,host,port)){closesocket(c);return;}}else{size_t hp=req.find("\r\nHost:");if(hp==std::string::npos)hp=req.find("\r\nhost:");if(hp!=std::string::npos){auto q=req.find('\n',hp+2);std::string hv=trim(req.substr(hp+6,q-(hp+6)));if(!parseHostPort(hv,host,port)){host=hv;port=80;}}}if(host.empty()){closesocket(c);return;}SOCKET up=INVALID_SOCKET;if(matchRule(host)){up=tcpConnect(g_torHost,g_torPort);if(up!=INVALID_SOCKET&&!socks5Connect(up,host,port)){closesocket(up);up=INVALID_SOCKET;}}else up=tcpConnect(host,port);if(up==INVALID_SOCKET){const char*x="HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n";sendAll(c,x,(int)strlen(x));closesocket(c);return;}if(isConnect){const char*x="HTTP/1.1 200 Connection Established\r\n\r\n";if(!sendAll(c,x,(int)strlen(x))){closesocket(up);closesocket(c);return;}}else if(!sendAll(up,req.data(),(int)req.size())){closesocket(up);closesocket(c);return;}relay(c,up);closesocket(up);closesocket(c);}
static unsigned __stdcall serverThread(void*){SOCKET s=socket(AF_INET,SOCK_STREAM,IPPROTO_TCP);if(s==INVALID_SOCKET)return 1;int yes=1;setsockopt(s,SOL_SOCKET,SO_REUSEADDR,(char*)&yes,sizeof(yes));sockaddr_in a{};a.sin_family=AF_INET;a.sin_port=htons((u_short)g_listenPort);inet_pton(AF_INET,g_listenHost.c_str(),&a.sin_addr);if(bind(s,(sockaddr*)&a,sizeof(a))!=0||listen(s,64)!=0){closesocket(s);return 2;}while(!g_stop){fd_set r;FD_ZERO(&r);FD_SET(s,&r);timeval tv{1,0};if(select(0,&r,nullptr,nullptr,&tv)>0){SOCKET c=accept(s,nullptr,nullptr);if(c!=INVALID_SOCKET)std::thread(handleClient,c).detach();}}closesocket(s);return 0;}
static std::string regGet(HKEY k,const char*n){DWORD t=0,z=0;if(RegQueryValueExA(k,n,nullptr,&t,nullptr,&z)!=ERROR_SUCCESS)return "<missing>";std::string s(z,'\0');if(RegQueryValueExA(k,n,nullptr,&t,(BYTE*)s.data(),&z)!=ERROR_SUCCESS)return "<missing>";while(!s.empty()&&s.back()=='\0')s.pop_back();return s;}
static void saveProxy(){HKEY k;if(RegOpenKeyExA(HKEY_CURRENT_USER,"Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings",0,KEY_READ,&k)!=ERROR_SUCCESS)return;std::ofstream f(BACKUP);f<<"ProxyEnable="<<regGet(k,"ProxyEnable")<<"\n";f<<"ProxyServer="<<regGet(k,"ProxyServer")<<"\n";f<<"ProxyOverride="<<regGet(k,"ProxyOverride")<<"\n";f<<"AutoConfigURL="<<regGet(k,"AutoConfigURL")<<"\n";RegCloseKey(k);}
static void setProxy(bool on){HKEY k;if(RegOpenKeyExA(HKEY_CURRENT_USER,"Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings",0,KEY_SET_VALUE|KEY_QUERY_VALUE,&k)!=ERROR_SUCCESS)throw std::runtime_error("Cannot access current-user Internet Settings");if(on){saveProxy();DWORD one=1;RegSetValueExA(k,"ProxyEnable",0,REG_DWORD,(BYTE*)&one,sizeof(one));std::string ps="http="+g_listenHost+":"+std::to_string(g_listenPort)+";https="+g_listenHost+":"+std::to_string(g_listenPort);RegSetValueExA(k,"ProxyServer",0,REG_SZ,(BYTE*)ps.c_str(),(DWORD)ps.size()+1);std::string ov="<local>";RegSetValueExA(k,"ProxyOverride",0,REG_SZ,(BYTE*)ov.c_str(),(DWORD)ov.size()+1);}else{std::ifstream f(BACKUP);std::string line;while(std::getline(f,line)){auto p=line.find('=');if(p==std::string::npos)continue;auto n=line.substr(0,p),v=line.substr(p+1);if(v=="<missing>"){RegDeleteValueA(k,n.c_str());continue;}if(n=="ProxyEnable"){DWORD d=atoi(v.c_str());RegSetValueExA(k,n.c_str(),0,REG_DWORD,(BYTE*)&d,sizeof(d));}else RegSetValueExA(k,n.c_str(),0,REG_SZ,(BYTE*)v.c_str(),(DWORD)v.size()+1);}DeleteFileA(BACKUP);}RegCloseKey(k);InternetSetOptionA(nullptr,INTERNET_OPTION_SETTINGS_CHANGED,nullptr,0);InternetSetOptionA(nullptr,INTERNET_OPTION_REFRESH,nullptr,0);}
static bool pidRunning(){std::ifstream f(PIDFILE);DWORD p=0;f>>p;if(!p)return false;HANDLE h=OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION,FALSE,p);if(!h)return false;DWORD code=0;GetExitCodeProcess(h,&code);CloseHandle(h);return code==STILL_ACTIVE;}
static DWORD readPid(){std::ifstream f(PIDFILE);DWORD p=0;f>>p;return p;}
static void writePid(){std::ofstream f(PIDFILE);f<<GetCurrentProcessId();}
static int addRule(const std::string&d){auto x=normalizeDomain(d);if(x.empty())return 1;auto r=rules();if(std::find(r.begin(),r.end(),x)==r.end()){std::ofstream f(RULES,std::ios::app);f<<x<<"\n";}return 0;}
static int removeRule(const std::string&d){auto x=normalizeDomain(d);std::ifstream f(RULES);std::vector<std::string>v;std::string s;while(std::getline(f,s))if(normalizeDomain(s)!=x)v.push_back(s);std::ofstream o(RULES);for(auto&q:v)o<<q<<"\n";return 0;}
static int start(){loadConfig();if(pidRunning()){std::cout<<"Already running.\n";return 0;}setProxy(true);STARTUPINFOA si{};si.cb=sizeof(si);PROCESS_INFORMATION pi{};char exe[MAX_PATH];GetModuleFileNameA(nullptr,exe,sizeof(exe));std::string c="\""+std::string(exe)+"\" run-server";std::vector<char>cc(c.begin(),c.end());cc.push_back(0);if(!CreateProcessA(nullptr,cc.data(),nullptr,nullptr,FALSE,CREATE_NO_WINDOW,nullptr,nullptr,&si,&pi)){setProxy(false);throw std::runtime_error("Could not start proxy process");}CloseHandle(pi.hThread);CloseHandle(pi.hProcess);std::cout<<"Started on "<<g_listenHost<<":"<<g_listenPort<<"\n";return 0;}
static int runServer(){loadConfig();writePid();WSADATA w;if(WSAStartup(MAKEWORD(2,2),&w)!=0)return 2;serverThread(nullptr);WSACleanup();DeleteFileA(PIDFILE);return 0;}
static int stop(){if(!pidRunning()){std::cout<<"Not running.\n";if(GetFileAttributesA(BACKUP)!=INVALID_FILE_ATTRIBUTES)setProxy(false);return 0;}HANDLE h=OpenProcess(PROCESS_TERMINATE,FALSE,readPid());if(h){TerminateProcess(h,0);CloseHandle(h);}setProxy(false);std::cout<<"Stopped; Direct proxy settings restored.\n";return 0;}
static void showStatus(){
 loadConfig();
 std::cout<<"\n========== TorRoute status ==========\n";
 std::cout<<"Service: "<<(pidRunning()?"RUNNING":"STOPPED")<<"\n";
 std::cout<<"Local proxy: "<<g_listenHost<<":"<<g_listenPort<<"\n";
 std::cout<<"Tor SOCKS5 endpoint (configured): "<<g_torHost<<":"<<g_torPort<<"\n";
 HKEY k; DWORD enabled=0,type=0,size=sizeof(enabled); std::string proxy="<unavailable>";
 if(RegOpenKeyExA(HKEY_CURRENT_USER,"Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings",0,KEY_QUERY_VALUE,&k)==ERROR_SUCCESS){
  if(RegQueryValueExA(k,"ProxyEnable",nullptr,&type,(BYTE*)&enabled,&size)!=ERROR_SUCCESS)enabled=0;
  proxy=regGet(k,"ProxyServer"); RegCloseKey(k);
 }
 std::cout<<"Windows Internet proxy: "<<(enabled?"ENABLED":"DISABLED")<<" ("<<proxy<<")\n";
 auto rr=rules(); std::cout<<"Tor-routed domains: "<<rr.size()<<"\n";
 std::cout<<"======================================\n";
}
static void showRules(){auto rr=rules();if(rr.empty()){std::cout<<"No domains configured in rules.txt.\n";return;}for(size_t i=0;i<rr.size();++i)std::cout<<" "<<(i+1)<<". "<<rr[i]<<"\n";}
static int interactiveMenu(){
 std::string choice;
 for(;;){
  showStatus();
  std::cout<<"\nChoose an action:\n"
           <<"  1) Start TorRoute\n"
           <<"  2) Stop TorRoute\n"
           <<"  3) Refresh status\n"
           <<"  4) List routed domains\n"
           <<"  5) Add a domain\n"
           <<"  6) Remove a domain\n"
           <<"  0) Exit\n"
           <<"Selection: ";
  if(!std::getline(std::cin,choice))return 0;
  choice=trim(choice);
  try{
   if(choice=="1")start();
   else if(choice=="2")stop();
   else if(choice=="3")continue;
   else if(choice=="4"){showRules();}
   else if(choice=="5"||choice=="6"){
    std::string domain;
    std::cout<<"Domain (example.com or *.example.com): ";
    if(!std::getline(std::cin,domain))return 0;
    domain=normalizeDomain(domain);
    if(domain.empty()){std::cout<<"No domain entered.\n";}
    else if(choice=="5"){addRule(domain);std::cout<<"Added (or already present): "<<domain<<"\n";}
    else {removeRule(domain);std::cout<<"Removed if present: "<<domain<<"\n";}
   }
   else if(choice=="0")return 0;
   else std::cout<<"Please choose one of the listed options.\n";
  }catch(const std::exception&e){std::cerr<<"ERROR: "<<e.what()<<"\n";}
  std::cout<<"\nPress Enter to continue...";
  std::string pause;if(!std::getline(std::cin,pause))return 0;
 }
}
static void usage(){std::cout<<"TorRoute: run without arguments for the interactive menu, or use: start | stop | status | add DOMAIN | remove DOMAIN | list\n";}
int main(int argc,char**argv){try{if(argc<2)return interactiveMenu();std::string c=lower(argv[1]);if(c=="add"&&argc>2)return addRule(argv[2]);if((c=="remove"||c=="rm")&&argc>2)return removeRule(argv[2]);if(c=="list"){showRules();return 0;}if(c=="start")return start();if(c=="run-server")return runServer();if(c=="stop")return stop();if(c=="status"){showStatus();return 0;}usage();return 0;}catch(const std::exception&e){std::cerr<<"ERROR: "<<e.what()<<"\n";return 1;}}