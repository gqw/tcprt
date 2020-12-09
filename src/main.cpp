
#include <winsock2.h>  
#include <Ws2def.h>
#include <ws2ipdef.h>
#include <ws2tcpip.h>
#include <Mstcpip.h>
#include <windows.h>

#pragma comment(lib,"ws2_32.lib") 

#include <iostream>
#include <string>
#include <sstream>
#include <thread>
#include <future>
#include <ctime>
#include <map>


std::atomic_bool g_is_stoped = false;

class ipv4_header
{
public:
  ipv4_header() { std::fill(rep_, rep_ + sizeof(rep_), 0); }

  unsigned char version() const { return (rep_[0] >> 4) & 0xF; }
  unsigned short header_length() const { return (rep_[0] & 0xF) * 4; }
  unsigned char type_of_service() const { return rep_[1]; }
  unsigned short total_length() const { return decode(2, 3); }
  unsigned short identification() const { return decode(4, 5); }
  bool dont_fragment() const { return (rep_[6] & 0x40) != 0; }
  bool more_fragments() const { return (rep_[6] & 0x20) != 0; }
  unsigned short fragment_offset() const { return decode(6, 7) & 0x1FFF; }
  unsigned int time_to_live() const { return rep_[8]; }
  unsigned char protocol() const { return rep_[9]; }
  unsigned short header_checksum() const { return decode(10, 11); }
  std::string source_ip() const { 
      char ip[64] {};
      unsigned int iip = (*((unsigned int*)&rep_[12]));
      inet_ntop(AF_INET, (const void*)&iip, ip, 64);
      return ip;
  }
  std::string dest_ip() const { 
      char ip[64] {};
      unsigned int iip = (*((unsigned int*)&rep_[16]));
      inet_ntop(AF_INET, (const void*)&iip, ip, 64);
      return ip;
  }


  friend std::istream& operator>>(std::istream& is, ipv4_header& header)
  {
    is.read(reinterpret_cast<char*>(header.rep_), 20);
    if (header.version() != 4)
      is.setstate(std::ios::failbit);
    std::streamsize options_length = header.header_length() - 20;
    if (options_length < 0 || options_length > 40)
      is.setstate(std::ios::failbit);
    else
      is.read(reinterpret_cast<char*>(header.rep_) + 20, options_length);
    return is;
  }

  friend std::ostream& operator<<(std::ostream& os, const ipv4_header& header)
  {
      os << std::endl;
      os << "ip header: " << std::endl;
      os << "  version: " << (int)header.version() << std::endl;
      os << "  header length: " << header.header_length() << std::endl;
      os << "  type of service: " << (int)header.type_of_service() << std::endl;
      os << "  total length: " << header.total_length() << std::endl;
      os << "  identification: " << header.identification() << std::endl;
      os << "  dont fragment: " << header.dont_fragment() << std::endl;
      os << "  more fragments: " << header.more_fragments() << std::endl;
      os << "  offset: " << header.fragment_offset() << std::endl;
      os << "  ttl: " << header.time_to_live() << std::endl;
      os << "  protocol: " << (int)header.protocol() << std::endl;
      os << "  src ip: " << header.source_ip() << std::endl;
      os << "  dst ip: " << header.dest_ip() << std::endl;
      return os;
  }

private:
  unsigned short decode(int a, int b) const
    { return (rep_[a] << 8) + rep_[b]; }

  unsigned char rep_[60];
};

class icmp_header
{
public:
  enum { echo_reply = 0, destination_unreachable = 3, source_quench = 4,
    redirect = 5, echo_request = 8, time_exceeded = 11, parameter_problem = 12,
    timestamp_request = 13, timestamp_reply = 14, info_request = 15,
    info_reply = 16, address_request = 17, address_reply = 18 };

  icmp_header() { std::fill(rep_, rep_ + sizeof(rep_), 0); }

  unsigned char type() const { return rep_[0]; }
  unsigned char code() const { return rep_[1]; }
  unsigned short checksum() const { return decode(2, 3); }
  unsigned short identifier() const { return decode(4, 5); }
  unsigned short sequence_number() const { return decode(6, 7); }

  void type(unsigned char n) { rep_[0] = n; }
  void code(unsigned char n) { rep_[1] = n; }
  void checksum(unsigned short n) { encode(2, 3, n); }
  void identifier(unsigned short n) { encode(4, 5, n); }
  void sequence_number(unsigned short n) { encode(6, 7, n); }

  friend std::istream& operator>>(std::istream& is, icmp_header& header)
    { return is.read(reinterpret_cast<char*>(header.rep_), 8); }

  friend std::ostream& operator<<(std::ostream& os, const icmp_header& header) {
      os << std::endl;
      os << "icmp header: " << std::endl;
      os << " type: " << (int)header.type() << std::endl;
      os << " code: " << (int)header.code() << std::endl;
      os << " identifier: " << header.identifier() << std::endl;
      os << " sequence_number: " << header.sequence_number() << std::endl;
      return os;
  }
    // { return os.write(reinterpret_cast<const char*>(header.rep_), 8); }

private:
  unsigned short decode(int a, int b) const
    { return (rep_[a] << 8) + rep_[b]; }

  void encode(int a, int b, unsigned short n)
  {
    rep_[a] = static_cast<unsigned char>(n >> 8);
    rep_[b] = static_cast<unsigned char>(n & 0xFF);
  }

  unsigned char rep_[8];
};

class tcpv4_header
{
public:
  tcpv4_header() { std::fill(rep_, rep_ + sizeof(rep_), 0); }

  unsigned short source_port() const { return decode(0, 1); }
  unsigned short dest_port() const { return decode(2, 3); }

  unsigned int sequence() const { return decode_int(4, 7); }
  unsigned int acknowledgment () const { return decode_int(8, 11); }

  unsigned short flags() const { return decode(12, 13); }
  unsigned short window_size() const { return decode(14, 15); }
  
  unsigned short checksum() const { return decode(16, 17); }
  unsigned short urgent () const { return decode(18, 19); }


  friend std::istream& operator>>(std::istream& is, tcpv4_header& header)
  {
    is.read(reinterpret_cast<char*>(header.rep_), 20);
    return is;
  }

  friend std::ostream& operator<<(std::ostream& os, const tcpv4_header& header)
  {
      os << std::endl;
      os << "ip header: " << std::endl;
      os << "  source_port: " << (int)header.source_port() << std::endl;
      os << "  dest_port: " << header.dest_port() << std::endl;
      os << "  sequence: " << (int)header.sequence() << std::endl;
      os << "  acknowledgment: " << header.acknowledgment() << std::endl;
      os << "  flags: " << header.flags() << std::endl;
      os << "  window_size: " << header.window_size() << std::endl;
      os << "  checksum: " << header.checksum() << std::endl;
      os << "  urgent: " << header.urgent() << std::endl;
      return os;
  }

private:
  unsigned short decode(int a, int b) const
    { return (rep_[a] << 8) + rep_[b]; }

  unsigned short decode_int(int a, int b) const
    { return (rep_[a] << 24) + (rep_[a + 1] << 16) + (rep_[a + 2] << 8) + rep_[b]; }

  unsigned char rep_[60];
};

struct ResultType {
    int ttl = 0;
    bool result = false;
    std::time_t cost_time = 0;
    std::string route_addr;
};

ResultType trace(const std::string& srcip, const std::string& dstip, uint16_t dstport, uint16_t ttl) {
    ResultType result{ttl, false, 0};
    auto tcp_sk = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (tcp_sk < 0) {
        std::cout << "tcp socket create failed." << std::endl;

        shutdown(tcp_sk, SD_BOTH);
        closesocket(tcp_sk);
        return result;
    }
    // set ttl value
    if (setsockopt (tcp_sk, IPPROTO_IP, IP_TTL, (char*)&ttl, sizeof (ttl)) < 0) {
        std::cout << "set raw socket ttl failed."  << errno << std::endl;
        shutdown(tcp_sk, SD_BOTH);
        closesocket(tcp_sk);        
        return result;
    }

    // non block mode
    u_long iMode = 1;
    auto ret = ioctlsocket(tcp_sk, FIONBIO, &iMode);
    if (ret == SOCKET_ERROR) {
        std::cout << "set socket option failed, err: " << GetLastError() << std::endl;
        shutdown(tcp_sk, SD_BOTH);
        closesocket(tcp_sk);        
        return result;
    }

    // just occupy the tcp port
    sockaddr_in src_addr;
    src_addr.sin_family = AF_INET;
    src_addr.sin_port = 0;
    int src_addr_len = sizeof(src_addr);
    inet_pton(AF_INET, "0.0.0.0",  (char*)&src_addr.sin_addr);
    bind(tcp_sk, (sockaddr*)&src_addr, src_addr_len);
    getsockname(tcp_sk, (sockaddr*)&src_addr, &src_addr_len);
    auto localport = ntohs(src_addr.sin_port);

    // create tcp raw socket
    auto raw_sk = socket(AF_INET, SOCK_RAW, IPPROTO_IP);
    if (raw_sk < 0) {
        std::cout << "socket create failed, err: " << GetLastError() << std::endl;
        return result;
    }

    sockaddr_in raw_src_addr{};
    raw_src_addr.sin_family = AF_INET;
    raw_src_addr.sin_port = 0;
    inet_pton(AF_INET, srcip.c_str(), (char*)&raw_src_addr.sin_addr);
    ret = bind(raw_sk, (sockaddr*)&raw_src_addr, sizeof(raw_src_addr));
    if (ret == -1) {
        std::cout << "raw bind failed." << GetLastError() << std::endl;

        shutdown(tcp_sk, SD_BOTH);
        closesocket(tcp_sk);

        shutdown(raw_sk, SD_BOTH);
        closesocket(raw_sk);       
        return result;
    }
    int in = 0;
	int j=1;
	if (WSAIoctl(raw_sk, SIO_RCVALL, &j, sizeof(j), 0, 0, (LPDWORD) &in , 0 , 0) == SOCKET_ERROR)
	{
        shutdown(tcp_sk, SD_BOTH);
        closesocket(tcp_sk);

        shutdown(raw_sk, SD_BOTH);
        closesocket(raw_sk);        
		return result;
	}

    auto before = std::chrono::system_clock::now();
    auto do_end_func = [&](const std::string& route_addr) {
        shutdown(tcp_sk, SD_BOTH);
        closesocket(tcp_sk);

        shutdown(raw_sk, SD_BOTH);
        closesocket(raw_sk);
        result.result = true;
        result.route_addr = route_addr; // ipv4_hdr.source_ip();     
        auto after = std::chrono::system_clock::now();
        result.cost_time = std::chrono::duration_cast<std::chrono::milliseconds>(after - before).count();
    };

    sockaddr_in dst_addr;
    dst_addr.sin_family = AF_INET;
    dst_addr.sin_port = htons(dstport);
    inet_pton(AF_INET, dstip.c_str(),  (char*)&dst_addr.sin_addr);
    auto dstconn = connect(tcp_sk, (sockaddr*)&dst_addr, sizeof(dst_addr));

    char buf[65535]{};
    do
    {
        if (g_is_stoped) {
            break;
        }
        auto rcvret = recv(raw_sk, buf, 65535, 0);
        if (rcvret < 0) {
            std::cout << "recv icmp failed. " << GetLastError() << std::endl;
            continue;
        }

        std::istringstream is(std::string(buf, rcvret));
        ipv4_header ipv4_hdr;
        is >> ipv4_hdr;
        if (ipv4_hdr.protocol() == IPPROTO_TCP) {
            tcpv4_header tcp_header;
            is >> tcp_header;
            if (tcp_header.dest_port() != localport) {
                continue;
            }
            do_end_func(ipv4_hdr.source_ip());
            break;
        } else if (ipv4_hdr.protocol() != IPPROTO_ICMP) {
            continue;
        }
        icmp_header icmp_hdr;
        is >> icmp_hdr;

        if (icmp_hdr.type() != 11 || icmp_hdr.code() != 0) {
            continue;
        }
        ipv4_header src_ipv4_hdr;
        is >> src_ipv4_hdr;

        if (src_ipv4_hdr.protocol() != 6) {
            continue;
        }      
        tcpv4_header tcp_header;
        is >> tcp_header;

        // std::cout << std::this_thread::get_id() << "    ttl: " << ttl << " port: "<< tcp_header.source_port() << std::endl;
        if (tcp_header.source_port() != localport) {
            continue;
        }
        do_end_func(ipv4_hdr.source_ip());
        break;
    } while (true);
    return result;
}

int main(int argc, char* argv[]) {
    uint16_t startttl = 1;
    uint16_t maxttl = 30;
    uint16_t dstport = 80;
    std::string dstip = "180.101.49.11"; 
    std::string srcip = "192.168.80.37";
    if (argc > 1) {
        dstip = argv[1];
    }
    if (argc > 2) {
        dstport = (uint16_t)std::stol(argv[2]);
    }
    if (argc > 3) {
        maxttl = (uint16_t)std::stol(argv[3]);
    }

    WSADATA Data; 
    auto status = WSAStartup(MAKEWORD(1, 1), &Data);  
    if (status != 0)  {
        std::cout << "ERROR: WSAStartup unsuccessful" << std::endl;
        return 1;
    }
    std::vector<std::future<ResultType>> futures;
    for (int i = startttl; i <= maxttl; ++i) {
        // 3 times every ttl
        for (int n = 0; n < 3; ++n) {
            futures.push_back(std::async([](const std::string& srcip, const std::string& dstip, uint16_t dstport, uint16_t ttl) -> ResultType {
                // std::cout << "enter ttl: " << ttl << std::endl;
                return trace(srcip, dstip, dstport, ttl);
            }, srcip, dstip, dstport, i));
        }
    }

    std::map<uint16_t, std::vector<ResultType>> results;
    auto wait_start = std::chrono::system_clock::now();
    int i = 0;
    for (auto &&f : futures)
    {
        i++;
        auto now = std::chrono::system_clock::now();
        auto seconds = std::chrono::duration_cast<std::chrono::seconds>(now - wait_start).count();

        auto status = f.wait_for(std::chrono::seconds(seconds > 5 ? 0 : 5 - seconds));
        if (status == std::future_status::timeout) {
            // std::cerr <<  "index: " << i << " timeout" << std::endl;
            continue;
        }
        auto ret = f.get();
        results[ret.ttl].push_back(ret);
    }
    g_is_stoped = true; // stop all timeout probes

    // finnally, print the result
    std::stringstream ss;
    ss << std::endl;
    ss << "traceroute to " << dstip << ", " << maxttl << " hops max" << std::endl;
    // for (auto &&iter : results)
    for (int i  = startttl; i < maxttl; ++i)
    {
        auto iter = results.find(i);
        if (iter == results.end()) {
            ss << i << "\t*\t*\t*"  "\tRequest timeout" << std::endl;
            continue;
        }
        std::string last_route;
        std::vector<std::string> routes;
        ss << iter->first;
        
        // for (auto &&r : iter->second)
        for (int i = 0; i < 3; ++i)
        {
            if (i >= (int)iter->second.size()) {
                ss << "\t*";
                continue;
            }
            const auto& r = iter->second[i];
            if (r.result == false) {
                ss << "\t*";
            } else {
                ss << "\t" << r.cost_time << "ms";
                if (last_route.empty()) {
                    if (!r.route_addr.empty()) {
                        routes.push_back(r.route_addr);
                        last_route = r.route_addr;
                    }
                } else {
                    if (last_route != r.route_addr) {
                        routes.push_back(r.route_addr);
                        last_route = r.route_addr;
                    }
                }
            }
        }

        if (routes.empty()) {
            ss << "\tRequest timeout" << std::endl;
        } else {
            for (auto &&r : routes)
            {
                ss << "\t" << r << "\t";
            }
            ss << std::endl;
        }
        if (last_route == dstip) {
            // arrive destinct address, break loop
            break;    
        }
    }
    std::cout << ss.str() << std::endl;
    return 0;
}