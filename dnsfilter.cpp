/*
 * SPDX-License-Identifier: MIT
 */

#ifndef _GNU_SOURCE
#  define _GNU_SOURCE
#endif

#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <errno.h>

#include <vector>
#include <string>
#include <iostream>
#include <iomanip>
#include <functional>
#include <map>
#include <cassert>
#include <assert.h>

#define BUFSIZE 65536

void die(const char * msg)
{
	perror(msg);
	exit(1);
}

std::ostream& operator<< (std::ostream& ostream, std::function< void(std::ostream&)> f)
{
	f(ostream);
	return ostream;
}

namespace DNS
{
	using Binary = std::vector<uint8_t>;

	using Name = std::vector<std::string>;

	namespace Type
	{
		const uint16_t A = 1;
		const uint16_t AAAA = 28;
	}

	namespace Class
	{
		const uint16_t IN = 1;
	}

	struct Query
	{
		Name q_name;
		uint16_t q_type;
		uint16_t q_class;
	};

	struct Answer
	{
		Name     r_name;
		uint16_t r_type;
		uint16_t r_class;
		uint32_t r_ttl;
		Binary   r_data;
	};

	struct Packet
	{
		uint16_t ID;
		unsigned QR 	: 1;
		unsigned OPCODE : 4;
		unsigned AA 	: 1;
		unsigned TC 	: 1;
		unsigned RD 	: 1;
		unsigned RA 	: 1;
		unsigned Z 	    : 3;
		unsigned RCODE 	: 4;

		std::vector< Query > query;
		std::vector< Answer > answer;
		std::vector< Answer > authority;
		std::vector< Answer > additional;
	};

	bool parse(const uint8_t * origin, size_t size, Packet& packet);

}

namespace DNS
{
	namespace
	{

		bool read16(const uint8_t *& data, const uint8_t * end, uint16_t & result)
		{
			if (end - data < 2)
				return false;
			result = (data[0] << 8u) | data[1];
			data += 2;
			return true;
		}

		bool read32(const uint8_t *& data, const uint8_t * end, uint32_t & result)
		{
			if (end - data < 4)
				return false;
			result = (data[0] << 24u) | (data[1] << 16u) | (data[2] << 8u) | data[3];
			data += 4;
			return true;
		}

		bool read_reference(
			uint16_t offset,
			const uint8_t * origin,
			const uint8_t * end,
			Name & name)
		{
			size_t size = end - origin;
			size_t last_offset = 0;
			// todo: detect loops

			while (true) {
				if (offset >= size)
					return false;

				uint8_t len = origin[offset++];
				if ((len & 0xc0u) == 0xc0u) {
					uint16_t off = len & 0x3f;

					if (offset == size)
						return false;
					off = (off << 8) | (origin[offset]);
					if (last_offset && off == last_offset) { // reference loop
						return false;
					}

					last_offset = offset = off;
					continue;
				}

				else if (len == 0)
					return true;

				if (len > size - offset)
					return false;

				name.emplace_back(origin + offset, origin + offset + len);

				offset += len;
			}
		}

		bool read_name(
			const uint8_t *& data,
			const uint8_t * origin,
			const uint8_t * end,
			Name& name)
		{
			while (true) {
				if (data == end)
					return false;

				uint8_t len = *data++;
				if ((len & 0xc0u) == 0xc0u) {
					uint16_t off = len & 0x3f;

					if (data == end)
						return false;
					off = (off << 8) | (*data++);
					return read_reference(off, origin, end, name);
				}

				else if (len == 0)
					return true;

				if (len > end - data)
					return false;

				name.emplace_back(data, data + len);
				data += len;
			}
		}

		bool read_query(
			const uint8_t *& data,
			const uint8_t * origin,
			const uint8_t * end,
			Query& query)
		{
			if (!read_name(data, origin, end, query.q_name))
				return false;

			if (!read16(data, end, query.q_type))
				return false;

			if (!read16(data, end, query.q_class))
				return false;

			return true;
		}

		bool read_reply(
			const uint8_t *& data,
			const uint8_t * origin,
			const uint8_t * end,
			Answer& answer)
		{
			if (!read_name(data, origin, end, answer.r_name))
				return false;

			if (!read16(data, end, answer.r_type))
				return false;

			if (!read16(data, end, answer.r_class))
				return false;

			if (!read32(data, end, answer.r_ttl))
				return false;

			uint16_t r_length;
			if (!read16(data, end, r_length))
				return false;

			if (r_length > end - data)
				return false;

			answer.r_data.assign( data, data + r_length);
			data += r_length;

			return true;
		}
	}

	bool parse(const uint8_t * origin, size_t size, Packet& packet)
	{
		const uint8_t * data = origin;
		const uint8_t * end = data + size;
		uint16_t FLAGS, QDCOUNT, ANCOUNT, NSCOUNT, ARCOUNT;

		if (!read16(data, end, packet.ID)
			|| !read16(data, end, FLAGS)
			|| !read16(data, end, QDCOUNT)
			|| !read16(data, end, ANCOUNT)
			|| !read16(data, end, NSCOUNT)
			|| !read16(data, end, ARCOUNT))
		{
			return false;
		}

		packet.QR     = (FLAGS >> 15) & 1u;
		packet.OPCODE = (FLAGS >> 11) & 0xFu;
		packet.AA     = (FLAGS >> 10) & 0x1u;
		packet.TC     = (FLAGS >> 9) & 0x1u;
		packet.RD     = (FLAGS >> 8) & 0x1u;
		packet.RA     = (FLAGS >> 7) & 0x1u;
		packet.Z      = (FLAGS >> 4) & 0x7u;
		packet.RCODE  = (FLAGS >> 0) & 0xFu;

		for (uint16_t i = 0; i < QDCOUNT; ++i) {
			Query query;

			if (!read_query(data, origin, end, query))
				return false;

			packet.query.push_back(query);
		}

		for (uint16_t i = 0; i < ANCOUNT; ++i) {
			Answer answer;

			if (!read_reply(data, origin, end, answer))
				return false;

			packet.answer.push_back(answer);
		}

		for (uint16_t i = 0; i < NSCOUNT; ++i) {
			Answer answer;

			if (!read_reply(data, origin, end, answer))
				return false;

			packet.authority.push_back(answer);
		}

		for (uint16_t i = 0; i < ARCOUNT; ++i) {
			Answer answer;

			if (!read_reply(data, origin, end, answer))
				return false;

			packet.additional.push_back(answer);
		}

		if (data != end)
			return false;

		return true;
	}

	///////////////////////////////////////////////////////////
	using NameMap = std::map<std::string, uint16_t>;

	void write16(Binary& blob, uint16_t value)
	{
		blob.push_back(value >> 8);
		blob.push_back(value);
	}

	void write32(Binary& blob, uint32_t value)
	{
		blob.push_back(value >> 24);
		blob.push_back(value >> 16);
		blob.push_back(value >> 8);
		blob.push_back(value);
	}

	std::string build_name(const Name& name, size_t off)
	{
		std::string n;
		for (size_t pos = off; pos < name.size(); ++pos) {
			if (pos != off)
				n.push_back('.');
			n.append(name[pos]);
		}
		return n;
	}

	void write_name(Binary& blob, const Name& name, NameMap& name_map)
	{
		for (size_t pos = 0; pos < name.size(); ++pos) {
			std::string n = build_name(name, pos);
			auto it = name_map.find(n);

			if (it == name_map.end()) { // not found, place
				size_t off = blob.size();
				if ((off & 0x3FFFu) == off)
					name_map.emplace(n, off);
				std::string cur_label = name[pos];

				uint8_t len = cur_label.size();
				assert(len <= 63);

				blob.push_back(len);
				blob.insert(blob.end(), cur_label.begin(), cur_label.end());
			}
			else { // write reference
				size_t off = it->second;
				blob.push_back(0xC0u | off >> 8);
				blob.push_back(off);
				return;
			}
		}

		blob.push_back(0);
	}


	void write_query(Binary& data, const Query& query, NameMap& name_map)
	{
		write_name(data, query.q_name, name_map);
		write16(data, query.q_type);
		write16(data, query.q_class);
	}

	void write_reply(Binary& data, const Answer& answer, NameMap& name_map)
	{
		uint16_t r_length = answer.r_data.size();
		assert(r_length == answer.r_data.size());

		write_name(data, answer.r_name, name_map);
		write16(data, answer.r_type);
		write16(data, answer.r_class);
		write32(data, answer.r_ttl);
		write16(data, r_length);
		data.insert( data.end(), answer.r_data.begin(), answer.r_data.end());
	}

	Binary build_packet(const Packet& packet)
	{
		Binary data;
		NameMap name_map;
		uint16_t FLAGS;
		uint16_t QDCOUNT = packet.query.size();
		uint16_t ANCOUNT = packet.answer.size();
		uint16_t NSCOUNT = packet.authority.size();
		uint16_t ARCOUNT = packet.additional.size();

		FLAGS  = static_cast<uint16_t>(packet.QR)     << 15;
		FLAGS |= static_cast<uint16_t>(packet.OPCODE) << 11;
		FLAGS |= static_cast<uint16_t>(packet.AA)     << 10;
		FLAGS |= static_cast<uint16_t>(packet.TC)     << 9;
		FLAGS |= static_cast<uint16_t>(packet.RD)     << 8;
		FLAGS |= static_cast<uint16_t>(packet.RA)     << 7;
		FLAGS |= static_cast<uint16_t>(packet.Z)      << 4;
		FLAGS |= static_cast<uint16_t>(packet.RCODE)  << 0;

		write16(data, packet.ID);
		write16(data, FLAGS);
		write16(data, QDCOUNT);
		write16(data, ANCOUNT);
		write16(data, NSCOUNT);
		write16(data, ARCOUNT);

		for (uint16_t i = 0; i < QDCOUNT; ++i) {
			write_query(data, packet.query[i], name_map);
		}

		for (uint16_t i = 0; i < ANCOUNT; ++i) {
			write_reply(data, packet.answer[i], name_map);
		}

		for (uint16_t i = 0; i < NSCOUNT; ++i) {
			write_reply(data, packet.authority[i], name_map);
		}

		for (uint16_t i = 0; i < ARCOUNT; ++i) {
			write_reply(data, packet.additional[i], name_map);
		}

		return data;
	}

	std::function< void(std::ostream&)> output_name(const DNS::Name& name)
	{
		return [name](std::ostream& ostream) {
			for (auto it = name.begin(); it != name.end(); ++it) {
				if (it != name.begin())
					ostream << "|";
				ostream << *it;
			}
		};
	}

	std::function< void(std::ostream&)> output_data(const DNS::Binary& data)
	{
		return [data](std::ostream& ostream) {
			auto fill = ostream.fill();
			ostream<< std::setfill('0') << std::hex;
			for (auto it = data.begin(); it != data.end(); ++it) {
				ostream << std::setw(2) << static_cast<unsigned>(*it);
			}
			ostream << std::dec;
			ostream.fill(fill);
		};
	}

	std::function< void(std::ostream&)> output_query( const std::vector<Query>& query, const std::string& indent)
	{
		return [query, indent](std::ostream& ostream) {
			for (auto& q : query) {
				ostream << indent << "NAME:  " << output_name(q.q_name) << '\n';
				ostream << indent << "TYPE:  " << q.q_type << '\n';
				ostream << indent << "CLASS: " << q.q_class << '\n';
			}
		};
	}

	std::function< void(std::ostream&)> output_answer(const std::vector<Answer>& answer, const std::string& indent)
	{
		return [answer, indent](std::ostream& ostream) {

			for (auto& q : answer) {
				ostream << indent << "NAME:  " << output_name(q.r_name) << '\n';
				ostream << indent << "TYPE:  " << q.r_type << '\n';
				ostream << indent << "CLASS: " << q.r_class << '\n';
				ostream << indent << "TTL: " << q.r_ttl << '\n';
				ostream << indent << "DATA: " << output_data(q.r_data) << '\n';
			}
		};
	}


	std::function< void(std::ostream&)> output_packet(const Packet& packet, const std::string& indent)
	{
		return [packet, indent](std::ostream& ostream) {
			ostream << indent << "ID: " << packet.ID << '\n';
			ostream << indent << "QR: " << packet.QR << ". query (0), or a response (1)" << '\n';
			ostream << indent << "OPCODE: " << packet.OPCODE << ". Authoritative Answer " << '\n';
			ostream << indent << "AA: " << packet.AA << '\n';
			ostream << indent << "TC: " << packet.TC << ". TrunCation" << '\n';
			ostream << indent << "RD: " << packet.RD << ". Recursion Desired" << '\n';
			ostream << indent << "RA: " << packet.RA << ". Recursion Available" << '\n';
			ostream << indent << "Z: " << packet.Z << ". Zero bit" << '\n';
			ostream << indent << "RCODE: " << packet.RCODE << ". Response code 0=ok"<< '\n';

			std::string subindent = indent + "  ";
			ostream << indent << "QUERY [" << packet.query.size() << " ]:\n" << output_query(packet.query, subindent);
			ostream << indent << "ANSWER [" << packet.answer.size() << "]:\n" << output_answer(packet.answer, subindent);
			ostream << indent << "AUTH [" << packet.authority.size() << "]:\n" << output_answer(packet.authority, subindent);
			ostream << indent << "ADDT [" << packet.additional.size() << "]:\n" << output_answer(packet.additional, subindent);
		};
	}

	std::string get_address(const Answer& ans)
	{
		if (ans.r_type == Type::A) {
			if (ans.r_data.size() == 4) {
				return inet_ntoa(*(in_addr*)ans.r_data.data());
			}
		}

		return std::string("???");
	}
}

#include <map>
#include <sstream>
#include <fstream>
#include <chrono>
#include <arpa/inet.h>

struct DnsServer
{
	struct Settings
	{
		bool ipv4;
		bool ipv6;

		uint16_t listen_port;
		std::string forward_address;
		std::chrono::duration<uint32_t> ttl;

		std::string bind;
	};


	DnsServer(const Settings& settings);
	bool load_hosts(const std::string& file_name);
	void run();

private:
	struct Address
	{
		struct sockaddr address;
		socklen_t addrlen;

		Address() {}

		Address(const sockaddr& address, socklen_t addrlen)
		: address( address )
		, addrlen (addrlen)
		{

		}

		Address(const sockaddr * address, socklen_t addrlen)
		: address( *address )
		, addrlen (addrlen)
		{

		}

		std::string ntop() const
		{
			char host[NI_MAXHOST], service[NI_MAXSERV];
			int rc;

			if ((rc = getnameinfo(&address, addrlen, host, sizeof host, service, sizeof service, NI_DGRAM | NI_NUMERICHOST | NI_NUMERICSERV)) != 0) {
				std::cerr << "unable to resolve address: " << gai_strerror(rc) << '\n';
				exit(EXIT_FAILURE);
			}

			return std::string(host) + ":" + std::string(service);
		}

	};

	struct Key
	{
		std::string name;
		uint16_t type;

		Key(const std::string& name, uint16_t type)
		: name(name)
		, type(type)
		{
		}

		bool operator<(const Key& key) const
		{
			int rc = name.compare(key.name);
			if (rc != 0)
				return rc < 0;

			return type < key.type ? true : false;
		}
	};

	struct Request
	{
		Address client_address;
		uint16_t client_id;
	};

	Settings settings_;
	std::map< uint16_t, Request > requests_;
	int sockfd_;
	Address forward_address_;
	std::multimap<Key, DNS::Binary> address_map_;
	uint16_t id_generator_;

	uint16_t request_id();
	void forward_request(const DNS::Packet& packet, uint8_t * buffer, size_t buf_size, const Address& clientaddr );
	void local_reply(const DNS::Packet& packet, const Address& clientaddr );
	void send_reply(const DNS::Packet& packet, const Address& client_addr);

	bool is_forwarder() const { return !settings_.forward_address.empty(); }

	void get_bind_addr(struct in_addr &);
	void resolve_forwarder_address();

	static ssize_t recvfrom(int fd, void *__restrict buf, size_t n, int flags, Address&);
	static ssize_t sendto(int fd, const void * buf, size_t n, int flags, const Address&);

	bool filter_out(uint16_t r_type) const;
	bool filter_out(const DNS::Answer& answer) const;
	bool filter_addresses(std::vector<DNS::Answer>& answers) const;
	bool filter_addresses(DNS::Packet& packet) const;
	void add_hosts(DNS::Packet& packet);

	bool lookup_address(const std::string& host, uint16_t type, std::vector<DNS::Binary>& result) const;
	static DNS::Binary make_binary(struct in_addr& addr);
	static DNS::Binary make_binary(struct in6_addr& addr);
};

DnsServer::DnsServer(const Settings& settings)
: settings_(settings)
{

}

ssize_t DnsServer::sendto(int fd, const void * buf, size_t n, int flags, const Address& address)
{
	return ::sendto(fd, buf, n, flags, &address.address, address.addrlen);
}

ssize_t DnsServer::recvfrom(int fd, void *__restrict buf, size_t n, int flags, Address& addr)
{
	sockaddr sockaddr;
	socklen_t addrlen = sizeof(sockaddr);

	ssize_t result = ::recvfrom(fd, buf, n, flags, &sockaddr, &addrlen);

	if (result < 0)
		return result;
	addr = Address(sockaddr, addrlen);
	return result;
}

bool DnsServer::filter_out(uint16_t r_type) const
{
	if (!settings_.ipv4 && r_type == DNS::Type::A)
		return true;

	if (!settings_.ipv6 && r_type == DNS::Type::AAAA)
		return true;

	return false;

}

bool DnsServer::filter_out(const DNS::Answer& answer) const
{
	return filter_out(answer.r_type);
}

bool DnsServer::filter_addresses(std::vector<DNS::Answer>& answers) const
{	bool changes_made = false;
	for (auto it = answers.begin(); it != answers.end(); ) {
		if (filter_out(*it)) {
			it = answers.erase(it);
			changes_made = true;
		}
		else {
			++it;
		}
	}
	return changes_made;
}

bool DnsServer::filter_addresses(DNS::Packet& packet) const
{
	return
		filter_addresses(packet.answer)
		|| filter_addresses(packet.authority)
		|| filter_addresses(packet.additional);
}

bool DnsServer::lookup_address(const std::string& host, uint16_t type, std::vector<DNS::Binary>& result) const
{
	Key key(host, type);

	auto range = address_map_.equal_range(key);

	if (range.first == range.second)
		return false;

	do {
		result.push_back( range.first->second);
	} while (++range.first != range.second);
	return true;
}

DNS::Binary DnsServer::make_binary(struct in_addr& addr)
{
	return DNS::Binary( reinterpret_cast<DNS::Binary::const_pointer>(&addr),
		reinterpret_cast<DNS::Binary::const_pointer>(&addr + 1));
}

DNS::Binary DnsServer::make_binary(struct in6_addr& addr)
{
	return DNS::Binary( reinterpret_cast<DNS::Binary::const_pointer>(&addr),
		reinterpret_cast<DNS::Binary::const_pointer>(&addr + 1));
}

bool DnsServer::load_hosts(const std::string& file_name)
{
	std::string host;
	std::string addr;
	std::string line;
	size_t lineno = 0;

	std::ifstream in(file_name);

	while(std::getline(in, line)) {
		std::istringstream is(line);
		DNS::Binary net_address;
		uint16_t type;

		lineno++;

		is >> addr;

		if (addr.empty() || is.bad())
			continue;

		if (addr[0] == '#')
			continue;

		if (addr.find(':') != std::string::npos) { // ipv6
			struct in6_addr a;
			if (inet_pton(AF_INET6, addr.c_str(), &a) <= 0) {
				std::cerr << file_name << "(" << lineno << "): Unable to load ipv6 addr " << host << " " << addr << '\n';

				return false;
			}

			type = DNS::Type::AAAA;
			net_address = make_binary(a);
		}

		else { // assume ipv4
			struct in_addr a;
			if (inet_pton(AF_INET, addr.c_str(), &a) <= 0) {
				std::cerr << file_name << "(" << lineno << "): Unable to load ipv4 addr " << host << " " << addr << '\n';
				return false;
			}
			type = DNS::Type::A;
			net_address = make_binary(a);
		}

		while(true) {
			host.clear();
			is >> host;

			if (is.bad() || host.empty() || host[0] == '#')
				break;

			address_map_.emplace( Key(host, type), net_address);
		}
	}

	return true;
}

void DnsServer::add_hosts(DNS::Packet& packet)
{
	std::vector<DNS::Binary> addr_list;

	for (auto const & query : packet.query) {
		std::string host_name = DNS::build_name(query.q_name, 0);

		if (query.q_class != DNS::Class::IN)
			continue;

		if (filter_out(query.q_type))
			continue;

		if (!lookup_address(host_name, query.q_type, addr_list))
			continue;

		DNS::Answer answer;
		answer.r_name = query.q_name;
		answer.r_type = query.q_type;
		answer.r_class = query.q_class;
		answer.r_ttl = settings_.ttl.count();
		for (auto& it : addr_list) {
			answer.r_data = it;
			packet.answer.push_back(answer);
		}
	}
}

uint16_t DnsServer::request_id()
{
	if (id_generator_ == 0)
		id_generator_ = time(nullptr);

	// Galois LFSR
	// https://en.wikipedia.org/wiki/Linear-feedback_shift_register

	unsigned lsb = id_generator_ & 1u;  /* Get LSB (i.e., the output bit). */
	id_generator_ >>= 1;                /* Shift register */
	if (lsb)                            /* If the output bit is 1, */
		id_generator_ ^= 0xB400u;       /* apply toggle mask. */

	return id_generator_;
}

void
DnsServer::forward_request(
	const DNS::Packet& packet,
	uint8_t * buffer,
	size_t buf_size,
	const Address& client_address)
{
	// This is query, forward to up stream server
	uint16_t pkt_id = request_id();

	// replace pkt id
	buffer[0] = pkt_id >> 8;
	buffer[1] = pkt_id & 0xffu;

	for (auto& i: packet.query) {
		std::cout << "Q: " << DNS::build_name(i.q_name, 0) << '\n';
	}

	ssize_t n = sendto(sockfd_, buffer, buf_size, 0, forward_address_);
	if (n < 0)
		die("ERROR in sendto");

	requests_.emplace(pkt_id, Request{ client_address, packet.ID });
}

void DnsServer::send_reply(const DNS::Packet& packet, const Address& client_addr)
{
	auto buf = DNS::build_packet(packet);

	DNS::Packet pkt;
	assert(DNS::parse(buf.data(), buf.size(), pkt));

	for (auto& i : packet.answer) {
		if (i.r_type == DNS::Type::A)
			std::cout << "R: " << DNS::build_name(i.r_name, 0) << "[" << i.r_class << "]" << " -> " << DNS::get_address(i) << '\n';
	}

	for (auto& i : packet.authority) {
		if (i.r_type == DNS::Type::A)
			std::cout << "R: " << DNS::build_name(i.r_name, 0) << "[" << i.r_class << "]" << " -> " << DNS::get_address(i) << '\n';
	}

	ssize_t n = sendto(sockfd_, buf.data(), buf.size(), 0, client_addr);
	if (n < 0)
		die("ERROR in sendto");
}

void DnsServer::local_reply(const DNS::Packet& req, const Address& client_address )
{
	DNS::Packet reply;

	reply.ID = req.ID;
	reply.QR = true;
	reply.OPCODE = 0;
	reply.AA = false;
	reply.TC = false;
	reply.RD = req.RD;
	reply.RA = false;
	reply.Z = false;
	reply.RCODE = 0;

	reply.query = req.query;

	add_hosts(reply);
	filter_addresses(reply);

	send_reply(reply, client_address);
}

void DnsServer::resolve_forwarder_address()
{
	if (!is_forwarder())
		return;

	struct addrinfo hints;
	struct addrinfo * result, * rp;
	memset(&hints, 0, sizeof(struct addrinfo));
	if (true)
		hints.ai_family = AF_INET; // socket is currently ipv4
	else if (settings_.ipv4 && settings_.ipv6)
		hints.ai_family = AF_UNSPEC;    /* Allow IPv4 or IPv6 */
	else if (settings_.ipv4)
		hints.ai_family = AF_INET;
	else if (settings_.ipv6)
		hints.ai_family = AF_INET6;

	hints.ai_socktype = SOCK_DGRAM; /* Datagram socket */
	hints.ai_flags = 0;
	hints.ai_protocol = 0;          /* Any protocol */

	if (getaddrinfo(settings_.forward_address.c_str(), "53", &hints, &result) != 0) {
		die("getaddrinfo");
	}

	if (result == NULL) {
		die("Unable to resolve forward address");
	}

	for (rp = result; rp != NULL; rp = rp->ai_next) {
		forward_address_ = Address(rp->ai_addr, rp->ai_addrlen);
		// currently the first address is used only
		break;
	}

	freeaddrinfo(result);
}

void
DnsServer::get_bind_addr(struct in_addr & sin_addr)
{

	if (settings_.bind.empty()) {
		sin_addr.s_addr = INADDR_ANY;
		return;
	}

	// it might be IP
	if (inet_pton(AF_INET, settings_.bind.c_str(), &sin_addr)) {
		return;
	}

	// interface name othewise
	struct ifaddrs *ifaddr, *ifa;

   	if (getifaddrs(&ifaddr) == -1) {
        perror("getifaddrs");
        exit(EXIT_FAILURE);
    }

	for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL)
            continue;

       	if (ifa->ifa_addr->sa_family != AF_INET)
		   continue;

		if (strcmp(ifa->ifa_name, settings_.bind.c_str()) != 0)
			continue;

		sin_addr = reinterpret_cast<const sockaddr_in*>(ifa->ifa_addr)->sin_addr;
		break;
	}

	freeifaddrs(ifaddr);
}

void
DnsServer::run()
{
	struct sockaddr_in serveraddr;	/* server's addr */
	Address client_address;
	int optval;		/* flag value for setsockopt */
	int buf_size;

    uint8_t buffer[BUFSIZE];

	/*
	 * socket: create the parent socket
	 */
	sockfd_ = socket(AF_INET, SOCK_DGRAM, 0);
	if (sockfd_ < 0)
		die("ERROR opening socket");

	/* setsockopt: Handy debugging trick that lets
	 * us rerun the server immediately after we kill it;
	 * otherwise we have to wait about 20 secs.
	 * Eliminates "ERROR on binding: Address already in use" error.
	 */
	optval = 1;
	setsockopt(sockfd_, SOL_SOCKET, SO_REUSEADDR,
		   (const void *)&optval, sizeof(int));

	/*
	 * build the server's Internet address
	 */
	bzero((char *)&serveraddr, sizeof(serveraddr));
	serveraddr.sin_family = AF_INET;
	serveraddr.sin_addr.s_addr = htonl(INADDR_ANY);
	serveraddr.sin_port = htons((unsigned short)settings_.listen_port);

	get_bind_addr(serveraddr.sin_addr);

	/*
	 * build the Forward's Internet address
	 */

	resolve_forwarder_address();

	/*
	 * bind: associate the parent socket with a port
	 */
	if (bind(sockfd_, (struct sockaddr *)&serveraddr, sizeof(serveraddr)) < 0)
		die("ERROR on bind()");

	std::cout << "Listen on " << inet_ntoa(serveraddr.sin_addr) << ":" << ntohs(serveraddr.sin_port) << '\n';
	if (is_forwarder())
		std::cout << "Forward requests to " << forward_address_.ntop() << '\n';

	while (true) {
		DNS::Packet packet;

		buf_size = recvfrom(sockfd_, buffer, BUFSIZE, 0, client_address);

		if (buf_size < 0)
			die("ERROR in recvfrom");

		if (!DNS::parse(buffer, buf_size, packet)) {
			die("Unable to parse DNS request");
			continue;
		}

		// std::cout << "PACKET FROM " << Address(clientaddr, clientlen).ntop() << "\n";
		// std::cout << DNS::output_packet(packet, "  ");

		if (packet.QR == 0) {
			if (is_forwarder())
				forward_request(packet, buffer, buf_size, client_address);
			else
				local_reply(packet, client_address);
		}
		else {
			if (is_forwarder()) {

				// this is reply. forward to client
				auto it = requests_.find(packet.ID);

				if (it != requests_.end()) {
					Request request = it->second;

					buffer[0] = request.client_id >> 8;
					buffer[1] = request.client_id & 0xffu;

					requests_.erase(it);

					packet.ID = request.client_id;
					add_hosts(packet);
					filter_addresses(packet);

					send_reply(packet, request.client_address);
				}
			}
		}
	}
}

#include <getopt.h>

bool string_to_bool(const char * str, bool def_value)
{
	if (!str || !*str)
		return def_value;

	if (strcasecmp(str, "0") == 0
	|| strcasecmp(str, "no") == 0
	|| strcasecmp(str, "false") == 0)
		return false;
	return true;
}

int
main(int argc, char ** argv)
{
	enum {
		Option_IPV4 = 256,
		Option_IPV6,
		Option_Bind,
	};

	static const struct option options[] = {
		{ "listen", required_argument, nullptr, 'l' },
		{ "forward", required_argument, nullptr, 'f' },
		{ "hosts", required_argument, nullptr, 'h' },
		{ "ipv4", optional_argument, nullptr, Option_IPV4 },
		{ "ipv6", optional_argument, nullptr, Option_IPV6 },
		{ "bind", required_argument, nullptr, Option_Bind },
		{}
	};

	int opt;

	DnsServer::Settings settings;

	settings.listen_port = 53;
	settings.forward_address = "8.8.8.8";
	settings.ipv4 = true;
	settings.ipv6 = true;
	settings.ttl = std::chrono::minutes(10);

	std::string hosts = std::string();


	while( (opt = getopt_long(argc, argv, "l:f:h:", options, nullptr)) != -1) {
		switch (opt)
		{
		case 'l': settings.listen_port = std::stoul(optarg); break;
		case 'f': settings.forward_address = optarg; break;
		case 'h': hosts = optarg; break;

		case Option_IPV4: settings.ipv4 = string_to_bool(optarg, true); break;
		case Option_IPV6: settings.ipv6 = string_to_bool(optarg, true); break;
		case Option_Bind: settings.bind = optarg; break;

		case ':':
			std::cerr << "Missing argument";
			exit(EXIT_FAILURE);

		case '?':
			std::cerr << "Unknown option";
			exit(EXIT_FAILURE);
		}
	}

	DnsServer dns_server(settings);

	if (!hosts.empty() && !dns_server.load_hosts(hosts))
		exit(EXIT_FAILURE);

	dns_server.run();
	return 0;
}
