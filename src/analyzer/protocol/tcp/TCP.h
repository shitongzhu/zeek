// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include "zeek/analyzer/Analyzer.h"
#include "zeek/IPAddr.h"
#include "zeek/analyzer/protocol/tcp/TCP_Endpoint.h"
#include "zeek/analyzer/protocol/tcp/TCP_Flags.h"
#include "zeek/Conn.h"

// We define two classes here:
// - TCP_Analyzer is the analyzer for the TCP protocol itself.
// - TCP_ApplicationAnalyzer is an abstract base class for analyzers for a
//   protocol running on top of TCP.
//

ZEEK_FORWARD_DECLARE_NAMESPACED(PIA_TCP, zeek, analyzer::pia);
ZEEK_FORWARD_DECLARE_NAMESPACED(TCP_Endpoint, zeek, analyzer::tcp);
ZEEK_FORWARD_DECLARE_NAMESPACED(TCP_Reassembler, zeek, analyzer::tcp);
ZEEK_FORWARD_DECLARE_NAMESPACED(TCP_ApplicationAnalyzer, zeek, analyzer::tcp);

namespace zeek::analyzer::tcp {

class TCP_FatherAnalyzer;

class TCP_Analyzer final : public analyzer::TransportLayerAnalyzer {
public:
	explicit TCP_Analyzer(Connection* conn, TCP_FatherAnalyzer* father = nullptr);
	~TCP_Analyzer() override;
 
	//Pengxiong's code
	TCP_Analyzer(TCP_Analyzer* tcp);

	Analyzer* Clone() override { return new TCP_Analyzer(this); }

	void Reset();

	virtual void EnableReassembly();

	// Add a child analyzer that will always get the packets,
	// independently of whether we do any reassembly.
	virtual void AddChildPacketAnalyzer(analyzer::Analyzer* a);

	Analyzer* FindChild(analyzer::ID id) override;
	Analyzer* FindChild(analyzer::Tag tag) override;
	bool RemoveChildAnalyzer(analyzer::ID id) override;

	// True if the connection has closed in some sense, false otherwise.
	virtual bool IsClosed() const	{ return orig->did_close || resp->did_close; }
	bool BothClosed() const	{ return orig->did_close && resp->did_close; }

	bool IsPartial() const	{ return is_partial; }

	bool HadGap(bool orig) const;

	TCP_Endpoint* Orig() const	{ return orig; }
	TCP_Endpoint* Resp() const	{ return resp; }
	int OrigState() const	{ return orig->state; }
	int RespState() const	{ return resp->state; }
	int OrigPrevState() const	{ return orig->prev_state; }
	int RespPrevState() const	{ return resp->prev_state; }
	uint32_t OrigSeq() const	{ return orig->LastSeq(); }
	uint32_t RespSeq() const	{ return resp->LastSeq(); }

	// True if either endpoint still has pending data.  closing_endp
	// is an endpoint that has indicated it is closing (i.e., for
	// which we have seen a FIN) - for it, data is pending unless
	// everything's been delivered up to the FIN.  For its peer,
	// the test is whether it has any outstanding, un-acked data.
	virtual bool DataPending(TCP_Endpoint* closing_endp);

	void SetContentsFile(unsigned int direction, FilePtr f) override;
	FilePtr GetContentsFile(unsigned int direction) const override;

	// From Analyzer.h
	void UpdateConnVal(RecordVal *conn_val) override;

	virtual int ParseTCPOptions(const struct tcphdr* tcp, bool is_orig);

	static analyzer::Analyzer* Instantiate(Connection* conn)
		{ return new TCP_Analyzer(conn); }

	// wzj
	void DumpAnalyzerTree(int level = 0) const override;

protected:
	friend class TCP_FatherAnalyzer;
	friend class TCP_ApplicationAnalyzer;
	friend class TCP_Reassembler;
	friend class analyzer::pia::PIA_TCP;

	// Analyzer interface.
	void Init() override;
	void Done() override;
	void DeliverPacket(int len, const u_char* data, bool orig, uint64_t seq,
	                   const IP_Hdr* ip, int caplen) override;
	void DeliverStream(int len, const u_char* data, bool orig) override;
	void Undelivered(uint64_t seq, int len, bool orig) override;
	void FlipRoles() override;
	bool IsReuse(double t, const u_char* pkt) override;
 
	//Pengxiong's code
	bool HasTCPMD5Option(const struct tcphdr* tcp);
	bool HasTCPSACKOption(const struct tcphdr* tcp);
	bool ParseTCPTimestampOption(const struct tcphdr* tcp, bool is_orig);

	bool CheckAmbiguity(const u_char* data, int len, int caplen, bool is_orig);

	// Returns the TCP header pointed to by data (which we assume is
	// aligned), updating data, len & caplen.  Returns nil if the header
	// isn't fully present.
	const struct tcphdr* ExtractTCP_Header(const u_char*& data, int& len,
						int& caplen);

	// Returns true if the checksum is valid, false if not (and in which
	// case also updates the status history of the endpoint).
	bool ValidateChecksum(const IP_Hdr* ip, const struct tcphdr* tp, TCP_Endpoint* endpoint,
				int len, int caplen);

	void SetPartialStatus(TCP_Flags flags, bool is_orig);

	// Update the state machine of the TCPs based on the activity.  This
	// includes our pseudo-states such as TCP_ENDPOINT_PARTIAL.
	//
	// On return, do_close is true if we should consider the connection
	// as closed, and gen_event if we shouuld generate an event about
	// this fact.
	void UpdateStateMachine(double t,
			TCP_Endpoint* endpoint, TCP_Endpoint* peer,
			uint32_t base_seq, uint32_t ack_seq,
			int len, int32_t delta_last, bool is_orig, TCP_Flags flags,
			bool& do_close, bool& gen_event);

	void UpdateInactiveState(double t,
				TCP_Endpoint* endpoint, TCP_Endpoint* peer,
				uint32_t base_seq, uint32_t ack_seq,
				int len, bool is_orig, TCP_Flags flags,
				bool& do_close, bool& gen_event);

	void UpdateSYN_SentState(TCP_Endpoint* endpoint, TCP_Endpoint* peer,
				 int len, bool is_orig, TCP_Flags flags,
				 bool& do_close, bool& gen_event);

	void UpdateEstablishedState(TCP_Endpoint* endpoint, TCP_Endpoint* peer,
				    TCP_Flags flags, bool& do_close, bool& gen_event);

	void UpdateClosedState(double t, TCP_Endpoint* endpoint,
				int32_t delta_last, TCP_Flags flags,
				bool& do_close);

	void UpdateResetState(int len, TCP_Flags flags);

	void GeneratePacketEvent(uint64_t rel_seq, uint64_t rel_ack,
				 const u_char* data, int len, int caplen,
				 bool is_orig, TCP_Flags flags);

	bool DeliverData(double t, const u_char* data, int len, int caplen,
	                 const IP_Hdr* ip, const struct tcphdr* tp,
	                 TCP_Endpoint* endpoint, uint64_t rel_data_seq,
	                 bool is_orig, TCP_Flags flags);

	void CheckRecording(bool need_contents, TCP_Flags flags);
	void CheckPIA_FirstPacket(bool is_orig, const IP_Hdr* ip);

	friend class detail::ConnectionTimer;
	void AttemptTimer(double t);
	void PartialCloseTimer(double t);
	void ExpireTimer(double t);
	void ResetTimer(double t);
	void DeleteTimer(double t);
	void ConnDeleteTimer(double t);

	void EndpointEOF(TCP_Reassembler* endp);
	void ConnectionClosed(TCP_Endpoint* endpoint,
					TCP_Endpoint* peer, bool gen_event);
	void ConnectionFinished(bool half_finished);
	void ConnectionReset();
	void PacketWithRST();

	void SetReassembler(tcp::TCP_Reassembler* rorig, tcp::TCP_Reassembler* rresp);

	// A couple utility functions that may also be useful to derived analyzers.
	static uint64_t get_relative_seq(const TCP_Endpoint* endpoint,
	                               uint32_t cur_base, uint32_t last,
	                               uint32_t wraps, bool* underflow = nullptr);

	static int get_segment_len(int payload_len, TCP_Flags flags);

	// ZST: Robust-NIDS
        // The following functions are for determining what ambuiguities are being encountered.
        bool IsSYNFINPacketInLISTEN(const struct tcphdr* tp, bool is_orig);
        bool IsInWindowPacket(const struct tcphdr* tp, bool is_orig);
	bool IsSEQEqualToRcvNxt(const struct tcphdr* tp, bool is_orig);
	bool IsInWindowSYNPacketInESTABLISHED(const struct tcphdr* tp, bool is_orig);
	bool IsInWindowRSTPacketInESTABLISHED(const struct tcphdr* tp, bool is_orig);
	bool IsAckNumberTooOldInESTABLISHED(const struct tcphdr* tp, bool is_orig);
        bool IsNoACKPacketInESTABLISHED(const struct tcphdr* tp, bool is_orig, int len);
        bool IsRSTPacketInESTABLISHED(const struct tcphdr* tp, bool is_orig);
	bool IsSYNPacketInESTABLISHED(const struct tcphdr* tp, bool is_orig);
	bool IsRSTPacketWithSEQOfRightmostSACK(const struct tcphdr* tp, bool is_orig);
	bool IsRSTAfterFINInClosingStates(const struct tcphdr* tp, bool is_orig);
	bool IsDataWithOldAckNumInClosingStates(const struct tcphdr* tp, bool is_orig, int len);

private:

	void SynWeirds(TCP_Flags flags, TCP_Endpoint* endpoint, int data_len) const;

	TCP_Endpoint* orig;
	TCP_Endpoint* resp;

	using analyzer_list = std::list<analyzer::Analyzer*>;
	analyzer_list packet_children;

	unsigned int first_packet_seen: 2;
	unsigned int reassembling: 1;
	unsigned int is_partial: 1;
	unsigned int is_active: 1;
	unsigned int finished: 1;

	// Whether we're waiting on final data delivery before closing
	// this connection.
	unsigned int close_deferred: 1;

	// Whether to generate an event when we finally do close it.
	unsigned int deferred_gen_event: 1;

	// Whether we have seen the first ACK from the originator.
	unsigned int seen_first_ACK: 1;

	// wzj
	std::vector<bool> curr_pkt_ambiguities;
	std::vector<int> ambiguity_behavior;

	bool sack_seen;

	TCP_FatherAnalyzer* tcp_father;
};

class TCP_ApplicationAnalyzer : public analyzer::Analyzer {
public:
	TCP_ApplicationAnalyzer(const char* name, Connection* conn)
		: Analyzer(name, conn), tcp(nullptr) { }

	explicit TCP_ApplicationAnalyzer(Connection* conn)
		: Analyzer(conn), tcp(nullptr) { }

	~TCP_ApplicationAnalyzer() override { }
 
	TCP_ApplicationAnalyzer(TCP_ApplicationAnalyzer* taa)
		: Analyzer(taa) 
		{ 
			tcp = nullptr; 
		}

	Analyzer* Clone() override { return new TCP_ApplicationAnalyzer(this); }

	// This may be nil if we are not directly associated with a TCP
	// analyzer (e.g., we're part of a tunnel decapsulation pipeline).
	TCP_Analyzer* TCP()
		{
		return tcp ?
			tcp :
			static_cast<TCP_Analyzer*>(Conn()->FindAnalyzer("TCP"));
		}

	void SetTCP(TCP_Analyzer* arg_tcp)	{ tcp = arg_tcp; }

	// The given endpoint's data delivery is complete.
	virtual void EndpointEOF(bool is_orig);

	// Called whenever an end enters TCP_ENDPOINT_CLOSED or
	// TCP_ENDPOINT_RESET.  If gen_event is true and the connection
	// is now fully closed, a connection_finished event will be
	// generated; otherwise not.
	virtual void ConnectionClosed(analyzer::tcp::TCP_Endpoint* endpoint,
				      analyzer::tcp::TCP_Endpoint* peer, bool gen_event);
	virtual void ConnectionFinished(bool half_finished);
	virtual void ConnectionReset();

	// Called whenever a RST packet is seen - sometimes the invocation
	// of ConnectionReset is delayed.
	virtual void PacketWithRST();

	void DeliverPacket(int len, const u_char* data, bool orig,
	                   uint64_t seq, const IP_Hdr* ip, int caplen) override;
	void Init() override;

	// This suppresses violations if the TCP connection wasn't
	// fully established.
	void ProtocolViolation(const char* reason,
					const char* data = nullptr, int len = 0) override;

	// "name" and "val" both now belong to this object, which needs to
	//  delete them when done with them.
	virtual void SetEnv(bool orig, char* name, char* val);

private:
	TCP_Analyzer* tcp;
};

class TCP_SupportAnalyzer : public analyzer::SupportAnalyzer {
public:
	TCP_SupportAnalyzer(const char* name, Connection* conn, bool arg_orig)
		: analyzer::SupportAnalyzer(name, conn, arg_orig)	{ }

	~TCP_SupportAnalyzer() override {}
 
	TCP_SupportAnalyzer(TCP_SupportAnalyzer* tsa)
		: analyzer::SupportAnalyzer(tsa)
		{ 
		}

	Analyzer* Clone() override { return new TCP_SupportAnalyzer(this); }

	// These are passed on from TCP_Analyzer.
	virtual void EndpointEOF(bool is_orig)	{ }
	virtual void ConnectionClosed(TCP_Endpoint* endpoint,
					TCP_Endpoint* peer, bool gen_event) 	{ }
	virtual void ConnectionFinished(bool half_finished)	{ }
	virtual void ConnectionReset()	{ }
	virtual void PacketWithRST()	{ }
};


class TCPStats_Endpoint {
public:
	explicit TCPStats_Endpoint(TCP_Endpoint* endp);

	bool DataSent(double t, uint64_t seq, int len, int caplen, const u_char* data,
	              const IP_Hdr* ip, const struct tcphdr* tp);

	RecordVal* BuildStats();

protected:
	TCP_Endpoint* endp;
	int num_pkts;
	int num_rxmit;
	int num_rxmit_bytes;
	int num_in_order;
	int num_OO;
	int num_repl;
	uint64_t max_top_seq;
	int last_id;
	int endian_type;
};

class TCPStats_Analyzer : public tcp::TCP_ApplicationAnalyzer {
public:
	explicit TCPStats_Analyzer(Connection* c);
	~TCPStats_Analyzer() override;

	void Init() override;
	void Done() override;

	static analyzer::Analyzer* Instantiate(Connection* conn)
		{ return new TCPStats_Analyzer(conn); }

protected:
	void DeliverPacket(int len, const u_char* data, bool is_orig,
	                   uint64_t seq, const IP_Hdr* ip, int caplen) override;

	TCPStats_Endpoint* orig_stats;
	TCPStats_Endpoint* resp_stats;
};

} // namespace zeek::analyzer::tcp

namespace analyzer::tcp {

using TCP_Analyzer [[deprecated("Remove in v4.1. Use zeek::analyzer::tcp::TCP_Analyzer.")]] = zeek::analyzer::tcp::TCP_Analyzer;
using TCP_ApplicationAnalyzer [[deprecated("Remove in v4.1. Use zeek::analyzer::tcp::TCP_ApplicationAnalyzer.")]] = zeek::analyzer::tcp::TCP_ApplicationAnalyzer;
using TCP_SupportAnalyzer [[deprecated("Remove in v4.1. Use zeek::analyzer::tcp::TCP_SupportAnalyzer.")]] = zeek::analyzer::tcp::TCP_SupportAnalyzer;
using TCPStats_Endpoint [[deprecated("Remove in v4.1. Use zeek::analyzer::tcp::TCPStats_Endpoint.")]] = zeek::analyzer::tcp::TCPStats_Endpoint;
using TCPStats_Analyzer [[deprecated("Remove in v4.1. Use zeek::analyzer::tcp::TCPStats_Analyzer.")]] = zeek::analyzer::tcp::TCPStats_Analyzer;

} // namespace analyzer::tcp
