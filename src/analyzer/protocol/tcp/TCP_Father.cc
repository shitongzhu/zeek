
#include "zeek/analyzer/protocol/tcp/TCP_Father.h"

#include <iostream>

#include "zeek/analyzer/protocol/tcp/Ambiguity.h"


namespace zeek::analyzer::tcp {

/********************
 * Analyzer methods *
 ********************/

TCP_FatherAnalyzer::TCP_FatherAnalyzer(Connection *conn)
: TransportLayerAnalyzer("TCPFather", conn) 
{
    TCP_Analyzer *ta = new TCP_Analyzer(conn);
    tcp_children.push_back(ta);
}

TCP_FatherAnalyzer::~TCP_FatherAnalyzer() 
{
    for (TCP_Analyzer *tcp_child : tcp_children) {
        delete tcp_child;
    }
}

void TCP_FatherAnalyzer::Init()
{
    assert(tcp_children.size() == 1);

    Analyzer::Init();

    for (TCP_Analyzer *tcp_child : tcp_children) {
        tcp_child->Init();
    }
}

void TCP_FatherAnalyzer::Done()
{
    TransportLayerAnalyzer::Done();

    for (TCP_Analyzer *tcp_child : tcp_children) {
        tcp_child->Done();
    }
}

void TCP_FatherAnalyzer::NextPacket(int len, const u_char* data, bool is_orig,
                uint64_t seq, const IP_Hdr* ip, int caplen)
{
    int i = 0;
    for (TCP_Analyzer *tcp_child : tcp_children) {
        if (tcp_child->CheckAmbiguity(data, len, caplen)) {
            for (int ambiguity_id : tcp_child->curr_pkt_ambiguities) {
                std::cout << "State " << i << ": found ambiguity: " << ambiguity_id << "\n";
                if (tcp_child->ambiguity_behavior[ambiguity_id] == -1) {
                    // fork
                    std::cout << "Forking State " << i << "\n";
                    TCP_Analyzer *new_tcp_child = Fork(tcp_child);
                    
                    // set ambiguity behavior
                    // old
                    for (int j = ambiguity_id; j < AMBI_MAX; j++) {
                        assert(tcp_child->ambiguity_behavior[j] != 1);
                        tcp_child->ambiguity_behavior[j] = 0;
                    }
                    // new
                    for (int j = ambiguity_id; j >= 0; j--) {
                        assert(new_tcp_child->ambiguity_behavior[j] != 0);
                        new_tcp_child->ambiguity_behavior[j] = 1;
                    }
                }
            }

            /*
            if(orig_cur->ambiguities[ambiguity_id] == -1) //forka
            {
                printf("State%d: ambiguity %d hasn't been recorded\n", i, ambiguity_id);
                TCP_Analyzer* tcp_analyzer_new = new TCP_Analyzer(*this);
                TCP_Endpoint* orig_new = tcp_analyzer_new->orig; //TODO: add an id to distinguish forked states
                TCP_Endpoint* resp_new = tcp_analyzer_new->resp;
                orig_forks.push_back(orig_new);
                resp_forks.push_back(resp_new);
                TCP_Reassembler* tcp_reassembler_orig_new = orig_cur->contents_processor->clone(tcp_analyzer_new, tcp_analyzer_new, orig_new, orig_cur->contents_file);
                
                TCP_Reassembler* tcp_reassembler_resp_new = resp_cur->contents_processor->clone(tcp_analyzer_new, tcp_analyzer_new, resp_new, resp_cur->contents_file);
                tcp_analyzer_new->SetReassembler(tcp_reassembler_orig_new, tcp_reassembler_resp_new);
                orig_new->ambiguities[ambiguity_id] = 2;
                orig_cur->ambiguities[ambiguity_id] = 1;
            }
            else
                printf("State%d: ambiguity %d has been recorded\n", i, ambiguity_id);
            // execute_ambiguity_action(orig->ambiguities[ambiguity_id]);
            if(orig_cur->ambiguities[ambiguity_id] == 1)
            {
                printf("State%d: ambiguity %d is being ignored\n\n", i, ambiguity_id);
                continue;  //ignore
            }
            else
            {
                printf("State%d: ambiguity %d is being accepted\n\n", i, ambiguity_id);
            }
            */

        }
        i++;
    }
    
    for (TCP_Analyzer *tcp_child : tcp_children) {
        tcp_child->NextPacket(len, data, is_orig, seq, ip, caplen);
    }
}

void TCP_FatherAnalyzer::NextStream(int len, const u_char* data, bool is_orig)
{
    std::cerr << "TCP_FatherAnalyzer::NextStream not implemented!\n";
    assert(false);
}

void TCP_FatherAnalyzer::NextUndelivered(uint64_t seq, int len, bool is_orig)
{
    std::cerr << "TCP_FatherAnalyzer::NextUndelivered not implemented!\n";
    assert(false);
}

void TCP_FatherAnalyzer::NextEndOfData(bool is_orig)
{
    std::cerr << "TCP_FatherAnalyzer::NextEndOfData not implemented!\n";
    assert(false);
}

void TCP_FatherAnalyzer::ForwardPacket(int len, const u_char* data,
                                       bool orig, uint64_t seq,
                                       const IP_Hdr* ip, int caplen)
{
    std::cerr << "TCP_FatherAnalyzer::ForwardPacket not implemented!\n";
    assert(false);
}

void TCP_FatherAnalyzer::ForwardStream(int len, const u_char* data, bool orig)
{
    std::cerr << "TCP_FatherAnalyzer::ForwardStream not implemented!\n";
    assert(false);
}

void TCP_FatherAnalyzer::ForwardUndelivered(uint64_t seq, int len, bool orig)
{
    std::cerr << "TCP_FatherAnalyzer::ForwardUndelivered not implemented!\n";
    assert(false);
}

void TCP_FatherAnalyzer::ForwardEndOfData(bool orig)
{
    std::cerr << "TCP_FatherAnalyzer::ForwardEndOfData not implemented!\n";
    assert(false);
}

void TCP_FatherAnalyzer::DeliverPacket(int len, const u_char* data, bool orig, uint64_t seq,
                   const IP_Hdr* ip, int caplen)
{
    std::cerr << "TCP_FatherAnalyzer::DeliverPacket not implemented!\n";
    assert(false);
}

void TCP_FatherAnalyzer::DeliverStream(int len, const u_char* data, bool orig)
{
    std::cerr << "TCP_FatherAnalyzer::DeliverStream not implemented!\n";
    assert(false);
}

void TCP_FatherAnalyzer::Undelivered(uint64_t seq, int len, bool orig)
{
    std::cerr << "TCP_FatherAnalyzer::Undelivered not implemented!\n";
    assert(false);
}

void TCP_FatherAnalyzer::FlipRoles()
{
    std::cerr << "TCP_FatherAnalyzer::FlipRoles not implemented!\n";
    assert(false);
}

void TCP_FatherAnalyzer::SetSkip(bool do_skip)
{
    std::cerr << "TCP_FatherAnalyzer::SetSkip not implemented!\n";
    assert(false);
}

bool TCP_FatherAnalyzer::Skipping() const
{
    std::cerr << "TCP_FatherAnalyzer::Skipping not implemented!\n";
    assert(false);
}

bool TCP_FatherAnalyzer::IsFinished() const 
{
    bool finished = false;
    for (TCP_Analyzer* tcp_child : tcp_children) {
        //finished |= tcp_child->IsFinsihed();
        finished |= tcp_child->finished;
    }
}

bool TCP_FatherAnalyzer::Removing() const
{
    std::cerr << "TCP_FatherAnalyzer::Removing not implemented!\n";
    assert(false);
}

bool TCP_FatherAnalyzer::RemoveChildAnalyzer(analyzer::ID id)
{
    std::cerr << "TCP_FatherAnalyzer::RemoveChildAnalyzer not implemented!\n";
    assert(false);
}

bool TCP_FatherAnalyzer::HasChildAnalyzer(Tag tag)
{
    std::cerr << "TCP_FatherAnalyzer::HasChildAnalyzer not implemented!\n";
    assert(false);
}

Analyzer* TCP_FatherAnalyzer::FindChild(analyzer::ID id)
{
    assert(tcp_children.size() == 1);
    return tcp_children.front()->FindChild(id);
}

Analyzer* TCP_FatherAnalyzer::FindChild(analyzer::Tag tag)
{
    assert(tcp_children.size() == 1);
    return tcp_children.front()->FindChild(tag);
}

const analyzer_list& TCP_FatherAnalyzer::GetChildren()
{
    assert(tcp_children.size() == 1);
    return tcp_children.front()->GetChildren();
}

void TCP_FatherAnalyzer::AddSupportAnalyzer(SupportAnalyzer* analyzer)
{
    std::cerr << "TCP_FatherAnalyzer::AddSupportAnalyzer not implemented!\n";
    assert(false);
}

void TCP_FatherAnalyzer::RemoveSupportAnalyzer(SupportAnalyzer* analyzer)
{
    std::cerr << "TCP_FatherAnalyzer::RemoveSupportAnalyzer not implemented!\n";
    assert(false);
}

void TCP_FatherAnalyzer::UpdateConnVal(RecordVal *conn_val)
{
    assert(tcp_children.size() == 1);
    for (TCP_Analyzer *tcp_child : tcp_children) {
        tcp_child->UpdateConnVal(conn_val);
    }
}

RecordVal* TCP_FatherAnalyzer::BuildConnVal()
{
    std::cerr << "TCP_FatherAnalyzer::BuildConnVal not implemented!\n";
    assert(false);
}

const RecordValPtr& TCP_FatherAnalyzer::ConnVal()
{
    std::cerr << "TCP_FatherAnalyzer::ConnVal not implemented!\n";
    assert(false);
}

unsigned int TCP_FatherAnalyzer::MemoryAllocation() const
{
    std::cerr << "TCP_FatherAnalyzer::MemoryAllocation not implemented!\n";
    assert(false);
}

void TCP_FatherAnalyzer::AddTimer(analyzer_timer_func timer, double t, bool do_expire,
                                  detail::TimerType type)
{
    std::cerr << "TCP_FatherAnalyzer::AddTimer not implemented!\n";
    assert(false);
}

void TCP_FatherAnalyzer::CancelTimers()
{
    for (TCP_Analyzer *tcp_child : tcp_children) {
        tcp_child->CancelTimers();
    }
}

void TCP_FatherAnalyzer::RemoveTimer(detail::Timer* t)
{
    std::cerr << "TCP_FatherAnalyzer::RemoveTimer not implemented!\n";
    assert(false);
}

bool TCP_FatherAnalyzer::HasSupportAnalyzer(const Tag& tag, bool orig)
{
    std::cerr << "TCP_FatherAnalyzer::HasSupportAnalyzer not implemented!\n";
    assert(false);
}

SupportAnalyzer* TCP_FatherAnalyzer::FirstSupportAnalyzer(bool orig)
{
    std::cerr << "TCP_FatherAnalyzer::FirstSupportAnalyzer not implemented!\n";
    assert(false);
}

bool TCP_FatherAnalyzer::AddChildAnalyzer(Analyzer *analyzer, bool init)
{
    assert(tcp_children.size() == 1);
    bool ret = false;
    bool first = true;
    for (TCP_Analyzer *tcp_child : tcp_children) {
        bool tmp = tcp_child->AddChildAnalyzer(analyzer, init);
        assert(first || tmp == ret);
        ret |= tmp;
        first = false;
    }
    return ret;
}

void TCP_FatherAnalyzer::InitChildren()
{
    assert(tcp_children.size() == 1);
    for (TCP_Analyzer *tcp_child : tcp_children) {
        tcp_child->InitChildren();
    }
}

void TCP_FatherAnalyzer::AppendNewChildren()
{
    for (TCP_Analyzer *tcp_child : tcp_children) {
        tcp_child->AppendNewChildren();
    }
}

bool TCP_FatherAnalyzer::RemoveChild(const analyzer_list& tcp_children, ID id)
{
    std::cerr << "TCP_FatherAnalyzer::RemoveChild not implemented!\n";
    assert(false);
}

void TCP_FatherAnalyzer::DeleteChild(analyzer_list::iterator i)
{
    std::cerr << "TCP_FatherAnalyzer::DeleteChild not implemented!\n";
    assert(false);
}

/**********************************
 * TransportLayerAnalyzer methods *
 **********************************/

void TCP_FatherAnalyzer::SetContentsFile(unsigned int direction, FilePtr f)
{
    std::cerr << "TCP_FatherAnalyzer::SetContentsFile not implemented!\n";
    assert(false);
}

FilePtr TCP_FatherAnalyzer::GetContentsFile(unsigned int direction) const
{
    std::cerr << "TCP_FatherAnalyzer::GetContentsFile not implemented!\n";
    assert(false);
}

void TCP_FatherAnalyzer::SetPIA(analyzer::pia::PIA* arg_PIA)
{
    std::cerr << "TCP_FatherAnalyzer::SetPIA not implemented!\n";
    assert(false);
}

analyzer::pia::PIA* TCP_FatherAnalyzer::GetPIA() const
{
    std::cerr << "TCP_FatherAnalyzer::GetPIA not implemented!\n";
    assert(false);
}

/************************
 * TCP_Analyzer methods *
 ************************/

void TCP_FatherAnalyzer::EnableReassembly() 
{
    assert(tcp_children.size() == 1);
    tcp_children.front()->EnableReassembly();
}

void TCP_FatherAnalyzer::AddChildPacketAnalyzer(Analyzer *analyzer)
{
    assert(tcp_children.size() == 1);
    for (TCP_Analyzer *tcp_child : tcp_children) {
        tcp_child->AddChildPacketAnalyzer(analyzer);
    }
}

/******************************
 * TCP_FatherAnalyzer methods *
 ******************************/

TCP_Analyzer* TCP_FatherAnalyzer::Fork(TCP_Analyzer* ta)
{
    ta->DumpAnalyzerTree();
    TCP_Analyzer *copy = new TCP_Analyzer(ta);
    copy->DumpAnalyzerTree();

    return copy;
}

} // namespace zeek::analyzer::tcp
