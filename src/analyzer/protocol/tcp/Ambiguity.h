
#pragma once


namespace zeek::analyzer::tcp {

enum
{
    AMBI_MD5, /* TCP packet with MD5 Option -- 0 */
    AMBI_SYNFIN_IN_LISTEN, /* SYN + FIN packet in LISTEN state -- 1 */
    AMBI_IN_WINDOW_SYN, /* In-window SYN in ESTABLISHED state -- 2 */
    AMBI_IN_WINDOW_RST, /* In-window RST in ESTABLISHED state -- 3 */
    AMBI_NO_ACK, /* Packets without ACK flag -- 4 */
    AMBI_RST_IN_EST, /* RST packets in ESTABLISHED state -- 5 */
    AMBI_SYN_IN_EST, /* SYN packets in ESTABLISHED state -- 6*/
    AMBI_RST_SEQ_SACK, /* RST packets with SEQ = rcv_nxt -- 7*/
    AMBI_MAX  /* Leave at the end! */
};

enum
{
    AMBI_BEHAV_OLD, /* Old behaviour in case the ambiguity is triggered -- 0 */
    AMBI_BEHAV_NEW, /* New behaviour in case the ambiguity is triggered -- 1 */
    AMBI_BEHAV_MAX /* Guard */
};


} // namespace analyzer::tcp
