
#pragma once


namespace zeek::analyzer::tcp {

enum
{
    AMBI_MD5, /* TCP packet with MD5 Option -- 0 */
    AMBI_SYNFIN_IN_LISTEN, /* SYN + FIN packet in LISTEN state -- 1 */
    AMBI_IN_WINDOW_SYN, /* In-window SYN in ESTABLISHED state -- 2 */
    AMBI_IN_WINDOW_RST, /* In-window RST in ESTABLISHED state -- 3 */
    AMBI_NO_ACK, /* Data packets without ACK flag -- 4 */
    AMBI_RST_RIGHTMOST_SACK, /* RST packets with SEQ = rightmost SACK -- 5*/
    AMBI_MAX  /* Leave at the end! */
};

enum
{
    AMBI_BEHAV_OLD, /* Old behaviour in case the ambiguity is triggered -- 0 */
    AMBI_BEHAV_NEW, /* New behaviour in case the ambiguity is triggered -- 1 */
    AMBI_BEHAV_MAX /* Guard */
};


} // namespace analyzer::tcp
