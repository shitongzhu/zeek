
#pragma once


namespace zeek::analyzer::tcp {

enum
{
    AMBI_MD5, /* TCP packet with MD5 Option -- 0 */
    AMBI_SYNFIN_IN_LISTEN, /* SYN + FIN packet in LISTEN state -- 1 */
    AMBI_IN_WINDOW_SYN, /* In-window SYN in ESTABLISHED state -- 2 */
    AMBI_IN_WINDOW_RST, /* In-window RST in ESTABLISHED state -- 3 */
    AMBI_TOO_OLD_ACK_NUM, /* Too old ACK number in ESTABLISHED state -- 4 */
    AMBI_NO_ACK, /* Data packets without ACK flag -- 5 */
    AMBI_RST_RIGHTMOST_SACK, /* RST packets with SEQ = rightmost SACK -- 6*/
    AMBI_RST_AFTER_FIN, /* RST packets with SEQ = rcv_nxt - 1 in closing states -- 7*/
    AMBI_DATA_IN_CLOSING_STATES, /* Data packets with old ACK number in closing states -- 8*/
    AMBI_MAX  /* Leave at the end! */
};

enum
{
    AMBI_BEHAV_UNDEF = -1, /* Undefined behaviour (initial value) -- -1 */
    AMBI_BEHAV_OLD = 0, /* Old behaviour in case the ambiguity is triggered -- 0 */
    AMBI_BEHAV_NEW = 1 /* New behaviour in case the ambiguity is triggered -- 1 */
};


} // namespace analyzer::tcp
