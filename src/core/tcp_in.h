#ifndef TCP_IN_H_INCLUDED
#define TCP_IN_H_INCLUDED

//Structs
struct tcp_hdr
{
    unsigned short src;
    unsigned short dest;
    unsigned int seqno;
    unsigned int ackno;
    //unsigned short _hdrlen_rsvd_flags;
    unsigned short wnd;
    unsigned short chksum;
    unsigned short urgp;
};

enum err_t
{
    E_OK = 0
};

//Globals
static tcp_hdr tcphdr;

static unsigned int seqno, ackno;
static unsigned char flags;
static unsigned short tcplen;

//static unsigned char recv_flags;
static Buffer recv_data;

static Connection recvConnection;

static void send_ack( const MinetHandle &mux, TCPState & state )
{
    Packet ret;

    //Set IP Header
    IPHeader ipHeader;
    ipHeader.SetSourceIP(recvConnection.src);
    ipHeader.SetDestIP(recvConnection.dest);
    ipHeader.SetTotalLength(IP_HEADER_BASE_LENGTH + TCP_HEADER_BASE_LENGTH);
    ipHeader.SetProtocol(IP_PROTO_TCP);

    ret.PushFrontHeader(ipHeader);

    //Set TCP Header
    TCPHeader tcpHeader;
    tcpHeader.SetSourcePort(recvConnection.srcport, ret);
    tcpHeader.SetDestPort(recvConnection.destport, ret);
    tcpHeader.SetHeaderLen(TCP_HEADER_BASE_LENGTH / 4, ret);
    tcpHeader.SetAckNum(state.GetLastRecvd() + 1, ret);
    tcpHeader.SetSeqNum(state.last_sent + 1, ret);
    tcpHeader.SetWinSize(state.GetN(), ret);
    tcpHeader.SetUrgentPtr(0, ret);

    unsigned char tempFlags = 0;
    SET_ACK(tempFlags);
    tcpHeader.SetFlags(tempFlags, ret);

    ret.PushBackHeader(tcpHeader);

    MinetSend(mux, ret);

    std::cerr << "send_ack: ACK sent" << std::endl;

    state.last_sent++;
}

static void send_synack(const MinetHandle & mux, TCPState & state )
{
    Packet ret;

    //Set IP Header
    IPHeader ipHeader;
    ipHeader.SetSourceIP(recvConnection.src);
    ipHeader.SetDestIP(recvConnection.dest);
    ipHeader.SetTotalLength(IP_HEADER_BASE_LENGTH + TCP_HEADER_BASE_LENGTH);
    ipHeader.SetProtocol(IP_PROTO_TCP);

    ret.PushFrontHeader(ipHeader);

    //Set TCP Header
    TCPHeader tcpHeader;
    tcpHeader.SetSourcePort(recvConnection.srcport, ret);
    tcpHeader.SetDestPort(recvConnection.destport, ret);
    tcpHeader.SetHeaderLen(TCP_HEADER_BASE_LENGTH / 4, ret);
    tcpHeader.SetAckNum(state.GetLastRecvd() + 1, ret);
    tcpHeader.SetSeqNum(state.last_sent + 1, ret);
    tcpHeader.SetWinSize(state.GetN(), ret);
    tcpHeader.SetUrgentPtr(0, ret);

    unsigned char tempFlags = 0;
    SET_SYN(tempFlags);
    SET_ACK(tempFlags);
    tcpHeader.SetFlags(tempFlags, ret);

    ret.PushBackHeader(tcpHeader);

    MinetSend(mux, ret);

    std::cerr << "send_synack: SYNACK sent" << std::endl;

    state.last_sent++;
}

static void send_write_to_application( const MinetHandle & sock, const Buffer &b )
{
    SockRequestResponse repl;
    repl.type = WRITE;
    repl.error = EOK;
    repl.data = b;
    repl.connection = recvConnection;
    MinetSend(sock, repl );
}

static void send_empty_write_to_application( const MinetHandle & sock )
{
    SockRequestResponse repl;
    repl.type = WRITE;
    repl.error = EOK;
    repl.bytes = 0;
    repl.connection = recvConnection;
    MinetSend(sock, repl);
}

//This function is responsible for sending data the the application,
//managing the send and recieve buffers (if implemented), and managing the recieve windows
static void receive_packet( const MinetHandle &mux, const MinetHandle &sock, TCPState & state )
{
    if ( IS_ACK(flags) )
    {
        //Update Window
        //Unimplemented

        //Check if duplicate ack
        if ( ackno <= state.last_acked )
        {
            //Not implemneted
        }

        //Sender is acking new data
        else if ( state.last_acked + 1 <= ackno && ackno <= state.last_sent )
        {
            //Update the send buffer
            state.SendBuffer.Erase( 0, ackno - state.last_acked );
            state.last_acked = ackno;
        }

        //Calculate RTT
        //Unimplemented
    }

    //Process data if the connection is in the propper state to receive data
    if ( tcplen > 0 && state.stateOfcnx != CLOSING && state.stateOfcnx != CLOSE_WAIT
            && state.stateOfcnx != LAST_ACK && state.stateOfcnx != TIME_WAIT )
    {
        //Process Data
        if ( seqno != state.last_recvd + 1 )
        {
            std::cerr << "receive_packet: recieved out of order packet, dropped" << std::endl;
        }

        else {
            std::cerr << "receive_packet: delivered " << recv_data.GetSize() << " bytes of data to the application" << std::endl;
            state.last_recvd += recv_data.GetSize();
            send_write_to_application( sock, recv_data );
            send_ack( mux, state );
        }

        //Send apropperiate acks
    }
}

enum MappingSomething {
    CLOSE_CONNECTION,
    OPEN_CONNECTION,
    TIME_WAIT_CONNECTION
};

static err_t openconnection_process( const MinetHandle &mux, const MinetHandle &sock, const Packet & p, TCPState state,
                                     ConnectionList<TCPState> &openConnections, ConnectionList<TCPState> &timeWaitConnections )
{
//    err_t err = E_OK;
//    unsigned char acceptable = 0;

//    //Process reset packets first
//    if ( IS_RST(flags) ) {
//        //Determine if it is an OK place to RST
//        if ( state.stateOfcnx == SYN_SENT ) {
//
//        } else {
//
//        }
//    }

//    if ( IS_ACK(flags) && state.stateOfcnx != SYN_SENT && state.stateOfcnx != SYN_RCVD ) {
//
//    }

    MappingSomething somewhere = CLOSE_CONNECTION;

    switch ( state.stateOfcnx )
    {
    case SYN_SENT:
        if ( IS_SYN(flags) && IS_ACK(flags) )
        {
            send_ack( mux, state );
            send_empty_write_to_application( sock );
            std::cerr << "listeningconnection_process: recieved SYNACK, connection transitioned from SYN_SENT to ESTABLISHED" << std::endl;
            state.stateOfcnx = ESTABLISHED;
            somewhere = OPEN_CONNECTION;
        }
        break;
    case SYN_RCVD:
        if ( IS_ACK(flags) )
        {
            receive_packet( mux, sock, state );
            send_empty_write_to_application( sock );
            std::cerr << "listeningconnection_process: recieved ACK, connection transitioned from SYN_RCVD to ESTABLISHED" << std::endl;
            state.stateOfcnx = ESTABLISHED;
            somewhere = OPEN_CONNECTION;
        }
        break;
    case CLOSE_WAIT:
        receive_packet( mux, sock, state ); //Should ignore data
        somewhere = OPEN_CONNECTION;
        break;
    case ESTABLISHED:
        receive_packet( mux, sock, state );
        somewhere = OPEN_CONNECTION;
        if ( IS_FIN(flags) )
        {
            send_ack( mux, state );
            send_empty_write_to_application( sock );
            std::cerr << "listeningconnection_process: recieved FIN, connection transitioned from ESTABLISHED to CLOSE_WAIT" << std::endl;
            state.stateOfcnx = CLOSE_WAIT;
        }
        break;
    case FIN_WAIT1:
        receive_packet( mux, sock, state );
        if ( IS_FIN(flags) )
        {
            if ( IS_ACK(flags) && ackno == state.last_recvd ) //??
            {
                send_ack( mux, state );
                state.stateOfcnx = TIME_WAIT;
                std::cerr << "listeningconnection_process: recieved FINACK, connection transitioned from FIN_WAIT1 to TIME_WAIT" << std::endl;
                somewhere = TIME_WAIT_CONNECTION;
            }
            else
            {
                send_ack( mux, state );
                state.stateOfcnx = CLOSING;
                std::cerr << "listeningconnection_process: recieved FIN, connection transitioned from FIN_WAIT1 to CLOSING" << std::endl;
                somewhere = OPEN_CONNECTION;
            }
        }
        else if ( IS_ACK(flags) && ackno == state.last_recvd )   //??
        {
            state.stateOfcnx = FIN_WAIT2;
            std::cerr << "listeningconnection_process: recieved ACK, connection transitioned from FIN_WAIT1 to FIN_WAIT2" << std::endl;
            somewhere = OPEN_CONNECTION;
        }
        break;
    case FIN_WAIT2:
        receive_packet( mux, sock, state );
        if ( IS_FIN(flags) )
        {
            send_ack( mux, state );
            state.stateOfcnx = TIME_WAIT;
            std::cerr << "listeningconnection_process: recieved FIN, connection transitioned from FIN_WAIT2 to TIME_WAIT" << std::endl;
            somewhere = TIME_WAIT_CONNECTION;
        }
        break;
    case CLOSING:
        receive_packet( mux, sock, state );
        if ( IS_ACK(flags) == state.last_recvd  )
        {
            state.stateOfcnx = TIME_WAIT;
            std::cerr << "listeningconnection_process: recieved ACK, connection transitioned from CLOSING to TIME_WAIT" << std::endl;
            somewhere = TIME_WAIT_CONNECTION;
        }
        break;
    case LAST_ACK:
        receive_packet( mux, sock, state ); //should ignore data
        if ( IS_ACK(flags) == state.last_recvd  )
        {
            somewhere = CLOSE_CONNECTION;
            std::cerr << "listeningconnection_process: recieved ACK, connection transitioned from LAST_ACK to CLOSED" << std::endl;
        }
        break;
    }

    ConnectionToStateMapping<TCPState> newMapping;

    switch ( somewhere )
    {
        case CLOSE_CONNECTION:
            break;
        case OPEN_CONNECTION:
            newMapping = ConnectionToStateMapping<TCPState>(recvConnection, Time() + 80, state, false);
            openConnections.push_back(newMapping);
            break;
        case TIME_WAIT_CONNECTION:
            break;
    }

    return E_OK;
}

void listeningconnection_process( const MinetHandle &mux, TCPState state, ConnectionList<TCPState> &openConnections )
{
    if ( state.stateOfcnx != LISTEN )
    {
        std::cerr << "listeningconnection_process: connection not in LISTEN state, packet dropped" << std::endl;
        return;
    }

    if ( IS_ACK(flags) )
    {
        //Could send RST here
    }

    else if ( IS_SYN(flags) )
    {
        std::cerr << "listeningconnection_process: SYN received" << std::endl;

        TCPState newState(1234, SYN_RCVD, 3); //1234 is the initial sequence number
        newState.last_recvd = seqno;

        //Send SYNACK
        send_synack(mux, newState );

        //Create and save mapping
        ConnectionToStateMapping<TCPState> newMapping(recvConnection, Time() + 80, newState, false);
        openConnections.push_back(newMapping);
    }
}

void timewaitconnection_process( )
{
    std::cerr << "timewaitconnection_process: packet dropped because connection already entered TIME_WAIT state" << std::endl;
}

void handle_mux(const MinetHandle &mux, const MinetHandle &sock, Packet & p,
                ConnectionList<TCPState> &openConnections, ConnectionList<TCPState> &timeWaitConnections, ConnectionList<TCPState> &listeningConnections)
{
    IPHeader ipHeader = p.FindHeader(Headers::IPHeader);

    unsigned short packetLen;
    unsigned char ipHeaderLen;

    ipHeader.GetTotalLength(packetLen);
    ipHeader.GetHeaderLength(ipHeaderLen);
    ipHeaderLen *= 4;

    //TCP Header would not fit in packet, drop packet
    if ( (unsigned)(packetLen - ipHeaderLen) < (unsigned)TCP_HEADER_BASE_LENGTH )
    {
        std::cerr << "handle_mux: short packet " << packetLen << " bytes dropped" << std::endl;
        return;
    }

    TCPHeader tcpHeader = p.FindHeader(Headers::TCPHeader);

    //Bad checksum, packet dropped
    if ( !ipHeader.IsChecksumCorrect() || !tcpHeader.IsCorrectChecksum( p ) )
    {
        std::cerr << "handle_mux: packet dropped because of bad checksum" << std::endl;
        return;
    }

    //Extract data from packet
    tcpHeader.GetSourcePort(tcphdr.src);
    tcpHeader.GetDestPort(tcphdr.dest);

    tcpHeader.GetSeqNum(tcphdr.seqno);
    seqno = tcphdr.seqno;

    tcpHeader.GetAckNum(tcphdr.ackno);
    ackno = tcphdr.ackno;

    tcpHeader.GetWinSize(tcphdr.wnd);

    tcpHeader.GetFlags(flags);

    unsigned char tcpHeaderLen;
    tcpHeader.GetHeaderLen(tcpHeaderLen);
    tcpHeaderLen *= 4;

    tcplen = packetLen - ipHeaderLen - tcpHeaderLen + ( ( IS_FIN(flags) || IS_SYN(flags) ) ? 1 : 0 );

    ipHeader.GetProtocol(recvConnection.protocol);
    ipHeader.GetDestIP(recvConnection.src);
    ipHeader.GetSourceIP(recvConnection.dest);
    tcpHeader.GetDestPort(recvConnection.srcport);
    tcpHeader.GetSourcePort(recvConnection.destport);

    //Get Payload
    recv_data = p.GetPayload().ExtractFront( packetLen - ipHeaderLen - tcpHeaderLen );

    //Demultiplex Packet
    ConnectionList<TCPState>::iterator iterator = openConnections.FindMatching(recvConnection);
    if ( iterator != openConnections.end() )
    {
        TCPState temp = iterator->state;
        openConnections.erase(iterator);
        openconnection_process( mux, sock, p, temp, openConnections, timeWaitConnections );
        return;
    }

    //If search failed, check TIME_WAIT connections
    iterator = timeWaitConnections.FindMatching(recvConnection);
    if ( iterator != timeWaitConnections.end() )
    {
        TCPState temp = iterator->state;
        openConnections.erase(iterator);
        timewaitconnection_process();
        return;
    }

    //If search failed again, try LISTENing connections
    iterator = listeningConnections.FindMatching(recvConnection);
    if ( iterator != listeningConnections.end() )
    {
        listeningconnection_process(mux, iterator->state, openConnections);
        return;
    }

    std::cerr << "handle_mux: packet dropped because it did match any connection " << std::endl;
}

#endif // TCP_IN_H_INCLUDED
