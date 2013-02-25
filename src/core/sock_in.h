#ifndef SOCK_IN_H_INCLUDED
#define SOCK_IN_H_INCLUDED

//This code is unchanged from before

static void send_syn( const MinetHandle &mux, Connection & c, TCPState & state )
{
    Packet ret;

    //Set IP Header
    IPHeader ipHeader;
    ipHeader.SetSourceIP(c.src);
    ipHeader.SetDestIP(c.dest);
    ipHeader.SetTotalLength(IP_HEADER_BASE_LENGTH + TCP_HEADER_BASE_LENGTH);
    ipHeader.SetProtocol(IP_PROTO_TCP);

    ret.PushFrontHeader(ipHeader);

    //Set TCP Header
    TCPHeader tcpHeader;
    tcpHeader.SetSourcePort(c.srcport, ret);
    tcpHeader.SetDestPort(c.destport, ret);
    tcpHeader.SetHeaderLen(TCP_HEADER_BASE_LENGTH / 4, ret);
    //tcpHeader.SetAckNum(state.GetLastRecvd() + 1, ret);
    tcpHeader.SetSeqNum(state.last_sent, ret);
    tcpHeader.SetWinSize(state.GetN(), ret);
    tcpHeader.SetUrgentPtr(0, ret);

    unsigned char tempFlags = 0;
    SET_SYN(tempFlags);
    tcpHeader.SetFlags(tempFlags, ret);

    ret.PushBackHeader(tcpHeader);

    MinetSend(mux, ret);

    std::cerr << "send_syn: SYN sent" << std::endl;

    state.last_sent++;
}

void send_data( const MinetHandle & mux, const Connection & c, TCPState & state )
{
    unsigned i = 0;

    std::cerr << "send_data: sending " << state.SendBuffer.GetSize() << " bytes of data over the network"<< std::endl;

    while ( i < state.SendBuffer.GetSize() )
    {
        unsigned unsentDataInBuffer = state.SendBuffer.GetSize() - i;
        unsigned dataToSend = ( unsentDataInBuffer < 536 ) ? unsentDataInBuffer : 536;

        char tempStorage[10000];
        state.SendBuffer.GetData( tempStorage, dataToSend, i );

        Packet ret( Buffer(tempStorage, dataToSend) );

        //Set IP Header
        IPHeader ipHeader;
        ipHeader.SetSourceIP(c.src);
        ipHeader.SetDestIP(c.dest);
        ipHeader.SetTotalLength(IP_HEADER_BASE_LENGTH + TCP_HEADER_BASE_LENGTH + dataToSend);
        ipHeader.SetProtocol(IP_PROTO_TCP);

        ret.PushFrontHeader(ipHeader);

        //Set TCP Header
        TCPHeader tcpHeader;
        tcpHeader.SetSourcePort(c.srcport, ret);
        tcpHeader.SetDestPort(c.destport, ret);
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

        std::cerr << "send_data: sent " << dataToSend << " bytes of data over the network"<< std::endl;

        state.last_sent += dataToSend;
        i += dataToSend;
    }
}

#define PORT_BASE 50000

void handle_sock(const MinetHandle &mux, const MinetHandle &sock,
                 ConnectionList<TCPState> &openConnections, ConnectionList<TCPState> &listeningConnections )
{
    SockRequestResponse s;
    MinetReceive(sock,s);

    if ( s.type == FORWARD )
    {
        SockRequestResponse repl;
        repl.type = STATUS;
        repl.error = ENOT_SUPPORTED;
        repl.bytes = 0;
        MinetSend(sock, repl );
    }

    //First, look for a matching open TCP connection
    ConnectionList<TCPState>::iterator associatedState = openConnections.FindMatching(s.connection);
    if ( associatedState != openConnections.end() )
    {

        if ( s.type == CLOSE )
        {
            std::cerr << "Application close request recieved, " << s.connection << std::endl;

            //Save the connection state and remove the mapping from the queue
            TCPState oldState = associatedState->state;
            openConnections.erase( associatedState );

            //If already recieved FIN from other end, passive close
            if ( oldState.stateOfcnx == CLOSE_WAIT )
            {
                //Adjust the connection state
                oldState.stateOfcnx = LAST_ACK;

                //Create the mapping
                ConnectionToStateMapping<TCPState> newMapping(s.connection, Time() + 80, oldState, false);

                //Modify and save mapping
                newMapping.state.last_sent++;
                openConnections.push_back( newMapping );

                //Send packet
                //MinetSend(mux, CraftSimplePacket(newMapping, E_FIN) );
                std::cerr << "Passive Close, ACK sent" << std::endl;
            }

            //Active Close
            else if ( oldState.stateOfcnx == ESTABLISHED || oldState.stateOfcnx == SYN_RCVD )
            {
                //Adjust the connection state
                oldState.stateOfcnx = FIN_WAIT1;

                //Create the mapping
                ConnectionToStateMapping<TCPState> newMapping(s.connection, Time() + 80, oldState, false);

                //Send packet
                //MinetSend(mux, CraftSimplePacket(newMapping, E_FIN) );
                if ( oldState.stateOfcnx == ESTABLISHED )
                    std::cerr << "Active Close, FIN sent" << std::endl;
                else
                    std::cerr << "Active Close, Connection Never Established, FIN sent" << std::endl;

                //Modify and save mapping
                newMapping.state.last_sent++;
                openConnections.push_back( newMapping );

                //Send Response to Application Layer
                SockRequestResponse repl;
                repl.type = STATUS;
                repl.error = EOK;
                repl.connection = s.connection;
                MinetSend(sock, repl );
            }

            else if ( oldState.stateOfcnx == SYN_SENT )
            {
                //Send Response to Application Layer
                SockRequestResponse repl;
                repl.type = STATUS;
                repl.error = EOK;
                repl.connection = s.connection;
                MinetSend(sock, repl );

                std::cerr << "Active Close, SYN Aborted, FIN sent" << std::endl;
            }
        }

        else if ( s.type == STATUS )
        {
            //std::cerr << "Received STATUS on SOCK" << std::endl;
        }

        else if ( s.type == CONNECT )
        {
            std::cerr << "Tried to open an already existing connection" << std::endl;
        }

        else if ( s.type == WRITE )
        {
            std::cerr << "handle_mux: writing data to a connection" << std::endl;

            TCPState oldState = associatedState->state;
            openConnections.erase( associatedState );

            unsigned sendBufferFreeSpace = oldState.TCP_BUFFER_SIZE - oldState.RecvBuffer.GetSize();
            unsigned dataWritten = ( s.data.GetSize() < sendBufferFreeSpace ) ? s.data.GetSize() : sendBufferFreeSpace;

            oldState.RecvBuffer.AddBack( s.data.ExtractFront( dataWritten ) );
            send_data( mux, s.connection, oldState );

            //Create and push mapping
            ConnectionToStateMapping<TCPState> stateMapping(s.connection, Time() + 80, oldState, false);
            listeningConnections.push_back(stateMapping);

            //Send reply to application
            SockRequestResponse repl;
            repl.type = STATUS;
            repl.error = EOK;
            repl.bytes = dataWritten;
            repl.connection = s.connection;
            MinetSend(sock, repl );
        }

        else
        {
            std::cerr << "Received Unhandled Socket Request: " << s << std::endl;
        }

        return;
    }

    //Active Open
    if ( s.type == CONNECT )
    {
        s.connection.srcport += PORT_BASE;
        std::cerr << "handle_sock: active open requested for " << s.connection << std::endl;

        //Create State
        TCPState synSent(4444, SYN_SENT, 0);

        //Send Packet
        send_syn( mux, s.connection, synSent );

        //Create and save mapping
        ConnectionToStateMapping<TCPState> stateMapping(s.connection, Time(), synSent, false);
        openConnections.push_back(stateMapping);

        //Send STATUS OK to Application Layer
        SockRequestResponse repl;
        repl.type = STATUS;
        repl.error = EOK;
        repl.connection = s.connection;
        MinetSend( sock, repl );

        return;
    }

    if ( s.type == WRITE )
    {
        std::cerr << "handle_mux: tried to write to an unmatched connection" << std::endl;
        SockRequestResponse repl;
        repl.type = STATUS;
        repl.error = ENOMATCH;
        repl.bytes = 0;
        repl.connection = s.connection;
        MinetSend(sock, repl );

        return;
    }

    if ( s.type == CLOSE )
    {
        std::cerr << "handle_mux: tried to close to an unmatched connection" << std::endl;
        SockRequestResponse repl;
        repl.type = STATUS;
        repl.error = ENOMATCH;
        repl.bytes = 0;
        repl.connection = s.connection;
        MinetSend(sock, repl );

        return;
    }

    //If the connection does not match with an open connection, check listening connections
    if ( s.type == ACCEPT )
    {
        ConnectionList<TCPState>::iterator associatedState = listeningConnections.FindMatching(s.connection);

        if ( associatedState == listeningConnections.end() )
        {
            std::cerr << "Received Request to Accept Connections on " << s.connection << std::endl;
            TCPState accept(0, LISTEN, 0);
            ConnectionToStateMapping<TCPState> stateMapping(s.connection, Time(), accept, false);
            listeningConnections.push_back(stateMapping);

            //Send STATUS OK to Application Layer
            SockRequestResponse repl;
            repl.type = STATUS;
            repl.error = EOK;
            repl.connection = s.connection;
            MinetSend(sock, repl );
        }

        else
        {
            std::cerr << "Tried to open an already existing connection" << std::endl;
        }

        return;
    }

    std::cerr << "Received Completely Unhandled Socket Request: " << s << std::endl;
}

#endif // SOCK_IN_H_INCLUDED
