#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>


#include <iostream>

#include "Minet.h"
#include "tcpstate.h"

#include <queue>

using std::cout;
using std::endl;
using std::cerr;
using std::string;
using std::queue;


int ConditionalMinetSend(const MinetHandle &handle, const Packet &object) {
    int send = rand() % 3; 
    if (send != 1) {
        MinetSend(handle, object);
    } else
        cerr << endl << endl << "NOPEEEEEEEEE" << endl << endl;
    return 0;
}

Packet MakeTCPPacket(const Connection c, const unsigned int &id, const unsigned int &seqnum, const unsigned int &acknum, const unsigned short &winsize, const unsigned char &hlen, const unsigned short &urgptr, const unsigned char &flags, const char *data, const size_t datalen) {

    Packet p(data, datalen);
//    Packet p;
    IPHeader ih;
    TCPHeader th;

    ih.SetProtocol(IP_PROTO_TCP);
    ih.SetSourceIP(c.src);
    ih.SetDestIP(c.dest);
    ih.SetTotalLength(TCP_HEADER_BASE_LENGTH + IP_HEADER_BASE_LENGTH);
    ih.SetID(id);

    p.PushFrontHeader(ih);

    th.SetDestPort(c.destport, p);
    th.SetSourcePort(c.srcport, p);
    th.SetSeqNum(seqnum, p);
    th.SetAckNum(acknum, p);
    th.SetWinSize(winsize, p);
    th.SetHeaderLen(hlen, p);
    th.SetUrgentPtr(urgptr, p);
    th.SetFlags(flags, p);

    p.PushBackHeader(th);

    //cerr << ih << endl;

    //cerr << th << endl;

    return p;

}

int main(int argc, char *argv[])
{
    srand(time(NULL));
    MinetHandle mux, sock;

    ConnectionList<TCPState> clist;
    queue<SockRequestResponse> SocksPending;

    MinetInit(MINET_TCP_MODULE);

    mux=MinetIsModuleInConfig(MINET_IP_MUX) ? MinetConnect(MINET_IP_MUX) : MINET_NOHANDLE;
    sock=MinetIsModuleInConfig(MINET_SOCK_MODULE) ? MinetAccept(MINET_SOCK_MODULE) : MINET_NOHANDLE;

    if (MinetIsModuleInConfig(MINET_IP_MUX) && mux==MINET_NOHANDLE) {
        MinetSendToMonitor(MinetMonitoringEvent("Can't connect to mux"));
        return -1;
    }

    if (MinetIsModuleInConfig(MINET_SOCK_MODULE) && sock==MINET_NOHANDLE) {
        MinetSendToMonitor(MinetMonitoringEvent("Can't accept from sock module"));
        return -1;
    }

    MinetSendToMonitor(MinetMonitoringEvent("tcp_module handling TCP traffic"));

    MinetEvent event;
  
    double min_timeout = -1;

    Buffer tdata;
    Buffer &data = tdata;

	unsigned char oldflags;

	unsigned int acknum = 0;
	unsigned int &acknumr = acknum;

	unsigned int seqnum = 0;
	unsigned int &seqnumr = seqnum;

	unsigned short winsize = 14600;
	unsigned short &winsizer = winsize;

	unsigned char hlen = 5;
	unsigned char &hlenr = hlen;

	unsigned short uptr = 0;
	unsigned short &uptrr = uptr;

	unsigned int id = rand() % 10000;
	unsigned int &idr = id;

	unsigned char flags = 0;
	unsigned char &flagsr = flags;

    while (MinetGetNextEvent(event, min_timeout)==0) {
        flags = 0;
        // if we received an unexpected type of event, print error
        if (event.eventtype!=MinetEvent::Dataflow 
	    || event.direction!=MinetEvent::IN) {
            MinetSendToMonitor(MinetMonitoringEvent("Unknown event ignored."));
        // if we received a valid event from Minet, do processing
        } else {
            //  Data from the IP layer below  //
            if (event.handle==mux) {
	            Packet p;
	            MinetReceive(mux,p);
	            unsigned tcphlen=TCPHeader::EstimateTCPHeaderLength(p);
	
	            p.ExtractHeaderFromPayload<TCPHeader>(tcphlen);
	            IPHeader ipl=p.FindHeader(Headers::IPHeader);
	            TCPHeader tcph=p.FindHeader(Headers::TCPHeader);
    
	            cerr << "TCP Packet: IP Header is "<<ipl<<" and ";
	            cerr << "TCP Header is "<<tcph << " and ";

                cerr << endl << endl;

	            //cerr << "Checksum is " << (tcph.IsCorrectChecksum(p) ? "VALID" : "INVALID");

                tcph.GetFlags(oldflags);
                tcph.GetSeqNum(acknumr);
	            tcph.GetAckNum(seqnumr);
	            tcph.GetWinSize(winsizer);
	            tcph.GetFlags(oldflags);

                if (seqnum == 0) 
                    seqnum = rand() % 50000;

                Connection c;

                ipl.GetSourceIP(c.dest);
                ipl.GetDestIP(c.src);
                tcph.GetDestPort(c.srcport);
                tcph.GetSourcePort(c.destport);
                c.protocol = IP_PROTO_TCP;

                ConnectionList<TCPState>::iterator cs = clist.FindMatching(c);


	            if (cs == clist.end()) {
       
                    cerr << "GOT THIS SHIT" << endl;

                    c.dest = IPAddress(IP_ADDRESS_ANY);
                    c.destport = PORT_ANY;

	                cerr << "Not listening for: " << c << endl << endl;

	            }

                if ((*cs).connection.dest == IPAddress(IP_ADDRESS_ANY) || (*cs).connection.destport == PORT_ANY) {
        
                    (*cs).connection.dest = c.dest;
                    (*cs).connection.destport = c.destport;

                }

                cerr << (*cs).state.GetState() << endl;

                //if (IS_RST(oldflags)) // TEMP
                //    getchar();


	    switch ((*cs).state.GetState()) {
	        case LISTEN: 
		        if ((IS_SYN(oldflags) && !IS_ACK(oldflags)) || IS_RST(oldflags)) {
                    cerr << "PASSIVE OPEN" << endl;
                    (*cs).state.SetState(SYN_RCVD);
		            (*cs).state.SetLastSent(seqnum);
		            (*cs).state.SetSendRwnd(winsize);

            	    SET_SYN(flags);
            	    SET_ACK(flags);

            	    Packet newp = MakeTCPPacket(c, idr, seqnumr, acknumr + 1, winsizer, hlenr, uptrr, flagsr, "", 0);


            	    MinetSend(mux, newp);

                    (*cs).state.SetLastRecvd(acknumr + 1);
		        }
		        break;

	        case SYN_SENT: 
		    
                if (IS_SYN(oldflags) && IS_ACK(oldflags)) {
	    
		            cerr << "ACTIVE OPEN ACK" << endl;
		            (*cs).state.SetState(ESTABLISHED);

	    	        SET_ACK(flags);

	    	        Packet newp = MakeTCPPacket(c, idr, seqnumr, acknumr + 1, winsizer, hlenr, uptrr, flagsr, "", 0);

	    	        MinetSend(mux, newp);

                    SockRequestResponse write(WRITE, 
                                            (*cs).connection, 
                                            data, 
                                            0, 
                                            EOK);

                    MinetSend(sock, write);

                    (*cs).state.SetLastRecvd(acknumr + 1);

	            } else if (IS_SYN(oldflags)) {
		    
                    cerr << "PASSIVE OPEN" << endl;
                    
                    (*cs).state.SetState(SYN_RCVD);
                    (*cs).state.SetLastSent(seqnum);
                    (*cs).state.SetSendRwnd(winsize);

		            SET_SYN(flags);
                    SET_ACK(flags);

		            Packet newp = MakeTCPPacket(c, idr, seqnumr, acknumr + 1, winsizer, hlenr, uptrr, flagsr, "", 0);

		            MinetSend(mux, newp);

                    (*cs).state.SetLastRecvd(acknumr + 1);

		        }
		        break;

	        case SYN_RCVD: 
		        if (IS_ACK(oldflags) && !IS_PSH(oldflags)) {

		            cerr << "PASSIVE OPEN ACK" << endl;
		    
                    (*cs).state.SetState(ESTABLISHED);

                    // set last acked

		            //(*cs).bTmrActive = 0;

		        } else if ((IS_SYN(oldflags) && !IS_ACK(oldflags)) || IS_RST(oldflags)) {
		            // synack dropped
		   
                    cerr << "SYNACK DROPPED" << endl;

		            (*cs).state.SetLastSent(seqnum);
                    (*cs).state.SetSendRwnd(winsize);		    

		            SET_SYN(flags);
                    SET_ACK(flags);

                    Packet newp = MakeTCPPacket(c, idr, seqnumr, acknumr + 1, winsizer, hlenr, uptrr, flagsr, "", 0);

                    MinetSend(mux, newp);

                    (*cs).state.SetLastRecvd(acknumr + 1);
		        }
		        break;

	        case ESTABLISHED: 
		    
                if (IS_FIN(oldflags)) {
		    
                    cerr << endl << "FOUND FIN!" << endl;
		    
		            (*cs).state.SetState(CLOSE_WAIT);

		            SET_ACK(flags);

		            Packet newp = MakeTCPPacket(c, idr, seqnumr, acknumr + 1, winsizer, hlenr, uptrr, flagsr, "", 0);

		            MinetSend(mux, newp);

		            SockRequestResponse close(CLOSE, 
						(*cs).connection, 
						data, 
						hlenr, // trash
						EOK); 

		            MinetSend(sock, close);

                    (*cs).state.SetLastRecvd(acknumr + 1);

		        } //else if (IS_ACK(oldflags) && !IS_PSH(oldflags)) {

			        // recvd ack, set last acked

		        else if (IS_RST(oldflags)) {

		            cerr << endl << "RESET CONN!" << endl;

		            (*cs).state.SetLastSent(seqnum);
		            (*cs).state.SetSendRwnd(winsize);

		            SET_SYN(flags);
		            SET_ACK(flags);

		            Packet newp = MakeTCPPacket(c, idr, seqnumr, acknumr + 1, winsizer, hlenr, uptrr, flagsr, "", 0);

                    MinetSend(mux, newp);

                    (*cs).state.SetLastRecvd(acknumr + 1);

	 	        } else {

		            cerr << "GOT DATA PACKET!" << endl;

		            unsigned short templen = 0;
		            unsigned short &templenr = templen;

		            unsigned char temphlen = 0;
		            unsigned char &temphlenr = temphlen;

		            ipl.GetTotalLength(templenr);
		            ipl.GetHeaderLength(temphlenr);

		            templen -= 4 * temphlen + tcphlen;

		            data = p.GetPayload().ExtractFront(templen);

		            cerr << endl << data << endl << endl;

            	    SockRequestResponse write(WRITE,
                                        	(*cs).connection,
                                        	data,
                                        	templen,
                                        	EOK);

		            MinetSend(sock, write);

                    SocksPending.push(write);

		            SET_ACK(flags);

		            Packet newp = MakeTCPPacket(c, idr, seqnumr, acknumr + templen, winsizer, hlenr, uptrr, flagsr, "", 0);

                    cerr << newp << endl << endl << acknum << endl << templen << endl;

                    (*cs).state.SetLastRecvd(acknumr + templen);

		            MinetSend(mux, newp);
		        }
		        break;

            case FIN_WAIT1: 
            
                if (IS_FIN(oldflags)) { // simultaneous close

                    cerr << endl << "FOUND FIN!" << endl;
		    
		            (*cs).state.SetState(TIME_WAIT);

		            SET_ACK(flags);

		            Packet newp = MakeTCPPacket(c, idr, seqnumr, acknumr + 1, winsizer, hlenr, uptrr, flagsr, "", 0);

		            MinetSend(mux, newp);

                    (*cs).state.SetLastRecvd(acknumr + 1);


                } else if (IS_ACK(oldflags) && !IS_PSH(oldflags)) {
            
                    cerr << endl << "FOUND CLOSE ACK" << endl;

                    (*cs).state.SetState(FIN_WAIT2);

                    (*cs).state.SetLastRecvd(acknumr + 1);

                }
                break;

                case FIN_WAIT2: 
        
                    if (IS_FIN(oldflags)) {

                        cerr << endl << "GOT FIN" << endl;

                        (*cs).state.SetState(TIME_WAIT);

                        SET_ACK(flags);

		                Packet newp = MakeTCPPacket(c, idr, seqnumr, acknumr + 1, winsizer, hlenr, uptrr, flagsr, "", 0);

		                MinetSend(mux, newp);

                        (*cs).state.SetLastRecvd(acknumr + 1);

                    }
                    break;
        
                case LAST_ACK: 

                    if (IS_ACK(oldflags)) {

                        clist.erase(cs);

                        // any other wrap-up? 

                    }
                    break;
	        }

        }
        //  Data from the Sockets layer above  //
        if (event.handle==sock) {
	        SockRequestResponse s;
	        MinetReceive(sock,s);
	        cerr << "Received Socket Request:" << s << endl;

	        ConnectionList<TCPState>::iterator cs = clist.FindMatching(s.connection);

            ConnectionToStateMapping<TCPState> m;

	        if (cs == clist.end()) {
	            m.connection = s.connection;
	            m.state.SetState(CLOSED);
	            clist.push_back(m);
	  
	            cerr << m << endl << endl;

                cs = clist.FindMatching(s.connection);

	        }

            Packet newp;
            unsigned int len = 0;
            unsigned int sending = 0;
            char *datachars = NULL;


	        switch (s.type) {
	            case CONNECT: {
            
                    cerr << "ACTIVE OPEN INIT!" << endl << endl;

                    seqnum = rand() % 50000;
            
                    (*cs).state.SetState(SYN_SENT);

                    SET_SYN(flags);
            
                    newp = MakeTCPPacket(s.connection, idr, seqnumr, acknumr, winsizer, hlenr, uptrr, flagsr, "", 0);

		            MinetSend(mux, newp);

                    SockRequestResponse res(STATUS, 
                                        (*cs).connection, 
                                        data, 
                                        0, 
                                        EOK);

                    MinetSend(sock, res);

                    (*cs).state.SetLastSent(seqnum);
                    (*cs).state.SetLastRecvd(acknum);
                
                }
                break;

	            case ACCEPT: {

                    cerr << "PASSIVE OPEN INIT!" << endl << endl;

                    (*cs).state.SetState(LISTEN);

                    cerr << m << endl << endl;
                
                }
                break;

	            case STATUS: {

                    if (!SocksPending.empty()) {

                        SockRequestResponse res = SocksPending.front();

                        SocksPending.pop();

                        sending = res.bytes - s.bytes;

                        if (sending != 0) {
                
                            cerr << "NOT EQUAL STATUS!" << endl << endl;

                            SockRequestResponse res(WRITE, 
                                            m.connection, 
                                            data.ExtractBack(sending), 
                                            sending, 
                                            EOK);

                            MinetSend(sock, res);

                            SocksPending.push(res);
                        }
                    }
                }
                break;
	    
                case WRITE: 

                    if (m.state.GetState() == ESTABLISHED) {

                        acknum = m.state.GetLastRecvd();

                        len = s.data.GetSize();
                        sending = 0;
                        datachars = (char *) malloc(TCP_MAXIMUM_SEGMENT_SIZE + 1);

                        SockRequestResponse res(STATUS, 
                                            m.connection, 
                                            data, 
                                            len, 
                                            EOK);

                        MinetSend(sock, res);

                        while (len > 0) {

                            memset(datachars, 0, TCP_MAXIMUM_SEGMENT_SIZE + 1);

                            seqnum = m.state.GetLastSent();

                            if (len > TCP_MAXIMUM_SEGMENT_SIZE) { // MSS 

                                sending = TCP_MAXIMUM_SEGMENT_SIZE;
                                len -= TCP_MAXIMUM_SEGMENT_SIZE;

                            } else {

                                sending = len;
                                len -= len;

                            }

                            data = s.data.ExtractFront(sending);
                            data.GetData(datachars, sending, 0);

                            newp = MakeTCPPacket(s.connection, idr, seqnumr, acknumr, winsizer, hlenr, uptrr, flagsr, datachars, sending);

                            MinetSend(mux, newp);

                            (*cs).state.SetLastSent(seqnum + sending);

                        }
                        free(datachars);
                    }

                    break;

	            case FORWARD: 
                    // fix
                    break;

	            case CLOSE: 

                    //clist.erase(cs);

                    if ((*cs).state.GetState() == ESTABLISHED)
                        (*cs).state.SetState(FIN_WAIT1); // see later
                    else if ((*cs).state.GetState() == CLOSE_WAIT)
                        (*cs).state.SetState(LAST_ACK);
                    else
                        cerr << "how? -- " << (*cs).state.GetState() << endl;

                    SET_FIN(flags);

                    seqnum = m.state.GetLastSent();
                    seqnum++;
                    (*cs).state.SetLastSent(seqnum);

                    acknum = m.state.GetLastRecvd();
                    (*cs).state.SetLastRecvd(acknum);

                    newp = MakeTCPPacket(s.connection, idr, seqnumr, acknumr, winsizer, hlenr, uptrr, flagsr, "", 0);

                    MinetSend(mux, newp);

                    break;
        
	        }
        }
        if (event.eventtype == MinetEvent::Timeout) {
	    
            cerr << "GOT TIMEOUT!" << endl;
	
            ConnectionList<TCPState>::iterator i = clist.begin();
	
            for (; i != clist.end(); ++i) {
	            if ((*i).bTmrActive)
	                cerr << *i << endl;
	            }
            }

            if ((*clist.FindEarliest()).Matches((*clist.end()).connection))
	            min_timeout = -1;
            else
	            min_timeout = (*clist.FindEarliest()).timeout;
        }
    }
    return 0;
}
