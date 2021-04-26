#ifndef DATA_LOG_H
#define DATA_LOG_H

struct DataLog{
		
	int sc_packets         = 0; // sent and received packets.
	int filtered_packets   = 0;
	int active_sessions    = 0;
	int deactived_sessions = 0;
	int new_sessions       = 0;
	size_t sc_size_byte    = 0; // size of data sent and received.
	size_t filtered_size   = 0;

} data_log;

#endif
