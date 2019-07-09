#pragma once
#include "main.h"


#define MAX_SRL	65495
#define MAX_RL	65498
#define MIN_RL	3
#define MAX_FDL	65517
#define TL_HEADER_MIN_LENGTH 11
#define TL_PACKET_MAX_LENGTH   65535


// Флаги заголовка транспортного уровня
struct  TLH_FL_bits {
	unsigned	PR : 2;	//Priority
	unsigned	CMP : 1; //Compressed
	unsigned	ENA : 2; //(Encryption Algorithm)
	unsigned	RTE : 1; //(Route)
	unsigned	PRF : 2; //Prefix of TLH
} ;

union T_TLH_FL {
	BYTE value;
	struct TLH_FL_bits bitfield;
};

//Коды результатов обработки протокола транспортного уровня
enum TLErrors {
	EGTS_PC_OK = 0,
	EGTS_PC_IN_PROGRESS,
	EGTS_PC_UNS_PROTOCOL = 128,
	EGTS_PC_DECRYPT_ERROR,
	EGTS_PC_PROC_DENIED,
	EGTS_PC_INC_HEADERFORM,
	EGTS_PC_INC_DATAFORM,
	EGTS_PC_UNS_TYPE,
	EGTS_PC_NOTEN_PARAMS,
	EGTS_PC_DBL_PROC,
	EGTS_PC_PROC_SRC_DENIED,
	EGTS_PC_HEADERCRC_ERROR,
	EGTS_PC_DATACRC_ERROR,
	EGTS_PC_INVDATALEN,
	EGTS_PC_ROUTE_NFOUND,
	EGTS_PC_ROUTE_CLOSED,
	EGTS_PC_ROUTE_DENIED,
	EGTS_PC_INVADDR,
	EGTS_PC_TTLEXPIRED,
	EGTS_PC_NO_ACK,
	EGTS_PC_OBJ_NFOUND,
	EGTS_PC_EVNT_NFOUND,
	EGTS_PC_SRVC_NFOUND,
	EGTS_PC_SRVC_DENIED,
	EGTS_PC_SRVC_UNKN,
	EGTS_PC_AUTH_DENIED,
	EGTS_PC_ALREADY_EXISTS,
	EGTS_PC_ID_NFOUND,
	EGTS_PC_INC_DATETIME,
	EGTS_PC_IO_ERROR,
	EGTS_PC_NO_RES_AVAIL,
	EGTS_PC_MODULE_FAULT,
	EGTS_PC_MODULE_PWR_FLT,
	EGTS_PC_MODULE_PROC_FLT,
	EGTS_PC_MODULE_SW_FLT,
	EGTS_PC_MODULE_FW_FLT,
	EGTS_PC_MODULE_IO_FLT,
	EGTS_PC_MODULE_MEM_FLT,
	EGTS_PC_TEST_FAILED
};


struct  RFLbits {
	unsigned	OBFE : 1;
	unsigned	EVFE : 1;
	unsigned	TMFE : 1;
	unsigned	RPP : 2;
	unsigned	GRP : 1;
	unsigned	RSOD : 1;
	unsigned	SSOD : 1;
};

union T_RFL {
	BYTE value;
	struct RFLbits bitfield;
};


class SubRecord
{
public:
	TLErrors ParseSubRecord(size_t &, const vector<BYTE>& );
	void PrintSubRecord();
	SubRecord();
	~SubRecord();

private:
	BYTE SRT; //Subrecord Type
	USHORT SRL;//Subrecord Length
	vector<BYTE>SRD;//Subrecord Data
};

class Record
{
public:
	TLErrors Record::ParseRecord(size_t &, const vector<BYTE>&);
	void PrintRecord();
	Record();
	~Record();

private:
	USHORT RL;//Record Length
	USHORT RN;//Record Number
	T_RFL RFL;// Record Flags
	UINT OID;//Object Indetifier
	UINT EVID;//Event Indetifier
	UINT TM; //Time
	BYTE SST;//Source Service Type
	BYTE RST;//Recipient Service Type
	vector<BYTE>RD; //Record Data
	vector<SubRecord*> subrecords; //
};


class TLHeader
{
public:
	TLHeader();
	~TLHeader();

	void ParseTransportLayer( const vector<BYTE>&);
	void PrintTL();
private:
	BYTE PRV;//Protocol Version
	BYTE SKID;//Security Kei Id
	T_TLH_FL HFL;//Header Flags
	BYTE HL;//Header Length
	BYTE HE;//Header Encoding
	USHORT FDL; //Frame Data Length
	USHORT PID; //Packet idetifier
	BYTE PT;// Packet Type
	USHORT PRA;//Peer Adress
	USHORT RCA; //Recipient adress
	BYTE TTL;//Time to live
	BYTE HCS; //Header Check Sum CRC8
	USHORT SFRCS; //Services Frame Data Check Sum CRC16 
	vector<Record*> records;
	TLErrors ValidatingResult;
};


