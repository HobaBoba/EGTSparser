// This is an open source non-commercial project. Dear PVS-Studio, please check it.
// PVS-Studio Static Code Analyzer for C, C++ and C#: http://www.viva64.com

#include "EGTS.h"
#include "CRC.h"
#include <map>
#include <string>

enum SubRecordsTypes { EGTS_SR_TERM_IDENTITY=1, EGTS_SR_VEHICLE_DATA=3, EGTS_SR_POS_DATA=16, EGTS_SR_AD_SENSORS_DATA=18, EGTS_SR_STATE_DATA=21};
enum RecordsTypes { EGTS_AUTH_SERVICE = 1, EGTS_TELEDATA_SERVICE, EGTS_COMMANDS_SERVICE, EGTS_FIRMWARE_SERVICE};
enum PacketTypes { EGTS_PT_RESPONSE = 0, EGTS_PT_APPDATA, EGTS_PT_SIGNED_APPDATA };


typedef map<TLErrors, string> TLErrorMap;

std::ostream& operator<<(std::ostream& out, const TLErrors value) {
	static TLErrorMap errors;
	if (errors.size() == 0) 
	{
		errors.insert(TLErrorMap::value_type(EGTS_PC_OK, "Успешно обработано"));
		errors.insert(TLErrorMap::value_type(EGTS_PC_IN_PROGRESS, "В процессе обработки"));
		errors.insert(TLErrorMap::value_type(EGTS_PC_UNS_PROTOCOL, "Неподдерживаемый протокол"));
		errors.insert(TLErrorMap::value_type(EGTS_PC_DECRYPT_ERROR, "Ошибка декодирования"));
		errors.insert(TLErrorMap::value_type(EGTS_PC_PROC_DENIED, "Обработка запрещена"));
		errors.insert(TLErrorMap::value_type(EGTS_PC_INC_HEADERFORM, "Неверный формат заголовка"));
		errors.insert(TLErrorMap::value_type(EGTS_PC_INC_DATAFORM, "Неверный формат данных"));
		errors.insert(TLErrorMap::value_type(EGTS_PC_UNS_TYPE, "Неподдерживаемый тип"));
		errors.insert(TLErrorMap::value_type(EGTS_PC_NOTEN_PARAMS, "Неверное число параметров"));
		errors.insert(TLErrorMap::value_type(EGTS_PC_DBL_PROC, "Попытка повторной обработки"));
		errors.insert(TLErrorMap::value_type(EGTS_PC_PROC_SRC_DENIED, "Обработка данных от источника запрещена"));
		errors.insert(TLErrorMap::value_type(EGTS_PC_HEADERCRC_ERROR, "Ошибка контрольной суммы заголовка"));
		errors.insert(TLErrorMap::value_type(EGTS_PC_DATACRC_ERROR, "Ошибка контрольной суммы данных"));
		errors.insert(TLErrorMap::value_type(EGTS_PC_INVDATALEN, "Некорректная длина данных "));
		errors.insert(TLErrorMap::value_type(EGTS_PC_ROUTE_NFOUND, "Маршрут не найден "));
		errors.insert(TLErrorMap::value_type(EGTS_PC_ROUTE_CLOSED, "Маршрут закрыт"));
		errors.insert(TLErrorMap::value_type(EGTS_PC_ROUTE_DENIED, "Маршрутизация запрещена"));
		errors.insert(TLErrorMap::value_type(EGTS_PC_INVADDR, "Неверный адрес"));
		errors.insert(TLErrorMap::value_type(EGTS_PC_TTLEXPIRED, "Превышено количество ретрансляции данных"));
		errors.insert(TLErrorMap::value_type(EGTS_PC_NO_ACK, "Нет подтверждения"));
		errors.insert(TLErrorMap::value_type(EGTS_PC_OBJ_NFOUND, "Объект не найден "));
		errors.insert(TLErrorMap::value_type(EGTS_PC_EVNT_NFOUND, "Событие не найдено "));
		errors.insert(TLErrorMap::value_type(EGTS_PC_SRVC_NFOUND, "Сервис не найден "));
		errors.insert(TLErrorMap::value_type(EGTS_PC_SRVC_DENIED, "Сервис запрещен"));
		errors.insert(TLErrorMap::value_type(EGTS_PC_SRVC_UNKN, "Неизвестный тип сервиса "));
		errors.insert(TLErrorMap::value_type(EGTS_PC_AUTH_DENIED, "Авторизация запрещена"));
		errors.insert(TLErrorMap::value_type(EGTS_PC_ALREADY_EXISTS, "Объект уже существует "));
		errors.insert(TLErrorMap::value_type(EGTS_PC_ID_NFOUND, "Идентификатор не найден "));
		errors.insert(TLErrorMap::value_type(EGTS_PC_INC_DATETIME, "Неправильная дата и время"));
		errors.insert(TLErrorMap::value_type(EGTS_PC_IO_ERROR, "Ошибка ввода/вывода"));
		errors.insert(TLErrorMap::value_type(EGTS_PC_NO_RES_AVAIL, "Недостаточно ресурсов"));
		errors.insert(TLErrorMap::value_type(EGTS_PC_MODULE_FAULT, "Внутренний сбой модуля "));
		errors.insert(TLErrorMap::value_type(EGTS_PC_MODULE_PWR_FLT, "Сбой в работе цепи питания модуля"));
		errors.insert(TLErrorMap::value_type(EGTS_PC_MODULE_PROC_FLT, "Сбой в работе микроконтроллера модуля "));
		errors.insert(TLErrorMap::value_type(EGTS_PC_MODULE_SW_FLT, "Сбой в работе программы модуля "));
		errors.insert(TLErrorMap::value_type(EGTS_PC_MODULE_FW_FLT, "Сбой в работе внутреннего ПО модуля"));
		errors.insert(TLErrorMap::value_type(EGTS_PC_MODULE_IO_FLT, "Сбой в работе блока ввода/вывода модуля"));
		errors.insert(TLErrorMap::value_type(EGTS_PC_MODULE_MEM_FLT, "Сбой в работе внутренней памяти модуля"));
		errors.insert(TLErrorMap::value_type(EGTS_PC_TEST_FAILED, "Тест не пройден "));
	}

	return out << errors[value];
}




SubRecord::SubRecord()
{
	SRT = 0;
	SRL = 0;
};
SubRecord::~SubRecord(){};

TLErrors SubRecord::ParseSubRecord(size_t& curInd, const vector<BYTE>& packet)
{
	try
	{
	if (packet.empty())	throw EGTS_PC_NOTEN_PARAMS;
	if (curInd > packet.size()) throw "Ошибка разбора подзаписи.Текущий индекс больше размера пакета";
	SRT = packet.at(curInd++);
	SRL = (packet.at(curInd++) + USHORT((packet.at(curInd++)) << 8));
	//if (SRL > MAX_SRL) throw "Длина поля данных подзаписи превышает максимально допустимого значения ";
	if (SRL > MAX_SRL) throw EGTS_PC_INVDATALEN;
	//if (vector<BYTE>::size_type(curInd + SRL) > packet.size()) throw " Ошибка. Длина подзаписи превышает размер вектора ";
	if (vector<BYTE>::size_type(curInd + SRL) > packet.size()) throw EGTS_PC_INVDATALEN;

	vector<BYTE>::const_iterator first = packet.begin(), last = packet.begin();
	advance(first, curInd); advance(last, curInd += SRL);
	copy(first, last, back_inserter(SRD));
	}

	catch (const out_of_range&)
	{
		cout << "При разборе подзаписи обнаружен выход за диапазон  " << endl;
		curInd= packet.size();
		return EGTS_PC_MODULE_SW_FLT;
	}

	catch (TLErrors exc)
	{
		cout << exc << endl;
		curInd = packet.size();
		return exc;
	}
	catch (const char *exc)
	{
		cout  << exc << endl;
		curInd = packet.size();
		return EGTS_PC_MODULE_SW_FLT;
	}

	catch(...)
		{
			cout << "При разборе подзаписи возникла ошибка" << endl;
			curInd = packet.size();
			return EGTS_PC_MODULE_SW_FLT;
		}

	return EGTS_PC_IN_PROGRESS;
}

void SubRecord::PrintSubRecord()
{
	cout << endl << "=========================================================================" << endl;
	cout <<"Service Data Sub Record (подзапись): ";

	if (SRT == EGTS_SR_TERM_IDENTITY)
		cout << "EGTS_SR_TERM_IDENTITY";
	else if (SRT == EGTS_SR_VEHICLE_DATA)
		cout << "EGTS_SR_VEHICLE_DATA";
	else if (SRT == EGTS_SR_POS_DATA)
		cout << "EGTS_SR_POS_DATA";
	else if (SRT == EGTS_SR_AD_SENSORS_DATA)
		cout << "EGTS_SR_AD_SENSORS_DATA";
	else if (SRT == EGTS_SR_STATE_DATA)
		cout << "EGTS_SR_STATE_DATA";
	else
		cout << "Некорректный тип подзаписи!";
	cout << endl; 
	//cout << "SRT hex: " << setfill('0') << setw(2) << hex << (int16_t)SRT << " " << endl;
	cout << "Subrecord Type:\t\t" << dec << (int16_t)SRT << "," << endl;
	//cout << "SRL hex: " << setfill('0') << setw(4) << hex << (int16_t)SRL << " " << endl;
	cout << "Subrecord Length:\t" << dec << (int16_t)SRL << "," << endl;

	cout << "Subrecord Data:\t";
	for (vector<BYTE>::const_iterator i = SRD.begin(); i != SRD.end(); ++i)
	{
		//cout << *i << endl;
		cout << setfill('0') << setw(2) << hex << (int16_t)*i << " ";

	}
	cout << endl;
	cout << "=========================================================================" << endl;
};


Record::Record()
{
	RL = 0;
	RN = 0;
	RFL.value = 0;
	OID = 0;
	EVID = 0;
	TM = 0; 
	SST = 0;
	RST = 0;
}

Record::~Record()
{
	for (vector<SubRecord*>::iterator it = subrecords.begin(); it != subrecords.end(); ++it)
		delete (*it);
}


TLErrors Record::ParseRecord(size_t &curInd, const vector<BYTE>& packet)
{
	TLErrors validResultSR = EGTS_PC_IN_PROGRESS;
	try
	{	
		if (packet.empty())	throw EGTS_PC_NOTEN_PARAMS;
		if (curInd > packet.size()) throw "Ошибка разбора записи.Текущий индекс больше размера пакета";
		RL = (packet.at(curInd++) + USHORT((packet.at(curInd++) ) << 8));
		//if (RL > MAX_RL) throw "Длина поля данных записи превышает максимально допустимого значения ";
		if (RL > MAX_RL) throw EGTS_PC_INVDATALEN;
		//if (RL < MIN_RL) throw "Длина поля данных записи меньше минимально допустимого значения ";
		if (RL < MIN_RL) throw EGTS_PC_INVDATALEN;
		RN = (packet.at(curInd++) + USHORT((packet.at(curInd++)) << 8));
		
		RFL.value = packet.at(curInd++);
		if (RFL.bitfield.OBFE)
		{
			OID = (packet.at(curInd++) + UINT((packet.at(curInd++)) << 8) + UINT((packet.at(curInd++)) << 16) + UINT((packet.at(curInd++)) << 24));
		}
		if (RFL.bitfield.EVFE)
		{
			EVID = (packet.at(curInd++) + UINT((packet.at(curInd++)) << 8) + UINT((packet.at(curInd++)) << 16) + UINT((packet.at(curInd++)) << 24));
		}
		if (RFL.bitfield.TMFE)
		{
			TM = (packet.at(curInd++) + UINT((packet.at(curInd++)) << 8) + UINT((packet.at(curInd++)) << 16) + UINT((packet.at(curInd++)) << 24));
		}
		SST = packet.at(curInd++);
		RST = packet.at(curInd++);

		size_t endOfRecord = curInd + RL;
		if ( endOfRecord > (packet.size()-2) ) throw EGTS_PC_INVDATALEN;
		while ((curInd < endOfRecord)&&(validResultSR <= EGTS_PC_IN_PROGRESS))
		{
			SubRecord* subrecord = new SubRecord;
			validResultSR=subrecord->ParseSubRecord(curInd, packet);
			subrecords.push_back(subrecord);
		}
	}
	catch (const out_of_range&)
	{
		cout << "При разборе записи обнаружен выход за диапазон  " << endl;
		curInd = packet.size();
		return EGTS_PC_MODULE_SW_FLT;
	}

	catch (bad_alloc &)
	{
		cout << "Мemory allocation problem " << endl;
		curInd = packet.size();
		return EGTS_PC_MODULE_MEM_FLT;
	}

	catch (TLErrors exc)
	{
		cout << exc << endl;
		curInd = packet.size();
		return exc;
	}

	catch (const char *exc)
	{
		cout << exc << endl;
		curInd = packet.size();
		return EGTS_PC_MODULE_SW_FLT;
	}

	catch (...)
	{
		cout << "Ошибка при разборе записи  " << endl;
		curInd = packet.size();
		return EGTS_PC_MODULE_SW_FLT;
	}

	return validResultSR;
};

void Record::PrintRecord()
{	
	cout << "-------------------------------------------------------------------------" << endl;
	cout << endl << "Service Data Record (запись): ";

	if (SST == EGTS_AUTH_SERVICE)
		cout << "EGTS_AUTH_SERVICE";
	else if (SST == EGTS_TELEDATA_SERVICE)
		cout << "EGTS_TELEDATA_SERVICE";
	else
		cout << "Некорректный тип записи!";
	cout << endl;

	
	cout << "Record Length: " << dec << RL << endl;
	cout << "Record Number: " << dec << RN << endl;
	cout << endl << "Flags" << endl;
	//cout << "RFL " << hex << RFL.value << endl;
	cout << "Source Service On Device:\t" << dec << RFL.bitfield.SSOD << "," << endl;
	cout << "Recipient Service On Device:\t" << dec << RFL.bitfield.RSOD << "," << endl;
	cout << "Group:\t\t\t\t" << dec << RFL.bitfield.GRP << "," << endl;
	cout << "Record Processing Priority:\t" << dec << RFL.bitfield.RPP << "," << endl;
	cout << "Time Field Exists:\t\t" << dec << RFL.bitfield.TMFE << "," << endl;
	cout << "Event ID Field Exists:\t\t" << dec << RFL.bitfield.EVFE << "," << endl;
	cout << "Object ID Field Exists:\t\t" << dec << RFL.bitfield.OBFE << "," << endl;
	cout << endl;
	cout << "Object Identifier:\t" << dec << OID << "," << endl;
	cout << "Event Identifier:\t" << dec << EVID << "," << endl;
	cout << "Time:\t" << dec << TM << "," << endl;
	cout << "Source Service Type:\t" << dec << (uint16_t)SST << "," << endl;
	cout << "Recipient Service Type:\t" << dec <<(uint16_t) RST << "," << endl;

	for (vector<BYTE>::size_type i = 0; i < subrecords.size(); i++)
	{
	 subrecords[i]->PrintSubRecord();
	}
};


void TLHeader::ParseTransportLayer(const vector<BYTE>& packet)
{
	size_t curInd=0;
	try
	{
		if (packet.empty())	throw EGTS_PC_NOTEN_PARAMS;
		PRV=packet.at(curInd++);
		if (PRV != 0x01)	throw EGTS_PC_UNS_PROTOCOL;
		SKID = packet.at(curInd++);
		HFL.value = packet.at(curInd++);
		if (HFL.bitfield.PRF != 0)	throw EGTS_PC_UNS_PROTOCOL;
		HL = packet.at(curInd++);
		if (HL != 11 && HL != 16)	throw EGTS_PC_INC_HEADERFORM;
		HE = packet.at(curInd++);
		FDL = (packet.at(curInd++) + USHORT((packet.at(curInd++)) << 8));
		if (FDL>MAX_FDL)			throw EGTS_PC_INVDATALEN;

		PID = (packet.at(curInd++) + USHORT((packet.at(curInd++)) << 8));
		PT = packet.at(curInd++);
		if (HFL.bitfield.RTE)
		{
			PRA = (packet.at(curInd++) + USHORT((packet.at(curInd++)) << 8) );
			RCA = (packet.at(curInd++) + USHORT((packet.at(curInd++)) << 8));
			TTL = packet.at(curInd++);
		}
		HCS = packet.at(curInd++);
		if (CRC8(packet.data(), HL - 1) != HCS)	throw EGTS_PC_HEADERCRC_ERROR;	
		if (FDL > 0)
		{
			SFRCS = packet.at(HL + FDL) + USHORT((packet.at(HL + FDL + 1)) << 8);
			if (CRC16(packet.data() + HL, FDL) != SFRCS)  throw EGTS_PC_DATACRC_ERROR; 
		}
		if (HFL.bitfield.ENA != 0) throw EGTS_PC_DECRYPT_ERROR;
		if (HFL.bitfield.CMP == 1) throw EGTS_PC_INC_DATAFORM;

		size_t endOfDataFrame = curInd + FDL;
		while ((curInd < endOfDataFrame)&&(ValidatingResult<= EGTS_PC_IN_PROGRESS))
		{
			Record* record = new Record;
			ValidatingResult = record->ParseRecord(curInd, packet);
			records.push_back(record);
		}
		if (ValidatingResult == EGTS_PC_IN_PROGRESS) { ValidatingResult = EGTS_PC_OK; }
	}
	catch (const out_of_range&)
	{
		cout << "При разборе заголовка транспортного уровня обнаружен выход за диапазон  " << endl;
		ValidatingResult = EGTS_PC_MODULE_SW_FLT;
		return;
	}

	catch (bad_alloc &)
	{
		cout << "Мemory allocation problem " << endl;
		ValidatingResult = EGTS_PC_MODULE_MEM_FLT;
		return;
	}

	catch (  TLErrors exc)
	{
		cout << exc << endl;
		ValidatingResult = exc;
		return;
	}
	
	catch (const char *exc)
	{
		cout << exc << endl;
		ValidatingResult = EGTS_PC_MODULE_SW_FLT;
		return;
	}

	catch (...)
	{
		cout << "Ошибка при разборе заголовка транспортного уровня  " << endl;
		ValidatingResult = EGTS_PC_MODULE_SW_FLT;
		return;
	}

};

TLHeader::TLHeader()
{
	PRV = 0;//Protocol Version
	SKID = 0;//Security Kei Id
	HFL.value = 0;//Header Flags
	HL = 0;//Header Length
	HE = 0;//Header Encoding
	FDL = 0; //Frame Data Length
	PID = 0; //Packet idetifier
	PT = 0;// Packet Type
	PRA = 0;//Peer Adress
	RCA = 0; //Recipient adress
	TTL = 0;//Time to live
	HCS = 0; //Header Check Sum CRC8
	SFRCS = 0; //Services Frame Data Check Sum CRC16 
	ValidatingResult = EGTS_PC_IN_PROGRESS;
}

TLHeader::~TLHeader()
{
	for (vector<Record*>::iterator it = records.begin(); it != records.end(); ++it)
		delete (*it);
}

void TLHeader::PrintTL()
{
	cout << "\nПакет " << endl;
	cout << "EGTS Transport Layer : " << endl;
	cout << "---------------------" << endl;
	cout << "Validating result - \t" << dec << (int)ValidatingResult <<"\t("<< ValidatingResult <<")" <<endl << endl;
	if (ValidatingResult != EGTS_PC_OK)	return;
	cout << "Заголовок пакета: " << endl;
	cout << "Protocol Version: \t" << dec << (USHORT)PRV << "," << endl;
	cout << "Security Key ID: \t" << dec << (USHORT)SKID << "," << endl;
	cout << "\nFlags " << endl;
	cout << "\tPrefix: \t" << dec << HFL.bitfield.PRF << "," << endl;
	cout << "\tRoute:  \t" << dec << HFL.bitfield.RTE << "," << endl;
	cout << "\tEncryption Alg: " << dec << HFL.bitfield.ENA << "," << endl;
	cout << "\tCompressed: \t" << dec << HFL.bitfield.CMP << "," << endl;
	cout << "\tPriority: \t" << dec << HFL.bitfield.PR << "," << endl << endl;
	cout << "Header Length: \t\t" << dec << (USHORT)HL << "," << endl;
	cout << "Header Encoding: \t" << dec << (USHORT)HE << "," << endl;
	cout << "FrameDataLength: \t" << dec << (USHORT)FDL << "," << endl;
	cout << "Packet Identifier: \t" << dec << (USHORT)PID << "," << endl;
	cout << "Packet Type:\t";
	if (PT == EGTS_PT_RESPONSE)
		cout << "EGTS_PT_RESPONSE";
	else if (PT == EGTS_PT_APPDATA)
		cout << " EGTS_PT_APPDATA";
	else if(PT == EGTS_PT_SIGNED_APPDATA)
		cout << " EGTS_PT_SIGNED_APPDATA";
	else
		cout << "Некорректный тип заголовка!";
	cout << endl;
	cout << "HeaderCheckSum: \t" << dec << (USHORT)HCS << "," << endl;

	for (vector<BYTE>::size_type i = 0; i < records.size(); i++)
	{
		records[i]->PrintRecord();
	}
};