// This is an open source non-commercial project. Dear PVS-Studio, please check it.
// PVS-Studio Static Code Analyzer for C, C++ and C#: http://www.viva64.com

#include <iostream>
#include <algorithm>
#include <sstream>
#include <iterator>
#include <cstring>
#include <iomanip>
#include "main.h"
#include "CRC.h"

 
int main()
{
	setlocale(LC_ALL, "Rus");
	//const char str[] = "01 00 00 0b 00 33 00 e4 00 01 92 2c 00 d5 00 00 02 02 10 15 00 c4 0a 6e 11 00 00 00 00 00 00 00 00 08 00 00 00 00 00 00 03 00 14 05 00 02 79 00 00 06 12 09 00 00 00 03 71 02 00 64 02 00 5e 10";
	const char str[] = "01 00 00 0b 00 02 01 01 00 01 6f 44 00 01 00 00 01 01 01 25 00 00 00 00 00 c2 33 35 31 35 35 35 30 36 31 30 34 33 36 39 39 00 02 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 03 19 00 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 30 01 00 00 00 01 00 00 00 b0 00 02 00 00 02 02 10 15 00 37 f0 81 10 00 00 00 00 00 00 00 00 02 00 00 00 00 00 00 04 00 15 05 00 02 79 00 01 06 12 09 00 00 00 03 54 02 00 4c 02 00 10 15 00 38 f0 81 10 00 00 00 00 00 00 00 00 02 00 00 00 00 00 00 04 00 15 05 00 02 79 00 00 06 12 09 00 00 00 03 50 02 00 49 02 00 10 15 00 38 f0 81 10 00 00 00 00 00 00 00 00 02 00 00 00 00 00 00 04 00 15 05 00 02 79 00 00 06 12 09 00 00 00 03 51 02 00 4a 02 00 10 15 00 3a f0 81 10 00 00 00 00 00 00 00 00 02 00 00 00 00 00 00 04 00 15 05 00 02 79 00 00 06 12 09 00 00 00 03 55 02 00 4e 02 00 9c fc";

	/*******************Конвертация символов в байты и печать пакета в консоль*******/
	vector<unsigned char> packet;
	copy(std::istream_iterator<unsigned>(std::istringstream(str) >> std::hex), std::istream_iterator<unsigned>(), std::back_inserter(packet));
	cout << "Пакет:" << endl;
	for (vector<BYTE>::iterator i = packet.begin(); i != packet.end(); ++i)
		{
			cout << setfill('0') << setw(2) << hex << (int)*i << " ";
		}
		cout << endl;
	/********************************************************************************/

	size_t packetLength = packet.size();
	if (packetLength>TL_PACKET_MAX_LENGTH)
	{
		cout << "Packet size is too large" << endl;
		return -1;
	}
	if (packetLength<TL_HEADER_MIN_LENGTH)
	{
		cout << "Packet size is too small" << endl;
		return -1;
	}

	cout << "Разбор пакета:" << endl;
	try
	{
		TLHeader * parsel = new TLHeader;
		parsel->ParseTransportLayer(packet);
		parsel->PrintTL();
		delete parsel;
	}
	catch (bad_alloc &)
	{
		cout << "Мemory allocation problem " << endl;
		return -1;
	}
	catch(...)
	{
		cout << " An error occurred while parsing the packet " << endl;
		return -1;
	}

	
	system("pause");
	return 0;
}


/*	Если принципиально проверить CRC в первейшую очередь,
т.е. до создания обьекта с заголовком транспортного уровня,
то можно использовать эту функцию перед дальнейшим парсингом
*/
/*
#define CRC_OK	1
#define CRC_ERR	0
bool CRCcheck(const vector<BYTE>& packet)
{
try
{
if (packet.empty())	return CRC_ERR;
BYTE HL = packet.at(3);
if (HL != 11 && HL != 16)	return CRC_ERR;
BYTE HCS = packet.at(HL-1);
if (CRC8(packet.data(), HL - 1) != HCS)	return CRC_ERR;

USHORT FDL = (packet.at(5) + USHORT((packet.at(6)) << 8));
if (FDL>MAX_FDL)			return CRC_ERR;
if (FDL > 0)
{
USHORT SFRCS = packet.at(HL + FDL) + USHORT((packet.at(HL + FDL + 1)) << 8);
if (CRC16(packet.data() + HL, FDL) != SFRCS)  return CRC_ERR;
}
}
catch(...) { return CRC_ERR; }
return CRC_OK;
}
*/

