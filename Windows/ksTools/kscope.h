#ifndef _KSCOPE_H_
#define _KSCOPE_H_

#include "pin.h"
#include <vector>
#include <map>
#include <set>

typedef unsigned char uint8_t;
typedef unsigned int uint32_t;

const static size_t REG_SIZE = 4; // for 32-bit platform

static const size_t WRITE_BUF_MAX_LEN = 64 * 32 * 0x1000;

class FileManager
{
public:
	FileManager( const char * const fileName, const char * const mode );
	~FileManager();
	FILE * fp();

private:
	FILE * file_;
};

class Compressor
{
public:
	Compressor();
	~Compressor();

	bool set_trace_file( char * recordFile );
	void flush();
	void save_data( void * data, size_t inLen);
	int compress_and_write();

private:
	unsigned char buffer_[WRITE_BUF_MAX_LEN];
	unsigned char lzoData_[WRITE_BUF_MAX_LEN];
	size_t counter_;
	FILE * traceFile_;
	FileManager logFile_;
	static bool toInitFlag_;
};

#include "configReader.h"

bool init_Interval( size_t& interval );
bool init_code_section( ADDRINT& codeStartAddr, ADDRINT& codeEndAddr );
bool init_func_filter( std::set<ADDRINT> & funcFilter );
bool init_addr_filter( std::set<ADDRINT> & addrFilter );
bool init_switch( ADDRINT& switchOnAddr, ADDRINT& switchOffAddr );
bool init_detach_point( ADDRINT& detachPoint );

int		compress_and_write				( FILE * fp, void * data, size_t inLen );
void	compress_and_write_with_buffer	( FILE * fp, void * data, size_t inLen );




#endif

