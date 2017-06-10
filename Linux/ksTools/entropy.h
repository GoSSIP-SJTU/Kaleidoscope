#include <iostream>
#include <fstream>
#include <math.h>
#include <map>
#include "pin.H"
#include "kscope.h"

extern ConfigReader Config;
static FileManager MemTrace("data/entropy.log", "w");

static ADDRINT WIP = 0;
static VOID * WAddr = 0;

struct Slot
{
	unsigned int d[0x100];
};

static map<ADDRINT, Slot> ReadEntropySlot;
static map<ADDRINT, Slot> WriteEntropySlot;

double shannon( const Slot & slot )
{
    unsigned int counter = 0;
    for ( size_t i = 0; i < 256; ++i )
        counter += slot.d[i];
    
    double base = 0.0;
	double log2 = log(2.0);
    
	for ( size_t i = 0; i < 256; ++i )
	{
        if ( 0 != slot.d[i] )
		{
            double hertz = 1.0 * slot.d[i] / counter;
            base += log(hertz) / log2 * hertz ;
		}
	}

	if ( (base / -8) < 0.001 && (base / -8) > -0.001 )
		return 0.0;
    return base / -8;
}

// Record a memory read record
VOID mem_read( ADDRINT ip, VOID * addr, UINT32 len )
{
	if ( len > REG_SIZE ) return;

	for ( size_t i = 0; i < len; ++i )
		++ReadEntropySlot[ip].d[ static_cast<UINT8*>(addr)[i] ];
}

// Record a memory write record
VOID mem_write( ADDRINT ip, VOID * addr, UINT32 len )
{
	WIP = ip;
	WAddr = addr;
}

VOID mem_write_content( UINT32 len )
{
	if ( len > REG_SIZE ) return;

	for ( size_t i = 0; i < len; ++i )
		++WriteEntropySlot[WIP].d[ static_cast<UINT8*>(WAddr)[i] ];
}


// Pin calls this function every time a new instruction is encountered
VOID Inst_Entropy(INS ins, VOID *v)
{
	if ( Config.in_addr_set(INS_Address(ins)) )
	{
		if (INS_IsMemoryWrite(ins))
		{
			INS_InsertCall(ins, IPOINT_BEFORE, AFUNPTR(mem_write),
				IARG_INST_PTR, IARG_MEMORYWRITE_EA, IARG_MEMORYWRITE_SIZE, IARG_END);

			if (INS_HasFallThrough(ins))
				INS_InsertPredicatedCall(ins, IPOINT_AFTER, AFUNPTR(mem_write_content),
					IARG_MEMORYWRITE_SIZE, IARG_END);
			if (INS_IsBranchOrCall(ins))
				INS_InsertPredicatedCall(ins, IPOINT_TAKEN_BRANCH, AFUNPTR(mem_write_content),
					IARG_MEMORYWRITE_SIZE, IARG_END);
		}

		if ( INS_IsMemoryRead(ins) )
		{
			INS_InsertPredicatedCall(ins, IPOINT_BEFORE, AFUNPTR(mem_read), 
				IARG_INST_PTR, IARG_MEMORYREAD_EA, IARG_MEMORYREAD_SIZE, IARG_END);
		}
		if ( INS_HasMemoryRead2(ins) )
		{
			INS_InsertPredicatedCall(ins, IPOINT_BEFORE, AFUNPTR(mem_read), 
				IARG_INST_PTR, IARG_MEMORYREAD2_EA, IARG_MEMORYREAD_SIZE, IARG_END);
		}
	}
}


// This function is called when the application exits
static VOID Fini_Entropy(INT32 code, VOID *v)
{
	for ( map<ADDRINT, Slot>::const_iterator i = ReadEntropySlot.begin(); i != ReadEntropySlot.end(); ++i )
	{
		fprintf( MemTrace.fp(), "R|%08x: %f\n", i->first, shannon( i->second ) );
	}

	for ( map<ADDRINT, Slot>::const_iterator i = WriteEntropySlot.begin(); i != WriteEntropySlot.end(); ++i )
	{
		fprintf( MemTrace.fp(), "W|%08x: %f\n", i->first, shannon( i->second ) );
	}


	fprintf( MemTrace.fp(), "--FINI--\n" );
}


int main(int argc, char * argv[])
{
    // Initialize pin
    if ( PIN_Init(argc, argv) )
		return -1;

	fprintf( MemTrace.fp(), "code section size: %d\n", Config.get_codeEndAddr() - Config.get_codeStartAddr() );

	// Register Instruction to be called to instrument instructions
    INS_AddInstrumentFunction(Inst_Entropy, 0);

    // Register Fini to be called when the application exits
    PIN_AddFiniFunction(Fini_Entropy, 0);
    
    // Start the program, never returns
    PIN_StartProgram();
    
    return 0;
}
