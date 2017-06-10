#include <iostream>
#include <fstream>
#include <map>
#include <set>
#include <vector>
#include <list>

#include "pin.h"
#include "kscope.h"
#include "lzo/minilzo.h"


ConfigReader Config;

static FileManager FpCodePool("./data/bblInst.log", "w");


static VOID bbl_trace(TRACE trace, VOID *v)
{
	// Visit every basic block in the trace
	for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl))
    {
		ADDRINT pc = BBL_Address(bbl);
		if ( pc >= Config.get_codeStartAddr() && pc <= Config.get_codeEndAddr() )
		{
			for ( INS ins = BBL_InsHead(bbl); INS_Valid(ins); ins = INS_Next(ins))
			{
				fprintf( FpCodePool.fp(), "%08x|%s\n", INS_Address (ins), INS_Disassemble(ins).c_str() );
			}
			fprintf( FpCodePool.fp(), "----\n" );
		}
	}
}


/* ===================================================================== */
/* Main                                                                  */
/* ===================================================================== */

/*
#include "kaleidoscope.h"
#include "memAnalyzer.h"
#include "ksTracer.h"
#include "citation.h"
#include "bblTracer.h"
#include "inputRecorder.h"
*/

#include "ksTracer.h"