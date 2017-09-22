/*BEGIN_LEGAL 
Intel Open Source License 
Copyright (c) 2002-2015 Intel Corporation. All rights reserved.
 


Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are
met:
Redistributions of source code must retain the above copyright notice,
this list of conditions and the following disclaimer.  Redistributions
in binary form must reproduce the above copyright notice, this list of
conditions and the following disclaimer in the documentation and/or
other materials provided with the distribution.  Neither the name of
the Intel Corporation nor the names of its contributors may be used to
endorse or promote products derived from this software without
specific prior written permission.
 
THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE INTEL OR
ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
END_LEGAL */

/* ===================================================================== */
/*
  @ORIGINAL_AUTHOR: Robert Muth
*/

/* ===================================================================== */
/*! @file
 *  This file contains an ISA-portable PIN tool for tracing instructions
 */

#include "pin.H"
#include <iostream>
#include <fstream>

/* ===================================================================== */
/* Global Variables */
/* ===================================================================== */

std::ofstream TraceFile;

/* ===================================================================== */
/* Commandline Switches */
/* ===================================================================== */

KNOB<string> KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool", "o", "trace.out", "specify trace file name");
//KNOB<BOOL>   KnobPrintArgs(KNOB_MODE_WRITEONCE, "pintool", "i", "0", "mark indirect calls ");
UINT32 count_trace = 0; // current trace number
bool outflag=false;
bool call_flag=false;
bool ret_flag=false;
const string Trace_begin_fun="main";

/* ===================================================================== */
/* Print Help Message                                                    */
/* ===================================================================== */

INT32 Usage()
{
    cerr << "This tool produces a call trace." << endl << endl;
    cerr << KNOB_BASE::StringKnobSummary() << endl;
    return -1;
}

string invalid = "invalid_rtn";

/* ===================================================================== */
void Out2file(const string *s){
	if(outflag){
 		TraceFile << *s << endl;
	}
}
/* ===================================================================== */
string *ADDRINT2str(ADDRINT value){
	char str[16];
    	sprintf(str,"%x",(unsigned int)value);
	return new string(str);
}
/* ===================================================================== */
const string *Target2String(ADDRINT target)
{
    string name = RTN_FindNameByAddress(target);
    if (name == "")
        return &invalid;
    else
        return new string(name);


}


/* ===================================================================== */

VOID  do_call(const string *s)
{
    TraceFile << *s << endl;

}
/* ===================================================================== */

VOID  my_call(const string *s,ADDRINT target)
{	
	
	if(call_flag){
	    const string fileout="[CALLF]"+*ADDRINT2str(target)+"\t"+*s;
	    Out2file(&fileout);
	}


}
/* ===================================================================== */

VOID  do_call_indirect(ADDRINT target, BOOL taken)
{
    if( !taken ) return;

    const string *s = Target2String(target);
    my_call( s, target );
    
    if (s != &invalid)
        delete s;
}

/* ===================================================================== */
VOID  do_ret(UINT32 insAddr,ADDRINT target)
{
	//Out2file(Target2String(insAddr));
    	if(Trace_begin_fun.compare(*(Target2String(insAddr)))==0){
		outflag=false;
	}
	if(ret_flag){
	    const string s = "[RET_D]"+*ADDRINT2str(insAddr)+"\t"+*Target2String(target);
	    Out2file(&s);
	}
    
}

/* ===================================================================== */
VOID  docount(const string *s,ADDRINT ins_addr)
{
    	//Out2file(Target2String(ins_addr));
	const string* funname=Target2String(ins_addr);
    	if(Trace_begin_fun.compare(*(funname))==0){
		outflag=true;
	}else if(funname->find("@plt")!=string::npos){
		Out2file(new string("[C2LIB]"+*ADDRINT2str(ins_addr)+"\t"+*funname));
		outflag=false;
	}
    	Out2file(s);
}

/* ===================================================================== */

VOID Trace(TRACE trace, VOID *v)
{
  
    const string funname="main";//baseblock trace the function
        
    for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl))
    {	
	
	
        INS tail = BBL_InsTail(bbl);
	if(true){
		INS ins = BBL_InsHead(bbl);
		ADDRINT ins_addr=INS_Address(ins);
		if(ins_addr/0x1000==0x400){
			
			string *s = new string("[B_ENT]"+*ADDRINT2str(ins_addr)+"\t%" + INS_Disassemble(ins));
			INS_InsertCall(BBL_InsTail(bbl), IPOINT_BEFORE, AFUNPTR(docount),
					   IARG_PTR, s, IARG_ADDRINT, ins_addr,
					   IARG_END);	
		}
		
	}
        if( INS_IsCall(tail) )
        {
            if( INS_IsDirectBranchOrCall(tail) )
            {
                const ADDRINT target = INS_DirectBranchOrCallTargetAddress(tail);
                INS_InsertPredicatedCall(tail, IPOINT_BEFORE, AFUNPTR(my_call),
                                             IARG_PTR, Target2String		(target),IARG_ADDRINT, target, IARG_END);
               
                
            }
            else
            {
                 INS_InsertCall(tail, IPOINT_BEFORE, AFUNPTR(do_call_indirect),
                                   IARG_END);
               
            }
        }
	else if( INS_IsRet(tail) )
	{
		
		//const ADDRINT target =INS_DirectBranchOrCallTargetAddress(tail);
		INS_InsertPredicatedCall(tail, IPOINT_BEFORE, AFUNPTR(do_ret),
                           IARG_ADDRINT, INS_Address(tail), IARG_BRANCH_TARGET_ADDR, IARG_END);
	
	}
        else
        {
            // sometimes code is not in an image
            RTN rtn = TRACE_Rtn(trace);
            
            // also track stup jumps into share libraries
            if( RTN_Valid(rtn) && !INS_IsDirectBranchOrCall(tail) && ".plt" == SEC_Name( RTN_Sec( rtn ) ))
            {
                
                
		INS_InsertCall(tail, IPOINT_BEFORE, AFUNPTR(do_call_indirect),
                                   IARG_BRANCH_TARGET_ADDR, IARG_BRANCH_TAKEN, IARG_END);

            }
        }
        
    }
}

/* ===================================================================== */

VOID Fini(INT32 code, VOID *v)
{
    TraceFile << "# eof" << endl;
    
    TraceFile.close();
}

/* ===================================================================== */
/* Main                                                                  */
/* ===================================================================== */

int  main(int argc, char *argv[])
{
    
    PIN_InitSymbols();

    if( PIN_Init(argc,argv) )
    {
        return Usage();
    }
    

    TraceFile.open(KnobOutputFile.Value().c_str());

    TraceFile << hex;
    TraceFile.setf(ios::showbase);
    
    string trace_header = string("#\n"
                                 "# Trace Generated By Pin\n"
                                 "#\n");
    

    TraceFile.write(trace_header.c_str(),trace_header.size());
    
    TRACE_AddInstrumentFunction(Trace, 0);
    PIN_AddFiniFunction(Fini, 0);

    // Never returns

    PIN_StartProgram();
    
    return 0;
}

/* ===================================================================== */
/* eof */
/* ===================================================================== */
