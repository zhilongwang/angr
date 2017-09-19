## Discription of step() into glibc function in symblic execution
  
### 1.How symblic execution run into plt   

  #### &nbsp;&nbsp;simuvex.plugins.sybolic_memory | Concretizing symbolic length. Much sad; think about implementing.

  #### &nbsp;&nbsp;call trace of run into simulate funcion.
 
  [angr/Path/step()](#1)   
  [angr/Path/_make_successors()](#1.1)   
  [angr/AngrObjectFactory/successors()](#2)   
  [angr/SimEngineHook/process()](#3)   
  [simuvex/SimEngineProcedure/process()](#4)   
  [simuvex/SimEngine/process()](#5)   
  [simuvex/SimEngine/_process()](#5.1)   
  [angr/SimEngineHook/_process()](#6)   
  [simuvex/SimEngineProcedure/_process()](#7)   
  [simuvex/procedures/libc___so___6.__isoc99_scanf/__isoc99_scanf.run()](#8)   
 
### 2.Path   
&nbsp;&nbsp;angr.path
  #### &nbsp;&nbsp;<h4 id="1">step()</h4>
  ```python
  
    #
    # Stepping methods and successor access
    #

    def step(self, throw=None, **run_args):
        """
        Step a path forward. Optionally takes any argument applicable to project.factory.successors.

        :param jumpkind:          the jumpkind of the previous exit.
        :param addr address:      to execute at instead of the state's ip.
        :param whitelist:         a list of stmt indexes to which to confine execution.
        :param last_stmt:         a statement index at which to stop execution.
        :param thumb:             whether the block should be lifted in ARM's THUMB mode.
        :param backup_state:      a state to read bytes from instead of using project memory.
        :param opt_level:         the VEX optimization level to use.
        :param insn_bytes:        a string of bytes to use for the block instead of #the project.
        :param size:              the maximum size of the block, in bytes.
        :param num_inst:          the maximum number of instructions.
        :param traceflags:        traceflags to be passed to VEX. Default: 0
        :param strong_reference   whether or not to keep a strong reference to the previous state. Default: False

        :returns:   An array of paths for the possible successors.
        """
        print("Debug:In angr/path.py/step()")
        # backward compatibility
        if 'max_size' in run_args:
            l.warning('"max_size" has been deprecated in Path.step(). Please use "size" instead.')
            size = run_args.pop('max_size')
            run_args['size'] = size
            
	
        if self._run_args != run_args or not self._run:
            self._run_args = run_args
            self._make_successors(throw=throw)

        self.state._inspect('path_step', simuvex.BP_BEFORE)
        
        if self._run_error:
            return [ self.copy(error=self._run_error, traceback=self._run_traceback) ]
            
        strong_reference = run_args.get("strong_reference", False)
<span style="color: red"> 
        out = [Path(self._project, s, path=self, strong_reference=strong_reference) for s in self._run.flat_successors]
</span>        
        if 'insn_bytes' in run_args and 'addr' not in run_args and len(out) == 1 \
                and isinstance(self._run, simuvex.SimIRSB) \
                and self.addr + self._run.irsb.size == out[0].state.se.any_int(out[0].state.regs.ip):
            out[0].state.regs.ip = self.addr

        for p in out:
            p.state._inspect('path_step', simuvex.BP_AFTER)
        return out

  ```
  #### &nbsp;&nbsp;<h4 id="1.1">_make_successors() </h4> 
  ```python
   def _make_successors(self, throw=None):
	print("Debug:In angr/path.py/_make_successors()")
        self._run = None
        self._run_error = None
        self._run_traceback = None
        try:
	       #************************************8
            self._run = self._project.factory.successors(self.state, **self._run_args)

        except (AngrError, simuvex.SimError, claripy.ClaripyError) as e:
            l.debug("Catching exception", exc_info=True)
            self._run_error = e
            self._run_traceback = sys.exc_info()[2]
            if throw:
                raise
        except (TypeError, ValueError, ArithmeticError, MemoryError) as e:
            l.debug("Catching exception", exc_info=True)
            self._run_error = e
            self._run_traceback = sys.exc_info()[2]
            if throw:
                raise
  ```
  
### 3.AngrObjectFactory
 &nbsp;&nbsp;angr.factory

  #### &nbsp;&nbsp;<h4 id="2">successors()  </h4> 
  
  ```python
  def successors(self, state,
            addr=None,
            jumpkind=None,
            inline=False,
            default_engine=False,
            engines=None,
            **kwargs):
        """
        Perform execution using any applicable engine. Enumerate the current engines and use the
        first one that works. Return a SimSuccessors object classifying the results of the run.

        :param state:           The state to analyze
        :param addr:            optional, an address to execute at instead of the state's ip
        :param jumpkind:        optional, the jumpkind of the previous exit
        :param inline:          This is an inline execution. Do not bother copying the state.
        :param default_engine:  Whether we should only attempt to use the default engine (usually VEX)
        :param engines:         A list of engines to try to use, instead of the default.

        Additional keyword arguments will be passed directly into each engine's process method.
        """
	print("Debug:in angr/factory/successors")
        if default_engine:
            engines = [self.default_engine]
        if engines is None:
            engines = self.engines

        if addr is not None or jumpkind is not None:
            state = state.copy()
            if addr is not None:
                state.ip = addr
            if jumpkind is not None:
                state.scratch.jumpkind = jumpkind

        r = None
        for engine in engines:
            if engine.check(state, inline=inline, **kwargs):
                #***************************8/
                
                r = engine.process(state, inline=inline,**kwargs)

                if r.processed:
                    break
     
        if r is None or not r.processed:
            raise AngrExitError("All engines failed to execute!")

        # Peek and fix the IP for syscalls
        if r.successors and r.successors[0].scratch.jumpkind.startswith('Ijk_Sys'):
            self._fix_syscall_ip(r.successors[0])

        return r   
  ```

### 4.SimEngineHook
 &nbsp;&nbsp;angr.engines 
 &nbsp;&nbsp; SimEngineHook is the subclass of SimEngineProcedure
  #### &nbsp;&nbsp;<h4 id="3">process()</h4> 
  ```python
  def process(self, state,
            procedure=None,
            ret_to=None,
            inline=None,
            force_addr=None, **kwargs):
        """
        Perform execution with a state.

        :param state:       The state with which to execute
        :param procedure:   An instance of a SimProcedure to run, optional
        :param ret_to:      The address to return to when this procedure is finished
        :param inline:      This is an inline execution. Do not bother copying the state.
        :param force_addr:  Force execution to pretend that we're working at this concrete address
        :returns:           A SimSuccessors object categorizing the execution's successor states
        """
	print("Debug:in engines.process")
	
        return super(SimEngineHook, self).process(state, procedure,
                ret_to=ret_to,
                inline=inline,
                force_addr=force_addr)
  ```
  ### 5.SimEngineProcedure
 &nbsp;&nbsp;simuvex.engines.procedure 
 &nbsp;&nbsp;SimEngineProcedure is subclass of SimEngine
  #### &nbsp;&nbsp;<h4 id="6">process()</h4>    
  
  ```python  
 def process(self, state, procedure,
            ret_to=None,
            inline=None,
            force_addr=None,
            **kwargs):
        """
        Perform execution with a state.

        :param state:       The state with which to execute
        :param procedure:   An instance of a SimProcedure to run
        :param ret_to:      The address to return to when this procedure is finished
        :param inline:      This is an inline execution. Do not bother copying the state.
        :param force_addr:  Force execution to pretend that we're working at this concrete address
        :returns:           A SimSuccessors object categorizing the execution's successor states
        """
        print("Debug:in simuvex/engines/procedure/SimEngineProcedure.procedure")
	
        return super(SimEngineProcedure, self).process(state, procedure,
                ret_to=ret_to,
                inline=inline,
                force_addr=force_addr)   
		
  ```  
 ### 6.SimEngine
 &nbsp;&nbsp;simuvex.engines.engine
 
   #### &nbsp;&nbsp;<h4 id="5">process() </h4> 
  
  ```python  
 def process(self, state, *args, **kwargs):
        """
        Perform execution with a state.

        You should only override this method in a subclass in order to provide the correct method signature and
        docstring. You should override the ``_process`` method to do your actual execution.

        :param state:       The state with which to execute. This state will be copied before
                            modification.
        :param inline:      This is an inline execution. Do not bother copying the state.
        :param force_addr:  Force execution to pretend that we're working at this concrete address
        :returns:           A SimSuccessors object categorizing the execution's successor states
        """
        print("Debug:in simuvex/engines/engine.py.process")
        inline = kwargs.pop('inline', False)
        force_addr = kwargs.pop('force_addr', None)
        addr = state.se.any_int(state._ip) if force_addr is None else force_addr

        # make a copy of the initial state for actual processing, if needed
        if not inline and o.COW_STATES in state.options:
            new_state = state.copy()
        else:
            new_state = state
	
        # clear the log (unless we're inlining)
        if not inline:
            new_state.log.clear()
            new_state.scratch.clear()
            new_state.scratch.bbl_addr = addr

        successors = SimSuccessors(addr, state)

        self._process(new_state, successors, *args, **kwargs)
      
        return successors
	
  ```  
  #### &nbsp;&nbsp; <h4 id="5.1">_process()  </h4> 
  
  ```python  
 def _process(self, new_state, successors, *args, **kwargs):
        raise NotImplementedError 
		
  ```  
 ### 8.SimEngineProcedure
 &nbsp;&nbsp;simuvex.engines.procedure 
 &nbsp;&nbsp;SimEngineProcedure is subclass of SimEngine, and supperclass of SimEnginHook
 #### &nbsp;&nbsp;<h4 id="6">_process()</h4>     
  
  ```python  
def _process(self, state, successors, procedure, ret_to=None):
        
        print("Debug:in simuvex/engines/procedure._process")
        successors.sort = 'SimProcedure'
        successors.description = 'SimProcedure ' + procedure.display_name
        if procedure.is_syscall:
            successors.description += ' (syscall)'

        # fill in artifacts
        successors.artifacts['is_syscall'] = procedure.is_syscall
        successors.artifacts['procedure'] = procedure
        successors.artifacts['name'] = procedure.display_name
        successors.artifacts['no_ret'] = procedure.NO_RET
        successors.artifacts['adds_exits'] = procedure.ADDS_EXITS

        # Update state.scratch
        state.scratch.sim_procedure = procedure
        state.scratch.executed_block_count = 1

        # prepare and run!
        state._inspect('simprocedure',
                       BP_BEFORE,
                       simprocedure_name=procedure.display_name,
                       simprocedure_addr=successors.addr
                       )

        if procedure.is_syscall:
            state._inspect('syscall', BP_BEFORE, syscall_name=procedure.display_name)

        cleanup_options = o.AUTO_REFS not in state.options
        if cleanup_options:
            state.options.add(o.AST_DEPS)
            state.options.add(o.AUTO_REFS)

        # do it
        #print("Debug: in simuvex/engines/engine.py.process constraints_len %d" % len(state.se.constraints))
        #constaint is add in the following code.
        procedure.execute(state, successors, ret_to=ret_to)
        #print("Debug: in simuvex/engines/engine.py.process constraints_len %d" % len(state.se.constraints))
        print(procedure.__class__)
        if cleanup_options:
            state.options.discard(o.AST_DEPS)
            state.options.discard(o.AUTO_REFS)

        if procedure.is_syscall:
            state._inspect('syscall', BP_AFTER, syscall_name=procedure.display_name)
        state._inspect('simprocedure',
                       BP_AFTER,
                       simprocedure_name=procedure.display_name,
                       simprocedure_addr=successors.addr
                       )

        successors.processed = True
		
  ```  
### 9.Hook
 &nbsp;&nbsp;

    An object describing an action to be taken at a given address instead of executing binary code.
    An instance of this class may be passed to `angr.Project.hook` along with the address at which
    to hook.

    More specifically, a hook is a wrapper for a SimProcedure, a simuvex object that contains a lot
    of logic for how to mutate a state in common ways. The SimProcedure base class is subclassed
    to produce a SimProcedure that may be used for hooking. If the SimProcedure class is too heavy
    for your use case, there is a class method `wrap` on this class that can be used to wrap a
    simple function into a SimProcedure, and then further into a `Hook` directly.

    This class is a bit of a hack to deal with t
    
    he fact that SimProcedures need to hold state but
    having them do so makes them not thread-safe.

#### &nbsp;&nbsp;instantiate()   
  ```python
    def instantiate(self, *args, **kwargs):
        kwargs['sim_kwargs'] = self.kwargs
        kwargs['is_continuation'] = self.is_continuation
        kwargs['continuation_addr'] = self._continuation_addr
        if self.cc: kwargs['cc'] = self.cc
        return self.procedure(*args, **kwargs)
  ```
### 8.__isoc99_scanf
 &nbsp;&nbsp;simuvex.procedures.libc.system

 #### &nbsp;&nbsp;<h4 id="8">run()  </h4>   

  ```python
from simuvex.s_format import FormatParser
from simuvex.s_type import SimTypeInt, SimTypeString

import logging
l = logging.getLogger("simuvex.procedures.libc.system")

class __isoc99_scanf(FormatParser):
    #pylint:disable=arguments-differ

    def run(self, fmt):
        #pylint:disable=attribute-defined-outside-init

        self.argument_types = {0: self.ty_ptr(SimTypeString())}
        self.return_type = SimTypeInt(self.state.arch.bits, True)
	
        fmt_str = self._parse(0)

        # we're reading from stdin so the region is the file's content
        f = self.state.posix.get_file(0)
        region = f.content
        start = f.pos

        (end, items) = fmt_str.interpret(start, 1, self.arg, region=region)

        # do the read, correcting the internal file position and logging the action
        self.state.posix.read_from(0, end - start)

        return items
  ```
  link:   
  ###### [FormatParser._parse()](https://github.com/njuwangzhilong/angr/blob/master/AngrCodeRead/FormatString.MD/#Inter-Page) 
  ###### [fmt_str.interpret(](http://blog.csdn.net/guodongxiaren) 
  ###### [FormatParser._parse()](http://blog.csdn.net/guodongxiaren) 

