## Discription of simulate of glibc function in symblic execution
  
### 1.How symblic execution run into plt   

  #### &nbsp;&nbsp;simuvex.plugins.sybolic_memory | Concretizing symbolic length. Much sad; think about implementing.

  #### &nbsp;&nbsp;call trace of run into simulate funcion.
  ```python
  angr/path.py/step()
  angr/path.py/_make_successors()
  angr/factory/successors
  engines.process
  simuvex/engines/procedure/SimEngineProcedure.procedure
  simuvex/engines/engine.py.process
  simuvex/engines/procedure._process
  simuvex.procedures.libc___so___6.__isoc99_scanf.__isoc99_scanf
  
  path.py-->factory-->engines-->successors-->__isoc99_scanf-->s_format-->s_type
  ```
### 1.path.py   

  #### &nbsp;&nbsp;
  #### &nbsp;&nbsp;
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


#### &nbsp;&nbsp;__isoc99_scanf.
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
### 2. 
