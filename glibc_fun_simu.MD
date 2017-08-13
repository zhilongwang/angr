## Discription of simulate of glibc function in symblic execution
  
### 1.When symblic execution run into plt   

  #### &nbsp;&nbsp;simuvex.plugins.sybolic_memory | Concretizing symbolic length. Much sad; think about implementing.

  #### &nbsp;&nbsp;call trace of run into simulate funcion.
  ```python
  path.step()-->
  self._make_successors()-->
  factory.successors()-->
  engines.process()-->
  SimEngineProcedure.procedure()-->
  engine.process()-->
  simuvex.procedure.libc___so___6.__isoc99_scanf.__isoc99_scanf()
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