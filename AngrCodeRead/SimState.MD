# SimState 是angr内部一个重要的类，她用于保存程序的状态信息。
## &nbsp;&nbsp; 内部变量
   &nbsp;&nbsp;&nbsp;&nbsp;SimState
   ```html
    """
    The SimState represents the state of a program, including its memory, registers, and so forth.

    :ivar regs:         A convenient view of the state's registers, where each register is a property
    :ivar mem:          A convenient view of the state's memory, a :class:`simuvex.plugins.view.SimMemView`
    :ivar registers:    The state's register file as a flat memory region
    :ivar memory:       The state's memory as a flat memory region
    :ivar se:           The solver engine for this state
    :ivar inspect:      The breakpoint manager, a :class:`simuvex.plugins.inspect.SimInspector`
    :ivar log:          Information about the state's history
    :ivar scratch:      Information about the current execution step
    :ivar posix:        MISNOMER: information about the operating system or environment model
    :ivar libc:         Information about the standard library we are emulating
    :ivar cgc:          Information about the cgc environment
    :ivar uc_manager:   Control of under-constrained symbolic execution
    :ivar unicorn:      Control of the Unicorn Engine
    """
   ```
