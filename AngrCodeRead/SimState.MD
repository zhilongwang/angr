# SimState 是angr内部一个重要的类，她用于保存程序的状态信息。
## &nbsp;&nbsp; 内部信息
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
 ## &nbsp;&nbsp; functool.wraps 函数装饰/函数预处理   
   &nbsp;&nbsp;&nbsp;&nbsp; http://www.wklken.me/posts/2013/08/18/python-extra-functools.html   
   ```python   
   
  def arch_overrideable(f):
    @functools.wraps(f)
    def wrapped_f(self, *args, **kwargs):
        if hasattr(self.arch, f.__name__):
            arch_f = getattr(self.arch, f.__name__)
            return arch_f(self, *args, **kwargs)
        else:
            return f(self, *args, **kwargs)
    return wrapped_f
    
   ```
  ## &nbsp;&nbsp; add_constraints
   &nbsp;&nbsp;&nbsp;&nbsp; Add some constraints to the state.  
   ```python
    def add_constraints(self, *args, **kwargs):
        """
        Add some constraints to the state.

        You may pass in any number of symbolic booleans as variadic positional arguments.
        """
     
        if len(args) > 0 and isinstance(args[0], (list, tuple)):
            raise Exception("Tuple or list passed to add_constraints!")

        if o.TRACK_CONSTRAINTS in self.options and len(args) > 0:
            if o.SIMPLIFY_CONSTRAINTS in self.options:
                constraints = [ self.simplify(a) for a in args ]
            else:
                constraints = args

            self._inspect('constraints', BP_BEFORE, added_constraints=constraints)
            constraints = self._inspect_getattr("added_constraints", constraints)
            added = self.se.add(*constraints)
            self._inspect('constraints', BP_AFTER)

            # add actions for the added constraints
            if o.TRACK_CONSTRAINT_ACTIONS in self.options:
                for c in added:
                    sac = SimActionConstraint(self, c)
                    self.log.add_action(sac)
        else:
            # preserve the old action logic for when we don't track constraints (why?)
            if (
                'action' in kwargs and kwargs['action'] and
                o.TRACK_CONSTRAINT_ACTIONS in self.options and len(args) > 0
            ):
                for arg in args:
                    if self.se.symbolic(arg):
                        sac = SimActionConstraint(self, arg)
                        self.log.add_action(sac)

        if o.ABSTRACT_SOLVER in self.options and len(args) > 0:
            for arg in args:
                if self.se.is_false(arg):
                    self._satisfiable = False
                    return

                if self.se.is_true(arg):
                    continue

                # `is_true` and `is_false` does not use VSABackend currently (see commits 97a75366 and 2dfba73e in
                # claripy). There is a chance that VSA backend can in fact handle it.
                # Therefore we try to resolve it with VSABackend again
                if claripy.backends.vsa.is_false(arg):
                    self._satisfiable = False
                    return

                if claripy.backends.vsa.is_true(arg):
                    continue

                # It's neither True or False. Let's try to apply the condition

                # We take the argument, extract a list of constrained SIs out of it (if we could, of course), and
                # then replace each original SI the intersection of original SI and the constrained one.

                _, converted = self.se.constraint_to_si(arg)

                for original_expr, constrained_si in converted:
                    if not original_expr.variables:
                        l.error('Incorrect original_expression to replace in add_constraints(). ' +
                                'This is due to defects in VSA logics inside claripy. Please report ' +
                                'to Fish and he will fix it if he\'s free.')
                        continue

                    new_expr = constrained_si
                    self.registers.replace_all(original_expr, new_expr)
                    for _, region in self.memory.regions.items():
                        region.memory.replace_all(original_expr, new_expr)

                    l.debug("SimState.add_constraints: Applied to final state.")
        elif o.SYMBOLIC not in self.options and len(args) > 0:
            for arg in args:
                if self.se.is_false(arg):
                    self._satisfiable = False
                    return
   ```
   
   
   
